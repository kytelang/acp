//! PKCS#11 HSM signing backend (decision H0.3 hardening).
//!
//! Fills the `acp_core::sign::Signer` seam with a hardware/soft-HSM backend over PKCS#11 (via
//! `cryptoki`), so the evidence signing key can live in a YubiHSM / Thales / SoftHSM instead of a
//! file. Uses Ed25519 (EdDSA) to match the ledger's existing verification, and produces a raw
//! 64-byte signature and raw 32-byte public key so a record signed by the HSM verifies with the
//! same `verify_ed25519` path as the file signer. No cloud: the module is a local `.so`/`.dylib`.
//!
//! Note on integration: a `cryptoki` Session is bound to a thread, so plugging this directly into
//! the ledger's `Box<dyn Signer + Send>` needs a dedicated signing thread + channel wrapper; that
//! wrapper is the remaining deploy-time wiring. The signer itself is complete and testable.

use acp_core::sign::Signer;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// DER encoding of the Ed25519 curve OID (id-Ed25519 = 1.3.101.112), the CKA_EC_PARAMS value.
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

pub struct Pkcs11Signer {
    session: Session,
    priv_key: ObjectHandle,
    public_key: Vec<u8>,
    // Keep the context alive for the life of the session.
    _ctx: Pkcs11,
}

impl Pkcs11Signer {
    /// Open the HSM module, log in to `slot` with `pin`, and find (or generate) the Ed25519 key
    /// labelled `label`. `module` is the path to the PKCS#11 `.so`/`.dylib`.
    pub fn open(module: &str, slot_id: u64, pin: &str, label: &str) -> Result<Self, String> {
        let ctx = Pkcs11::new(module).map_err(|e| format!("load module: {e}"))?;
        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| format!("initialize: {e}"))?;
        let slot = Slot::try_from(slot_id).map_err(|_| "bad slot id".to_string())?;
        let session = ctx.open_rw_session(slot).map_err(|e| format!("open session: {e}"))?;
        session
            .login(UserType::User, Some(&AuthPin::new(pin.to_string())))
            .map_err(|e| format!("login: {e}"))?;

        let label_bytes = label.as_bytes().to_vec();
        let (priv_key, pub_key) = find_or_generate(&session, &label_bytes)?;
        let public_key = read_raw_ed25519_point(&session, pub_key)?;
        Ok(Pkcs11Signer { session, priv_key, public_key, _ctx: ctx })
    }
}

fn find_or_generate(
    session: &Session,
    label: &[u8],
) -> Result<(ObjectHandle, ObjectHandle), String> {
    let priv_found = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.to_vec()),
        ])
        .map_err(|e| format!("find priv: {e}"))?;
    let pub_found = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.to_vec()),
        ])
        .map_err(|e| format!("find pub: {e}"))?;
    if let (Some(&priv_h), Some(&pub_h)) = (priv_found.first(), pub_found.first()) {
        return Ok((priv_h, pub_h));
    }
    // Generate a fresh Ed25519 key pair, persisted (token) under the label.
    let pub_tmpl = [
        Attribute::Token(true),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
        Attribute::Label(label.to_vec()),
    ];
    let priv_tmpl = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Label(label.to_vec()),
    ];
    let (pub_h, priv_h) = session
        .generate_key_pair(&Mechanism::EccEdwardsKeyPairGen, &pub_tmpl, &priv_tmpl)
        .map_err(|e| format!("generate key pair: {e}"))?;
    Ok((priv_h, pub_h))
}

/// Read CKA_EC_POINT and strip the DER OCTET STRING wrapper to the raw 32-byte Ed25519 point.
fn read_raw_ed25519_point(session: &Session, pub_key: ObjectHandle) -> Result<Vec<u8>, String> {
    let attrs = session
        .get_attributes(pub_key, &[AttributeType::EcPoint])
        .map_err(|e| format!("get ec point: {e}"))?;
    let point = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| "no EC_POINT attribute".to_string())?;
    // DER OCTET STRING: 0x04 <len> <bytes>. For Ed25519 len == 32.
    if point.len() == 34 && point[0] == 0x04 && point[1] == 0x20 {
        Ok(point[2..].to_vec())
    } else if point.len() == 32 {
        Ok(point) // some modules return the raw point directly
    } else {
        Err(format!("unexpected EC_POINT length {}", point.len()))
    }
}

impl Signer for Pkcs11Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519));
        self.session.sign(&mech, self.priv_key, msg).unwrap_or_default()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }
}

use std::sync::mpsc;
use std::thread;

/// A `Send` handle to a PKCS#11 signer that lives on its own thread.
///
/// A `cryptoki` Session is thread-bound and not `Send`, but the ledger needs `Box<dyn Signer + Send>`.
/// This owns a dedicated thread that holds the session and services sign requests over a channel;
/// the handle carries only the channel and the cached public key, so it is `Send`. This is the piece
/// that lets the ledger sign every tree head directly on the HSM.
pub struct ThreadedPkcs11Signer {
    tx: mpsc::Sender<SignReq>,
    public_key: Vec<u8>,
}

struct SignReq {
    msg: Vec<u8>,
    reply: mpsc::Sender<Vec<u8>>,
}

impl ThreadedPkcs11Signer {
    /// Open the HSM on a dedicated signing thread. The public key is read once, up front, so the
    /// handle can answer `public_key()` without touching the session.
    pub fn open(module: &str, slot_id: u64, pin: &str, label: &str) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::channel::<Result<Vec<u8>, String>>();
        let (tx, rx) = mpsc::channel::<SignReq>();
        let (module, pin, label) = (module.to_string(), pin.to_string(), label.to_string());
        thread::spawn(move || {
            let signer = match Pkcs11Signer::open(&module, slot_id, &pin, &label) {
                Ok(s) => s,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            if ready_tx.send(Ok(signer.public_key())).is_err() {
                return;
            }
            // Service sign requests until the handle is dropped (channel closes).
            while let Ok(req) = rx.recv() {
                let sig = signer.sign(&req.msg);
                let _ = req.reply.send(sig);
            }
        });
        let public_key = ready_rx
            .recv()
            .map_err(|_| "signing thread died before init".to_string())??;
        Ok(ThreadedPkcs11Signer { tx, public_key })
    }
}

impl Signer for ThreadedPkcs11Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let (reply_tx, reply_rx) = mpsc::channel();
        if self.tx.send(SignReq { msg: msg.to_vec(), reply: reply_tx }).is_err() {
            return Vec::new();
        }
        reply_rx.recv().unwrap_or_default()
    }
    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }
}
