//! H0.3: sign with a real PKCS#11 HSM and verify the signature with the ledger's Ed25519 path, so
//! an HSM-signed tree head verifies exactly like a file-signed one. Gated on ACP_PKCS11_MODULE so
//! CI without a module skips; run against SoftHSM (or any PKCS#11 module) by setting the env.

use acp_core::sign::{verify_ed25519, Signer};
use acp_hsm::Pkcs11Signer;

fn env() -> Option<(String, u64, String, String)> {
    Some((
        std::env::var("ACP_PKCS11_MODULE").ok()?,
        std::env::var("ACP_PKCS11_SLOT").ok()?.parse().ok()?,
        std::env::var("ACP_PKCS11_PIN").ok()?,
        std::env::var("ACP_PKCS11_LABEL").unwrap_or_else(|_| "acp".to_string()),
    ))
}

#[test]
fn hsm_signs_and_the_signature_verifies_with_the_ledger_path() {
    let Some((module, slot, pin, label)) = env() else {
        eprintln!("ACP_PKCS11_MODULE not set; skipping HSM test");
        return;
    };
    // Part 1: the direct session signer. Opened and DROPPED before opening any second context, so
    // there is never more than one live PKCS#11 context in this process (SoftHSM's global C state
    // does not tolerate two concurrent C_Initialize calls).
    let pk = {
        let signer = Pkcs11Signer::open(&module, slot, &pin, &label).expect("open HSM signer");
        assert_eq!(signer.algorithm(), "ed25519");
        let pk = signer.public_key();
        assert_eq!(pk.len(), 32, "raw Ed25519 public key is 32 bytes, got {}", pk.len());
        let msg = b"acp signed tree head bytes";
        let sig = signer.sign(msg);
        assert_eq!(sig.len(), 64, "raw Ed25519 signature is 64 bytes, got {}", sig.len());
        assert!(verify_ed25519(&pk, msg, &sig), "HSM signature must verify with verify_ed25519");
        assert!(!verify_ed25519(&pk, b"tampered", &sig));
        pk
    }; // signer dropped here -> its context is finalized before the next open.

    // Part 2: the Send threaded handle, exactly what the ledger takes as Box<dyn Signer + Send>.
    use acp_hsm::ThreadedPkcs11Signer;
    let signer: Box<dyn Signer + Send> =
        Box::new(ThreadedPkcs11Signer::open(&module, slot, &pin, &label).expect("open"));
    let handle = std::thread::spawn(move || {
        let msg = b"threaded HSM tree head";
        let sig = signer.sign(msg);
        (signer.public_key(), msg.to_vec(), sig)
    });
    let (pk2, msg, sig) = handle.join().unwrap();
    assert_eq!(pk2, pk, "same token key -> same public key");
    assert!(verify_ed25519(&pk2, &msg, &sig), "HSM-thread signature must verify");
}
