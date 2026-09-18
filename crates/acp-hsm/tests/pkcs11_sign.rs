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
fn hsm_signature_verifies_with_the_ledger_ed25519_path() {
    let Some((module, slot, pin, label)) = env() else {
        eprintln!("ACP_PKCS11_MODULE not set; skipping HSM test");
        return;
    };
    let signer = Pkcs11Signer::open(&module, slot, &pin, &label).expect("open HSM signer");
    assert_eq!(signer.algorithm(), "ed25519");
    let pk = signer.public_key();
    assert_eq!(pk.len(), 32, "raw Ed25519 public key is 32 bytes, got {}", pk.len());

    let msg = b"acp signed tree head bytes";
    let sig = signer.sign(msg);
    assert_eq!(sig.len(), 64, "raw Ed25519 signature is 64 bytes, got {}", sig.len());

    // The whole point: an HSM signature verifies with the exact same code the ledger uses.
    assert!(verify_ed25519(&pk, msg, &sig), "HSM signature must verify with verify_ed25519");
    // A tampered message must fail.
    assert!(!verify_ed25519(&pk, b"tampered", &sig));
}

#[test]
fn threaded_signer_is_send_and_signs_on_the_hsm() {
    let Some((module, slot, pin, label)) = env() else {
        eprintln!("ACP_PKCS11_MODULE not set; skipping HSM test");
        return;
    };
    use acp_hsm::ThreadedPkcs11Signer;
    // As a boxed Send signer, exactly what the ledger takes.
    let signer: Box<dyn Signer + Send> =
        Box::new(ThreadedPkcs11Signer::open(&module, slot, &pin, &label).expect("open"));
    // Move it across a thread boundary to prove Send, then sign there.
    let handle = std::thread::spawn(move || {
        let msg = b"threaded HSM tree head";
        let sig = signer.sign(msg);
        (signer.public_key(), msg.to_vec(), sig)
    });
    let (pk, msg, sig) = handle.join().unwrap();
    assert_eq!(pk.len(), 32);
    assert_eq!(sig.len(), 64);
    assert!(verify_ed25519(&pk, &msg, &sig), "HSM-thread signature must verify");
}
