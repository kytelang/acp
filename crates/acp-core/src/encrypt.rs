//! Envelope encryption at rest with customer-managed keys (decision H0.5).
//!
//! Argument blobs are the sensitive part of the evidence store, so they are encrypted at rest under
//! a customer-managed key (BYOK). Each blob gets a fresh random data-encryption key (DEK); the DEK
//! encrypts the blob, and the customer's key-encryption key (KEK) wraps the DEK. Only the wrapped
//! DEK and the ciphertext are stored, never the KEK. This gives two properties for free: rotating
//! or revoking the KEK renders every blob unreadable (crypto-erasure), and a compromise of the
//! store without the KEK yields nothing. AES-256-GCM (authenticated) via `ring::aead`; a tampered
//! ciphertext or wrong key fails to open rather than returning garbage.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// A sealed blob: the KEK-wrapped DEK and the DEK-encrypted payload, each with its own nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    /// nonce used to wrap the DEK under the KEK (hex).
    pub dek_nonce: String,
    /// the DEK, encrypted under the KEK (hex): AES-GCM ciphertext+tag.
    pub wrapped_dek: String,
    /// nonce used to encrypt the payload under the DEK (hex).
    pub data_nonce: String,
    /// the payload, encrypted under the DEK (hex): AES-GCM ciphertext+tag.
    pub ciphertext: String,
}

fn seal(key_bytes: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<(String, String), String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| "bad key".to_string())?;
    let key = LessSafeKey::new(unbound);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| "rng".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "seal failed".to_string())?;
    Ok((hex::encode(nonce_bytes), hex::encode(in_out)))
}

fn open(key_bytes: &[u8; 32], nonce_hex: &str, ct_hex: &str, aad: &[u8]) -> Result<Vec<u8>, String> {
    let unbound = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| "bad key".to_string())?;
    let key = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; NONCE_LEN] = hex::decode(nonce_hex)
        .map_err(|_| "bad nonce".to_string())?
        .try_into()
        .map_err(|_| "nonce len".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = hex::decode(ct_hex).map_err(|_| "bad ct".to_string())?;
    let plain = key
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| "open failed (wrong key or tampered)".to_string())?;
    Ok(plain.to_vec())
}

/// Encrypt a blob under a customer KEK. `aad` binds the ciphertext to a context (e.g. the tenant +
/// args_hash), so a blob cannot be replayed under a different record.
pub fn encrypt(kek: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Envelope, String> {
    // Fresh random DEK per blob.
    let rng = SystemRandom::new();
    let mut dek = [0u8; 32];
    rng.fill(&mut dek).map_err(|_| "rng".to_string())?;
    // Encrypt the payload under the DEK, then wrap the DEK under the KEK.
    let (data_nonce, ciphertext) = seal(&dek, plaintext, aad)?;
    let (dek_nonce, wrapped_dek) = seal(kek, &dek, aad)?;
    Ok(Envelope { dek_nonce, wrapped_dek, data_nonce, ciphertext })
}

/// Decrypt a blob: unwrap the DEK with the KEK, then decrypt the payload. Wrong KEK or a tampered
/// envelope fails to open.
pub fn decrypt(kek: &[u8; 32], env: &Envelope, aad: &[u8]) -> Result<Vec<u8>, String> {
    let dek_vec = open(kek, &env.dek_nonce, &env.wrapped_dek, aad)?;
    let dek: [u8; 32] = dek_vec.try_into().map_err(|_| "dek len".to_string())?;
    open(&dek, &env.data_nonce, &env.ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_under_the_customer_key() {
        let kek = [9u8; 32];
        let env = encrypt(&kek, b"pii: jane@example.com", b"tenant=acme").unwrap();
        let back = decrypt(&kek, &env, b"tenant=acme").unwrap();
        assert_eq!(back, b"pii: jane@example.com");
        // Ciphertext is not the plaintext.
        assert!(!env.ciphertext.contains(&hex::encode(b"jane")));
    }

    #[test]
    fn a_wrong_key_cannot_decrypt_crypto_erasure() {
        let env = encrypt(&[1u8; 32], b"secret", b"aad").unwrap();
        // Revoking/rotating the KEK (a different key) makes the blob unreadable.
        assert!(decrypt(&[2u8; 32], &env, b"aad").is_err());
    }

    #[test]
    fn a_tampered_ciphertext_fails_authentication() {
        let kek = [7u8; 32];
        let mut env = encrypt(&kek, b"secret", b"aad").unwrap();
        // Flip a hex nibble in the ciphertext.
        let mut c: Vec<char> = env.ciphertext.chars().collect();
        c[0] = if c[0] == 'a' { 'b' } else { 'a' };
        env.ciphertext = c.into_iter().collect();
        assert!(decrypt(&kek, &env, b"aad").is_err(), "GCM tag must reject tampering");
    }

    #[test]
    fn aad_binds_the_blob_to_its_context() {
        let kek = [5u8; 32];
        let env = encrypt(&kek, b"secret", b"tenant=acme").unwrap();
        // Presenting the blob under a different context (aad) fails.
        assert!(decrypt(&kek, &env, b"tenant=globex").is_err());
    }
}
