//! Signed, versioned policy deployment (decision X.6 / H0.6 / v3.4).
//!
//! A policy is enforcement code, so deploying one is a controlled action: validate it, sign it, give
//! it a version, and record who signed it. The proxy loads the current policy only after verifying
//! that signature, and fails closed if it does not check out. This composes the pieces already
//! built: `PolicyEngine` validation, `policyprov` signing/verification, and (for rollout) the
//! `rollout` state machine. Local-first: the store is a directory the proxy watches, no cloud.

use crate::policy::eval::PolicyEngine;
use crate::policyprov::{sign_policy, verify_policy, SignedPolicy};
use crate::sign::Signer;
use serde_json::{json, Value};
use std::fs;

#[derive(Debug, Clone)]
pub struct Deployed {
    pub version: u32,
    pub hash: String,
    pub file: String,
}

fn next_version(store_dir: &str) -> u32 {
    let mut max = 0u32;
    if let Ok(rd) = fs::read_dir(store_dir) {
        for e in rd.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if let Some(v) = name.strip_prefix('v').and_then(|s| s.strip_suffix(".yaml")) {
                    if let Ok(n) = v.parse::<u32>() {
                        max = max.max(n);
                    }
                }
            }
        }
    }
    max + 1
}

/// Deploy a policy: validate, version, sign (author-bound), and write. Returns the deployed version.
/// A policy that does not compile is rejected before anything is written.
pub fn deploy(policy_src: &str, store_dir: &str, signer: &dyn Signer, author: &str) -> Result<Deployed, String> {
    let engine = PolicyEngine::from_yaml(policy_src)?; // validates + compiles to Cedar
    let hash = engine.hash().to_string();
    fs::create_dir_all(store_dir).map_err(|e| e.to_string())?;
    let version = next_version(store_dir);
    let file = format!("v{version}.yaml");
    fs::write(format!("{store_dir}/{file}"), policy_src).map_err(|e| e.to_string())?;
    let signed = sign_policy(signer, &hash, author);
    let current = json!({
        "version": version,
        "hash": hash,
        "author": author,
        "file": file,
        "sig": hex::encode(&signed.sig),
        "pubkey": hex::encode(signer.public_key()),
    });
    fs::write(format!("{store_dir}/current.json"), serde_json::to_string_pretty(&current).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(Deployed { version, hash, file })
}

/// Metadata about the current deployment, without loading the engine.
pub fn current_info(store_dir: &str) -> Result<Value, String> {
    let raw = fs::read(format!("{store_dir}/current.json")).map_err(|e| e.to_string())?;
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

/// The raw YAML source of the current deployed policy, for read-only inspection in the console.
/// This is the same file whose hash is bound into the signed manifest, so what the operator reads
/// here is exactly what the proxy enforces.
pub fn current_source(store_dir: &str) -> Result<String, String> {
    let cur = current_info(store_dir)?;
    let file = cur.get("file").and_then(|v| v.as_str()).ok_or_else(|| "no current policy".to_string())?;
    fs::read_to_string(format!("{store_dir}/{file}")).map_err(|e| e.to_string())
}

/// Load the current policy, verifying its signature and that the file has not been tampered with.
/// Fails closed on a bad signature or a file whose hash does not match the signed manifest.
pub fn load_current(store_dir: &str) -> Result<PolicyEngine, String> {
    let cur = current_info(store_dir)?;
    let get = |k: &str| cur.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (hash, author, file) = (get("hash"), get("author"), get("file"));
    let sig = hex::decode(get("sig")).map_err(|_| "bad sig hex".to_string())?;
    let pubkey = hex::decode(get("pubkey")).map_err(|_| "bad pubkey hex".to_string())?;

    let src = fs::read_to_string(format!("{store_dir}/{file}")).map_err(|e| e.to_string())?;
    load_signed(&src, &hash, &author, &sig, &pubkey)
}

/// Verify and load a signed policy from its parts (no filesystem), so a remote enforcement point can
/// fetch the deployed policy over HTTP and load it under the same rules as the on-disk store: verify
/// the author-bound signature against the public key, then confirm the source hashes to the signed
/// manifest. Fails closed on either check.
pub fn load_signed(
    source: &str,
    hash: &str,
    author: &str,
    sig: &[u8],
    pubkey: &[u8],
) -> Result<PolicyEngine, String> {
    let signed = SignedPolicy { policy_hash: hash.to_string(), author: author.to_string(), sig: sig.to_vec() };
    if !verify_policy(pubkey, &signed) {
        return Err("policy signature verification failed (fail-closed)".into());
    }
    let engine = PolicyEngine::from_yaml(source)?;
    if engine.hash() != hash {
        return Err("policy source hash does not match the signed manifest (tampered)".into());
    }
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn tmp(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("acp-pstore-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.to_string_lossy().to_string()
    }
    const POL: &str = "version: 1\ndefault: allow\nrules:\n  - id: r\n    when: { tool: \"x\" }\n    verdict: deny\n";

    #[test]
    fn load_signed_round_trips_and_is_tamper_evident() {
        use crate::canonical::sha256_hex;
        let signer = Ed25519Signer::generate();
        let hash = sha256_hex(&POL.to_string());
        let signed = crate::policyprov::sign_policy(&signer, &hash, "alice");
        let pk = crate::sign::Signer::public_key(&signer);
        // Correct parts verify and load.
        assert!(load_signed(POL, &hash, "alice", &signed.sig, &pk).is_ok());
        // A tampered source (hash no longer matches the signed manifest) is rejected.
        let other = "version: 1\ndefault: allow\nrules: []\n";
        assert!(load_signed(other, &hash, "alice", &signed.sig, &pk).is_err());
        // A wrong public key is rejected (signature does not verify).
        let pk2 = crate::sign::Signer::public_key(&Ed25519Signer::generate());
        assert!(load_signed(POL, &hash, "alice", &signed.sig, &pk2).is_err());
    }

    #[test]
    fn deploy_then_load_verifies() {
        let dir = tmp("load");
        let signer = Ed25519Signer::generate();
        let d = deploy(POL, &dir, &signer, "alice").unwrap();
        assert_eq!(d.version, 1);
        let engine = load_current(&dir).unwrap();
        assert_eq!(engine.hash(), d.hash);
        // second deploy bumps the version
        let d2 = deploy(POL, &dir, &signer, "alice").unwrap();
        assert_eq!(d2.version, 2);
    }

    #[test]
    fn a_tampered_policy_file_fails_closed() {
        let dir = tmp("tamper");
        let signer = Ed25519Signer::generate();
        deploy(POL, &dir, &signer, "alice").unwrap();
        // Edit the deployed policy file directly (the signed manifest still says the old hash).
        std::fs::write(
            format!("{dir}/v1.yaml"),
            "version: 1\ndefault: allow\nrules: []\n",
        )
        .unwrap();
        assert!(load_current(&dir).is_err(), "tampered policy must not load");
    }

    #[test]
    fn a_forged_signature_fails_closed() {
        let dir = tmp("forge");
        let signer = Ed25519Signer::generate();
        deploy(POL, &dir, &signer, "alice").unwrap();
        // Replace the pubkey with a different key's: the signature no longer verifies.
        let mut cur: Value = current_info(&dir).unwrap();
        cur["pubkey"] = json!(hex::encode(Ed25519Signer::generate().public_key()));
        std::fs::write(format!("{dir}/current.json"), cur.to_string()).unwrap();
        assert!(load_current(&dir).is_err(), "forged signature must not load");
    }
}
