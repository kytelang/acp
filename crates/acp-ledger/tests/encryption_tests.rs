//! P0-1: at-rest encryption of argument blobs. Verifies the security property (no plaintext on disk),
//! functional round-trip, fail-safe on wrong/absent key, backward compatibility with plaintext
//! ledgers, verification unaffected, and that erasure still works.

use acp_core::sign::Ed25519Signer;
use acp_ledger::{read_record_with_kek, Ledger};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};

static N: AtomicU32 = AtomicU32::new(0);

fn tmp(tag: &str) -> String {
    let n = N.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!("acp-enc-{}-{}-{}.db", std::process::id(), tag, n))
        .to_string_lossy()
        .into_owned()
}

// Scan the db file and its WAL sidecar for a needle.
fn on_disk_contains(path: &str, needle: &[u8]) -> bool {
    let mut hay: Vec<u8> = Vec::new();
    for p in [path.to_string(), format!("{path}-wal"), format!("{path}-shm")] {
        if let Ok(b) = std::fs::read(&p) {
            hay.extend_from_slice(&b);
        }
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

const SSN: &str = "123-45-6789";

fn rec() -> serde_json::Value {
    json!({"schema":1,"type":"decision","action":{"tool":"charge_card","impact":"high"}})
}
fn args() -> serde_json::Value {
    json!({"ssn": SSN, "amount_cents": 50000})
}

#[test]
fn encrypted_no_plaintext_on_disk_and_round_trips() {
    let kek = [7u8; 32];
    let path = tmp("enc");
    {
        let mut l =
            Ledger::open_with_kek(&path, Box::new(Ed25519Signer::generate()), Some(kek)).unwrap();
        l.append("d1", "decision", &rec(), Some(&args())).unwrap();
        assert!(l.verify().is_ok(), "encrypted ledger must still verify");
    }
    // The sensitive value must NOT be recoverable from the raw store.
    assert!(
        !on_disk_contains(&path, SSN.as_bytes()),
        "plaintext SSN leaked to disk"
    );
    // With the right KEK it decrypts.
    let (_r, a) = read_record_with_kek(&path, 1, Some(kek)).unwrap();
    assert_eq!(a.expect("args present")["ssn"], SSN);
}

#[test]
fn wrong_or_absent_kek_reveals_nothing() {
    let kek = [7u8; 32];
    let path = tmp("wrong");
    {
        let mut l =
            Ledger::open_with_kek(&path, Box::new(Ed25519Signer::generate()), Some(kek)).unwrap();
        l.append("d1", "decision", &rec(), Some(&args())).unwrap();
    }
    // Wrong KEK: no decrypt, no error, no leak.
    let (_r, a) = read_record_with_kek(&path, 1, Some([9u8; 32])).unwrap();
    assert!(a.is_none(), "wrong KEK must not decrypt");
    // No KEK at all: same.
    let (_r2, a2) = read_record_with_kek(&path, 1, None).unwrap();
    assert!(a2.is_none(), "absent KEK must not decrypt");
}

#[test]
fn plaintext_ledger_backward_compatible() {
    let path = tmp("plain");
    {
        let mut l = Ledger::open_with_kek(&path, Box::new(Ed25519Signer::generate()), None).unwrap();
        l.append("d1", "decision", &rec(), Some(&args())).unwrap();
    }
    // Readable without a KEK (legacy behaviour).
    let (_r, a) = read_record_with_kek(&path, 1, None).unwrap();
    assert_eq!(a.expect("args")["ssn"], SSN);
    // A KEK-holder still reads legacy plaintext (untagged blob passes through).
    let (_r2, a2) = read_record_with_kek(&path, 1, Some([7u8; 32])).unwrap();
    assert_eq!(a2.expect("args")["ssn"], SSN);
}

#[test]
fn erasure_still_works_on_encrypted_blobs() {
    let kek = [7u8; 32];
    let path = tmp("erase");
    {
        let mut l =
            Ledger::open_with_kek(&path, Box::new(Ed25519Signer::generate()), Some(kek)).unwrap();
        l.append("d1", "decision", &rec(), Some(&args())).unwrap();
        let n = l.erase_args_for("d1").unwrap();
        assert_eq!(n, 1, "erasure removes the encrypted blob");
        assert!(l.verify().is_ok(), "ledger still verifies after erasure");
    }
    let (_r, a) = read_record_with_kek(&path, 1, Some(kek)).unwrap();
    assert!(a.is_none(), "erased args are gone");
}


#[test]
fn kek_from_file_env_source() {
    // A KEK provided via ACP_LEDGER_KEK_FILE (a mounted secret file) drives encryption end to end.
    let kek_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let kekfile = std::env::temp_dir().join(format!("acp-kek-{}.hex", std::process::id()));
    std::fs::write(&kekfile, format!("{kek_hex}\n")).unwrap();
    // acp_ledger::kek_from_env reads the file when ACP_LEDGER_KEK_FILE is set.
    std::env::set_var("ACP_LEDGER_KEK_FILE", &kekfile);
    let kek = acp_ledger::kek_from_env().expect("kek from file");
    std::env::remove_var("ACP_LEDGER_KEK_FILE");
    let mut expect = [0u8; 32];
    for (i, b) in expect.iter_mut().enumerate() {
        *b = u8::from_str_radix(&kek_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    assert_eq!(kek, expect, "KEK loaded from file must match the hex contents");
    let _ = std::fs::remove_file(&kekfile);
}
