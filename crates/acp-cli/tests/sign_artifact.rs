//! H0.9: signing a release artifact and verifying it round-trips; a tampered artifact fails.
use std::process::Command;

fn bin() -> &'static str { env!("CARGO_BIN_EXE_acp-cli") }

#[test]
fn sign_then_verify_round_trips_and_detects_tampering() {
    let dir = std::env::temp_dir().join(format!("acp-sign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let art = dir.join("release.txt");
    let key = dir.join("release.key");
    std::fs::write(&art, b"acp release v1 artifact bytes").unwrap();

    let s = Command::new(bin()).arg("sign-artifact").arg(&art).arg(&key).output().unwrap();
    assert!(s.status.success(), "sign failed: {}", String::from_utf8_lossy(&s.stderr));

    let pubf = format!("{}.pub", key.display());
    let sigf = format!("{}.sig", art.display());
    let v = Command::new(bin()).arg("verify-artifact").arg(&art).arg(&pubf).arg(&sigf).output().unwrap();
    assert!(v.status.success(), "valid signature must verify: {}", String::from_utf8_lossy(&v.stdout));

    // Tamper with the artifact; verification must now fail.
    std::fs::write(&art, b"acp release v1 artifact bytes TAMPERED").unwrap();
    let v2 = Command::new(bin()).arg("verify-artifact").arg(&art).arg(&pubf).arg(&sigf).output().unwrap();
    assert!(!v2.status.success(), "a tampered artifact must fail verification");
}
