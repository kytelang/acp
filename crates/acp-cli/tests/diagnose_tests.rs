//! X.4 support without seeing arguments: the diagnose bundle must explain a decision using the
//! record fields (verdict, rule, impact, hash) and must never emit the raw argument payload.

use acp_core::sign::Ed25519Signer;
use acp_ledger::Ledger;
use serde_json::json;
use std::process::Command;

#[test]
fn diagnose_bundle_omits_raw_args_but_keeps_the_hash() {
    let dir = std::env::temp_dir().join(format!("acp-diag-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("l.db");
    let _ = std::fs::remove_file(&db);

    // Write one decision record whose args carry a secret we must never see in the bundle.
    let secret = "topsecret-value-42";
    {
        let mut l =
            Ledger::open(db.to_str().unwrap(), Box::new(Ed25519Signer::generate())).unwrap();
        let rec = json!({
            "schema": 1, "type": "decision", "ts_ms": 1, "hlc": "000:000:p",
            "action": {"tool": "payments.charge", "args_hash": "abc123", "impact": "high", "env": "prod"},
            "decision": {"verdict": "deny", "rule_id": "cap", "matched": "amount over cap",
                         "policy_hash": "deadbeef", "reason": "amount over cap"}
        });
        l.append(
            "d1",
            "decision",
            &rec,
            Some(&json!({"amount_cents": 90000, "note": secret})),
        )
        .unwrap();
    }

    let out = Command::new(env!("CARGO_BIN_EXE_acp-cli"))
        .arg("diagnose")
        .arg(db.to_str().unwrap())
        .arg("1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "diagnose failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"verdict\""),
        "bundle should carry the verdict: {text}"
    );
    assert!(text.contains("abc123"), "bundle should carry the args hash");
    assert!(
        !text.contains(secret),
        "bundle must NOT leak raw args: {text}"
    );
    assert!(!text.contains("90000"), "bundle must NOT leak raw args");
}
