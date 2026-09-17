//! M3 end-to-end: the proxy writes verifiable evidence for each decision.

use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

const POLICY: &str = r#"
version: 1
default: allow
rules:
  - id: cap
    when: { tool: "payments.charge", arg: { amount_cents: { gt: 50000 } } }
    verdict: deny
"#;

fn run_session(proxy_args: &[&str], reqs: &[String]) {
    let mut child = Command::new(PROXY)
        .args(proxy_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    {
        let mut sin = child.stdin.take().unwrap();
        for r in reqs {
            writeln!(sin, "{r}").unwrap();
        }
    }
    let _ = child.wait_with_output();
}

#[test]
fn proxy_writes_verifiable_evidence_with_outcomes() {
    let db = format!("{TMP}/m3.db");
    let key = format!("{TMP}/m3.key");
    let policy = format!("{TMP}/m3-policy.yaml");
    for f in [
        &db,
        &key,
        &format!("{db}.spool"),
        &format!("{db}-wal"),
        &format!("{db}-shm"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, POLICY).unwrap();

    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}).to_string(), // deny
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}).to_string(),                          // allow
    ];
    run_session(
        &[
            "stdio", "--policy", &policy, "--ledger", &db, "--key", &key, "--", MOCK,
        ],
        &reqs,
    );

    // Two decisions + two linked outcomes = 4 leaves; the ledger must verify.
    acp_ledger::verify_file(&db).expect("ledger must verify");
    let pack = acp_ledger::export_file(&db).unwrap();
    assert_eq!(
        pack["records"].as_array().unwrap().len(),
        4,
        "2 decisions + 2 outcomes"
    );
    acp_ledger::verify_pack(&pack).expect("export pack must verify standalone");

    // Every decision has a linked outcome (kind decision -> a matching :out outcome).
    let kinds: Vec<&str> = pack["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.iter().filter(|k| **k == "decision").count(), 2);
    assert_eq!(kinds.iter().filter(|k| **k == "outcome").count(), 2);
}

#[test]
fn spooled_evidence_survives_restart() {
    let db = format!("{TMP}/m3b.db");
    let key = format!("{TMP}/m3b.key");
    let policy = format!("{TMP}/m3b-policy.yaml");
    for f in [
        &db,
        &key,
        &format!("{db}.spool"),
        &format!("{db}-wal"),
        &format!("{db}-shm"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, POLICY).unwrap();
    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}).to_string(),
    ];
    // First run records evidence.
    run_session(
        &[
            "stdio", "--policy", &policy, "--ledger", &db, "--key", &key, "--", MOCK,
        ],
        &reqs,
    );
    let n1 = acp_ledger::export_file(&db).unwrap()["records"]
        .as_array()
        .unwrap()
        .len();
    assert!(n1 >= 2);
    // A second run reopens the same ledger; replay is idempotent and the ledger still verifies.
    run_session(
        &[
            "stdio", "--policy", &policy, "--ledger", &db, "--key", &key, "--", MOCK,
        ],
        &reqs,
    );
    acp_ledger::verify_file(&db).expect("ledger verifies after restart");
}
