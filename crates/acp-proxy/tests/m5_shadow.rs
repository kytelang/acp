//! M5.3: shadow mode records what would be blocked but forwards everything.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

const POLICY: &str = "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when: { tool: \"payments.charge\", arg: { amount_cents: { gt: 50000 } } }\n    verdict: deny\n";

fn drive(args: &[&str], reqs: &[String]) -> Vec<Value> {
    let mut child = Command::new(PROXY)
        .args(args)
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
    let out = child.stdout.take().unwrap();
    let mut v = Vec::new();
    for line in BufReader::new(out).lines() {
        let l = line.unwrap();
        if !l.trim().is_empty() {
            if let Ok(j) = serde_json::from_str(&l) {
                v.push(j);
            }
        }
    }
    let _ = child.wait();
    v
}

#[test]
fn shadow_forwards_but_records() {
    let db = format!("{TMP}/m5s.db");
    let policy = format!("{TMP}/m5s.yaml");
    for f in [
        &db,
        &format!("{db}.key"),
        &format!("{db}.spool"),
        &format!("{db}-wal"),
        &format!("{db}-shm"),
        &format!("{db}.approvals"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, POLICY).unwrap();
    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        // would be denied by policy, but shadow mode forwards it
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}).to_string(),
    ];
    let frames = drive(
        &[
            "stdio", "--shadow", "--policy", &policy, "--ledger", &db, "--", MOCK,
        ],
        &reqs,
    );
    let r = frames.iter().find(|f| f["id"] == json!(10)).unwrap();
    // forwarded: the mock echoed a normal result (NOT an isError block)
    assert!(
        r.pointer("/result/content").is_some(),
        "shadow must forward the call: {r}"
    );
    assert_ne!(r.pointer("/result/isError"), Some(&Value::Bool(true)));
    // but the would-block was still recorded and the ledger verifies
    acp_ledger::verify_file(&db).expect("ledger verifies");
    let pack = acp_ledger::export_file(&db).unwrap();
    assert!(
        pack["records"].as_array().unwrap().len() >= 2,
        "would-block decision + outcome recorded"
    );
}
