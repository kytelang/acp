//! M4 end-to-end: step-up holds for approval, then a re-issue is forwarded exactly once (D8).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

const POLICY: &str = r#"
version: 1
default: allow
rules:
  - id: bigcharge
    when: { tool: "payments.charge", arg: { amount_cents: { gt: 50000 } } }
    verdict: step_up
    approvers: ["dpo"]
"#;

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
    let mut frames = Vec::new();
    for line in BufReader::new(out).lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            frames.push(v);
        }
    }
    let _ = child.wait();
    frames
}

fn by_id(frames: &[Value], id: i64) -> &Value {
    frames
        .iter()
        .find(|f| f.get("id").and_then(Value::as_i64) == Some(id))
        .expect("response id")
}

#[test]
fn step_up_holds_then_forwards_exactly_once() {
    let approvals = format!("{TMP}/m4.approvals");
    let ledger = format!("{TMP}/m4.db");
    let key = format!("{TMP}/m4.key");
    let policy = format!("{TMP}/m4-policy.yaml");
    for f in [
        &approvals,
        &ledger,
        &key,
        &format!("{ledger}.spool"),
        &format!("{ledger}-wal"),
        &format!("{ledger}-shm"),
        &format!("{approvals}-wal"),
        &format!("{approvals}-shm"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, POLICY).unwrap();
    let proxy_args = [
        "stdio",
        "--policy",
        &policy,
        "--approvals",
        &approvals,
        "--ledger",
        &ledger,
        "--key",
        &key,
        "--",
        MOCK,
    ];
    let call = json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}).to_string();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string();

    // Session 1: first issue -> held with -32001 + approvalId.
    let s1 = drive(&proxy_args, &[init.clone(), call.clone()]);
    let held = by_id(&s1, 10);
    assert_eq!(
        held.pointer("/error/code").and_then(Value::as_i64),
        Some(-32001),
        "first issue must be held: {held}"
    );
    let approval_id = held
        .pointer("/error/data/approvalId")
        .and_then(Value::as_str)
        .expect("approvalId")
        .to_string();

    // A human approves out of band (here: directly via the store, as the CLI `acp approve` would).
    let store = acp_approvals::ApprovalStore::open(&approvals).unwrap();
    store
        .resolve(&approval_id, true, "boss@corp", "cli")
        .unwrap();
    drop(store);

    // Session 2: re-issue the identical call -> forwarded, mock echoes a normal result.
    let s2 = drive(&proxy_args, &[init.clone(), call.clone()]);
    let ok = by_id(&s2, 10);
    assert!(
        ok.pointer("/result/content").is_some(),
        "approved re-issue must be forwarded: {ok}"
    );
    assert_ne!(ok.pointer("/result/isError"), Some(&Value::Bool(true)));

    // Session 3: re-issue again -> single-use, the approval is spent.
    let s3 = drive(&proxy_args, &[init, call]);
    let spent = by_id(&s3, 10);
    let txt = spent
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        txt.contains("already used") || spent.pointer("/error").is_some(),
        "second re-issue must be blocked (single-use): {spent}"
    );

    // Evidence remains verifiable throughout.
    acp_ledger::verify_file(&ledger).expect("ledger verifies");
}

#[test]
fn changed_arguments_cannot_ride_an_approval() {
    let approvals = format!("{TMP}/m4b.approvals");
    let policy = format!("{TMP}/m4b-policy.yaml");
    for f in [
        &approvals,
        &format!("{approvals}-wal"),
        &format!("{approvals}-shm"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, POLICY).unwrap();
    let proxy_args = [
        "stdio",
        "--policy",
        &policy,
        "--approvals",
        &approvals,
        "--",
        MOCK,
    ];
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string();
    let call_a = json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}).to_string();
    let call_b = json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":95000}}}).to_string();

    let s1 = drive(&proxy_args, &[init.clone(), call_a.clone()]);
    let approval_id = by_id(&s1, 10)
        .pointer("/error/data/approvalId")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    // approve the $900 charge
    acp_approvals::ApprovalStore::open(&approvals)
        .unwrap()
        .resolve(&approval_id, true, "boss", "cli")
        .unwrap();

    // re-issue with DIFFERENT arguments ($950): must not be forwarded on the $900 approval.
    let s2 = drive(&proxy_args, &[init, call_b]);
    let held = by_id(&s2, 10);
    assert_eq!(
        held.pointer("/error/code").and_then(Value::as_i64),
        Some(-32001),
        "changed arguments must open a new hold, not ride the old approval: {held}"
    );
}
