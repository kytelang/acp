//! D14/F1: a redacted governance event is emitted per decision, carrying no raw arguments.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

const POLICY: &str = "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when: { tool: \"payments.charge\", arg: { amount_cents: { gt: 50000 } } }\n    verdict: deny\n";

#[test]
fn emits_redacted_governance_events() {
    let events = format!("{TMP}/events.jsonl");
    let policy = format!("{TMP}/ev-policy.yaml");
    let _ = std::fs::remove_file(&events);
    std::fs::write(&policy, POLICY).unwrap();

    let reqs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000,"secret_note":"card 4111111111111111"}}}).to_string(),
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}).to_string(),
    ];
    let mut child = Command::new(PROXY)
        .args([
            "stdio", "--policy", &policy, "--events", &events, "--", MOCK,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut sin = child.stdin.take().unwrap();
        for r in &reqs {
            writeln!(sin, "{r}").unwrap();
        }
    }
    let _ = child.wait();

    let text = std::fs::read_to_string(&events).expect("events file");
    let lines: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "one event per tool call, got {}",
        lines.len()
    );

    // The deny event names the verdict/rule/outcome...
    let deny = lines
        .iter()
        .find(|e| e["tool"] == json!("payments.charge"))
        .unwrap();
    assert_eq!(deny["verdict"], json!("deny"));
    assert_eq!(deny["outcome"], json!("denied"));
    assert_eq!(deny["rule_id"], json!("cap"));
    // ...but carries NO raw arguments (telemetry PII hygiene).
    assert!(
        !text.contains("4111111111111111"),
        "events must not leak raw args"
    );
    assert!(
        !text.contains("secret_note"),
        "events must not leak arg keys/values"
    );

    let allow = lines.iter().find(|e| e["tool"] == json!("echo")).unwrap();
    assert_eq!(allow["verdict"], json!("allow"));
    assert_eq!(allow["outcome"], json!("forwarded"));
}
