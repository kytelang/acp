//! M2.6: the proxy enforces policy on tools/call. A deny returns a structured isError naming the
//! rule; an allowed call is forwarded to the tool server unchanged.

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
  - id: cap-spend
    when:
      tool: "payments.charge"
      arg:
        amount_cents: { gt: 50000 }
    verdict: deny
    reason: "charge over 500.00 is not permitted"
"#;

fn drive(program: &str, args: &[&str], requests: &[String]) -> Vec<Value> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn");
    {
        let mut sin = child.stdin.take().unwrap();
        for r in requests {
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

fn by_id(frames: &[Value], id: i64) -> Option<&Value> {
    frames
        .iter()
        .find(|f| f.get("id").and_then(Value::as_i64) == Some(id))
}

#[test]
fn deny_blocks_allow_forwards() {
    let policy_path = format!("{TMP}/cap-policy.yaml");
    std::fs::write(&policy_path, POLICY).unwrap();

    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        // over threshold -> denied by cap-spend
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}).to_string(),
        // under threshold -> allowed, forwarded to the mock
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":100}}}).to_string(),
        // different tool -> default allow, forwarded
        json!({"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}).to_string(),
    ];
    let frames = drive(
        PROXY,
        &["stdio", "--policy", &policy_path, "--", MOCK],
        &reqs,
    );

    // id 10 blocked: a structured isError result naming the rule, never forwarded to the mock.
    let denied = by_id(&frames, 10).expect("response for 10");
    assert_eq!(
        denied.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "id 10 must be isError"
    );
    let text = denied
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        text.contains("cap-spend"),
        "denial should name the rule, got: {text}"
    );

    // id 11 allowed: forwarded, mock echoed a normal (non-error) result.
    let ok = by_id(&frames, 11).expect("response for 11");
    assert!(
        ok.pointer("/result/content").is_some(),
        "id 11 should be forwarded and echoed"
    );
    assert_ne!(ok.pointer("/result/isError"), Some(&Value::Bool(true)));

    // id 12 different tool allowed and forwarded.
    assert!(by_id(&frames, 12)
        .unwrap()
        .pointer("/result/content")
        .is_some());
}

#[test]
fn typed_bypass_is_blocked_end_to_end() {
    let policy_path = format!("{TMP}/cap-policy2.yaml");
    std::fs::write(&policy_path, POLICY).unwrap();
    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        // amount as a STRING must not bypass the numeric guard: fails closed (denied).
        json!({"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":"90000"}}}).to_string(),
    ];
    let frames = drive(
        PROXY,
        &["stdio", "--policy", &policy_path, "--", MOCK],
        &reqs,
    );
    let d = by_id(&frames, 20).expect("response for 20");
    assert_eq!(
        d.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "string amount must fail closed"
    );
}
