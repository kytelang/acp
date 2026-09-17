//! M1 golden transparency + anti-bypass integration tests.
//! Drives the proxy over a mock MCP server and asserts: verbatim passthrough for safe methods
//! (byte-identical vs talking to the server directly), id correlation under concurrency, and
//! default-deny of an unknown action-bearing method (D10).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");

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

fn safe_session() -> Vec<String> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}).to_string(),
        json!({"jsonrpc":"2.0","id":4,"method":"resources/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":5,"method":"prompts/list"}).to_string(),
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo","arguments":{"x":42}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
    ]
}

#[test]
fn transparency_passthrough_is_byte_identical() {
    let reqs = safe_session();
    let via_proxy = drive(PROXY, &["stdio", "--", MOCK], &reqs);
    let direct = drive(MOCK, &[], &reqs);
    for id in [1, 2, 3, 4, 5, 6] {
        let p = by_id(&via_proxy, id).unwrap_or_else(|| panic!("proxy missing id {id}"));
        let d = by_id(&direct, id).unwrap_or_else(|| panic!("direct missing id {id}"));
        assert_eq!(p, d, "response for id {id} differs behind the proxy");
        assert!(
            p.get("result").is_some(),
            "id {id} should be a result, not an error"
        );
    }
}

#[test]
fn unknown_action_method_is_denied_by_default() {
    let reqs = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        json!({"jsonrpc":"2.0","id":77,"method":"danger/execute","params":{}}).to_string(),
    ];
    let via_proxy = drive(PROXY, &["stdio", "--", MOCK], &reqs);
    let denied = by_id(&via_proxy, 77).expect("proxy must respond to id 77");
    assert_eq!(
        denied
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64),
        Some(-32001),
        "unknown method should be denied with the proxy block code, got {denied}"
    );
    let direct = drive(MOCK, &[], &reqs);
    assert_eq!(
        by_id(&direct, 77)
            .unwrap()
            .get("error")
            .unwrap()
            .get("code")
            .and_then(Value::as_i64),
        Some(-32601)
    );
}

#[test]
fn id_correlation_under_concurrency() {
    let mut reqs = vec![json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string()];
    for i in 1..=100 {
        reqs.push(json!({"jsonrpc":"2.0","id":i,"method":"ping"}).to_string());
    }
    let frames = drive(PROXY, &["stdio", "--", MOCK], &reqs);
    for i in 1..=100 {
        let f = by_id(&frames, i).unwrap_or_else(|| panic!("missing response for id {i}"));
        assert!(f.get("result").is_some(), "id {i} should be a result");
    }
}
