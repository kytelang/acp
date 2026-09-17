//! E4: a per-tenant impact taxonomy drives enforcement (policy matches context.impact).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

fn drive(args: &[&str], reqs: &[String]) -> Vec<Value> {
    let mut child = Command::new(PROXY)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    {
        let mut sin = child.stdin.take().unwrap();
        for r in reqs {
            let _ = writeln!(sin, "{r}");
        }
    }
    let out = child.stdout.take().unwrap();
    let mut v = Vec::new();
    for line in BufReader::new(out).lines() {
        let l = match line {
            Ok(l) => l,
            Err(_) => break,
        };
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
fn custom_taxonomy_changes_enforcement() {
    // policy: deny anything the taxonomy scores as high impact
    let policy = format!("{TMP}/imp-policy.yaml");
    std::fs::write(&policy, "version: 1\ndefault: allow\nrules:\n  - id: high-blocked\n    when:\n      tool: \"*\"\n      impact: { eq: \"high\" }\n    verdict: deny\n").unwrap();
    // taxonomy: any external recipient alone = high
    let tax = format!("{TMP}/imp.yaml");
    std::fs::write(&tax, "version: impact@t1\nexternal_keys: [to]\nmedium_at: 1\nhigh_at: 2\namount_keys: []\ndestructive_ops: []\ndestructive_tool_substrings: []\namount_high_threshold: 0\n").unwrap();

    let reqs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        // has an external recipient -> taxonomy scores high -> policy denies
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"mail.send","arguments":{"to":"x@y.com"}}}).to_string(),
        // no external recipient -> low -> allowed
        json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hi"}}}).to_string(),
    ];
    let frames = drive(
        &["stdio", "--policy", &policy, "--impact", &tax, "--", MOCK],
        &reqs,
    );
    let denied = frames.iter().find(|f| f["id"] == json!(10)).unwrap();
    assert_eq!(
        denied.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "high-impact call denied: {denied}"
    );
    let ok = frames.iter().find(|f| f["id"] == json!(11)).unwrap();
    assert!(
        ok.pointer("/result/content").is_some(),
        "low-impact call forwarded: {ok}"
    );
}
