//! B5: the proxy refuses to launch a tool-server binary whose fingerprint does not match.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const MOCK: &str = env!("CARGO_BIN_EXE_mock-mcp-server");

fn run(args: &[&str], reqs: &[String]) -> (bool, Vec<Value>) {
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
    let status = child.wait().unwrap();
    (status.success(), v)
}

fn sha256_file(path: &str) -> String {
    acp_core::canonical::sha256_hex_bytes(&std::fs::read(path).unwrap())
}

#[test]
fn wrong_tool_hash_refuses_launch() {
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string();
    // wrong hash -> refuse (non-zero exit, no responses)
    let (ok, frames) = run(
        &["stdio", "--tool-hash", &"0".repeat(64), "--", MOCK],
        std::slice::from_ref(&init),
    );
    assert!(!ok, "proxy must exit non-zero on a bad tool fingerprint");
    assert!(frames.is_empty(), "no MCP responses when launch is refused");
    // correct hash -> launches and responds
    let good = sha256_file(MOCK);
    let (_ok2, frames2) = run(&["stdio", "--tool-hash", &good, "--", MOCK], &[init]);
    assert!(
        frames2.iter().any(|f| f["id"] == json!(1)),
        "correct fingerprint launches the tool"
    );
}
