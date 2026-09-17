//! SIEM sinks (CEF/OCSF) and the fail-open/fail-closed durability surface.

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
        .stderr(Stdio::null())
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
fn cef_and_ocsf_sinks_are_redacted() {
    let cef = format!("{TMP}/s.cef");
    let ocsf = format!("{TMP}/s.ocsf");
    let policy = format!("{TMP}/s-policy.yaml");
    let _ = std::fs::remove_file(&cef);
    let _ = std::fs::remove_file(&ocsf);
    std::fs::write(&policy, POLICY).unwrap();
    let reqs = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string(),
        json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000,"pan":"4111111111111111"}}}).to_string(),
    ];
    drive(
        &[
            "stdio", "--policy", &policy, "--cef", &cef, "--ocsf", &ocsf, "--", MOCK,
        ],
        &reqs,
    );

    let cef_text = std::fs::read_to_string(&cef).unwrap();
    assert!(
        cef_text.contains("CEF:0|ACP|acp-proxy|1.0|deny"),
        "CEF line: {cef_text}"
    );
    assert!(cef_text.contains("cs1=payments.charge") && cef_text.contains("cs2=cap"));
    assert!(
        !cef_text.contains("4111111111111111"),
        "CEF must not leak raw args"
    );

    let ocsf_line: Value = serde_json::from_str(
        std::fs::read_to_string(&ocsf)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ocsf_line["class_uid"], json!(6003));
    assert_eq!(ocsf_line["unmapped"]["verdict"], json!("deny"));
    assert!(!std::fs::read_to_string(&ocsf)
        .unwrap()
        .contains("4111111111111111"));
}

#[test]
fn fail_closed_when_evidence_cannot_be_recorded() {
    let ledger = format!("{TMP}/fc.db");
    let policy = format!("{TMP}/fc-policy.yaml");
    for f in [
        &ledger,
        &format!("{ledger}.key"),
        &format!("{ledger}-wal"),
        &format!("{ledger}-shm"),
        &format!("{ledger}.approvals"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    // Force the durable spool write to fail by putting a DIRECTORY where the spool file goes.
    let spool_dir = format!("{ledger}.spool");
    let _ = std::fs::remove_file(&spool_dir);
    std::fs::create_dir_all(&spool_dir).unwrap();
    std::fs::write(&policy, "version: 1\ndefault: allow\nrules: []\n").unwrap();

    let call = json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}).to_string();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}).to_string();

    // Default (fail-closed): an allow whose evidence cannot be durably recorded is blocked.
    let closed = drive(
        &[
            "stdio", "--policy", &policy, "--ledger", &ledger, "--", MOCK,
        ],
        &[init.clone(), call.clone()],
    );
    let r = closed.iter().find(|f| f["id"] == json!(10)).unwrap();
    assert_eq!(
        r.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "must fail closed: {r}"
    );
    let txt = r
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(txt.contains("failing closed"));

    // With --fail-open: the same allow is forwarded despite the record failure.
    std::fs::create_dir_all(&spool_dir).ok(); // ensure the dir is still there
    let open = drive(
        &[
            "stdio",
            "--fail-open",
            "--policy",
            &policy,
            "--ledger",
            &ledger,
            "--",
            MOCK,
        ],
        &[init, call],
    );
    let r = open.iter().find(|f| f["id"] == json!(10)).unwrap();
    assert!(
        r.pointer("/result/content").is_some(),
        "fail-open must forward: {r}"
    );
}
