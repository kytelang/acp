//! B2 canary: synthetic decisions must prove the gate is live, and a mis-loaded policy that
//! lets a must-deny probe through must fail (page) within one probe run.

use std::fs;
use std::process::Command;

fn run(policy: &str, canaries: &str, dir: &std::path::Path) -> std::process::Output {
    let pol = dir.join("policy.yaml");
    let can = dir.join("canaries.json");
    fs::write(&pol, policy).unwrap();
    fs::write(&can, canaries).unwrap();
    Command::new(env!("CARGO_BIN_EXE_acp-cli"))
        .arg("canary")
        .arg(&pol)
        .arg(&can)
        .output()
        .unwrap()
}

#[test]
fn a_correct_policy_passes_its_canaries() {
    let dir = std::env::temp_dir().join(format!("acp-canary-ok-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let policy = "version: 1\ndefault: allow\nrules:\n  - id: no-delete\n    when:\n      tool: \"fs.delete\"\n    verdict: deny\n";
    let canaries = r#"[{"tool":"fs.delete","args":{},"expect":"deny"}]"#;
    let out = run(policy, canaries, &dir);
    assert!(
        out.status.success(),
        "canary should pass: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn a_mis_loaded_policy_fails_the_canary() {
    let dir = std::env::temp_dir().join(format!("acp-canary-bad-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // The rule that should deny fs.delete is missing, so the call falls through to default allow.
    let policy = "version: 1\ndefault: allow\nrules: []\n";
    let canaries = r#"[{"tool":"fs.delete","args":{},"expect":"deny"}]"#;
    let out = run(policy, canaries, &dir);
    assert!(
        !out.status.success(),
        "a policy that lets the must-deny probe through must page"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("FAIL") || combined.contains("PAGE"),
        "output: {combined}"
    );
}
