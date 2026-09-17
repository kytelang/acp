//! acp: the single CLI (init, verify, export, policy-compile, policy-test).

use acp_policy::{build_context, PolicyEngine};
use serde_json::Value;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("help") {
        "policy-compile" => match args.get(2) {
            Some(p) => policy_compile(p),
            None => usage("acp policy-compile <policy.yaml>"),
        },
        "policy-test" => run_policy_test(&args[2..]),
        "verify" => match args.get(2) {
            Some(p) => cmd_verify(p),
            None => usage("acp verify <ledger.db>"),
        },
        "verify-pack" => match args.get(2) {
            Some(p) => cmd_verify_pack(p),
            None => usage("acp verify-pack <pack.json>"),
        },
        "export" => match args.get(2) {
            Some(p) => cmd_export(p),
            None => usage("acp export <ledger.db>"),
        },
        _ => usage("acp [init|verify|export|policy-compile|policy-test]"),
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("usage: {msg}");
    ExitCode::from(2)
}

fn load(path: &str) -> Result<PolicyEngine, ExitCode> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("acp: cannot read {path}: {e}");
        ExitCode::from(1)
    })?;
    PolicyEngine::from_yaml(&src).map_err(|e| {
        eprintln!("acp: invalid policy {path}: {e}");
        ExitCode::from(1)
    })
}

fn policy_compile(path: &str) -> ExitCode {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match acp_policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: invalid policy {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = acp_policy::validate(&policy) {
        eprintln!("acp: invalid policy {path}: {e}");
        return ExitCode::from(1);
    }
    print!("{}", acp_policy::compile_to_cedar(&policy));
    ExitCode::SUCCESS
}

/// `acp policy-test <policy.yaml> <calls.jsonl>`            -> verdict per call
/// `acp policy-test --diff <old.yaml> <new.yaml> <calls.jsonl>` -> only the calls whose verdict flips
fn run_policy_test(rest: &[String]) -> ExitCode {
    if rest.first().map(String::as_str) == Some("--diff") {
        if rest.len() < 4 {
            return usage("acp policy-test --diff <old.yaml> <new.yaml> <calls.jsonl>");
        }
        let old = match load(&rest[1]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let new = match load(&rest[2]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let calls = match read_calls(&rest[3]) {
            Ok(c) => c,
            Err(c) => return c,
        };
        let mut flips = 0;
        for (i, ctx) in calls.iter().enumerate() {
            let a = old.evaluate(ctx.clone()).verdict;
            let b = new.evaluate(ctx.clone()).verdict;
            if a != b {
                flips += 1;
                println!("flip call#{i} {}: {a:?} -> {b:?}", label(ctx));
            }
        }
        println!("{flips} of {} calls change verdict", calls.len());
        ExitCode::SUCCESS
    } else {
        if rest.len() < 2 {
            return usage("acp policy-test <policy.yaml> <calls.jsonl>");
        }
        let engine = match load(&rest[0]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let calls = match read_calls(&rest[1]) {
            Ok(c) => c,
            Err(c) => return c,
        };
        for (i, ctx) in calls.iter().enumerate() {
            let out = engine.evaluate(ctx.clone());
            println!(
                "call#{i} {}: {:?}{}",
                label(ctx),
                out.verdict,
                out.rule_id
                    .map(|r| format!(" (rule {r})"))
                    .unwrap_or_default()
            );
        }
        ExitCode::SUCCESS
    }
}

/// Each line of the calls file is `{"tool":"...","args":{...},"env":"..."}`. It is turned into a
/// namespaced context exactly as the proxy would build it.
fn read_calls(path: &str) -> Result<Vec<Value>, ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("acp: cannot read {path}: {e}");
        ExitCode::from(1)
    })?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).map_err(|e| {
            eprintln!("acp: {path}:{}: invalid JSON: {e}", n + 1);
            ExitCode::from(1)
        })?;
        let tool = v.get("tool").and_then(Value::as_str).unwrap_or("");
        let args = v
            .get("args")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let env = v.get("env").and_then(Value::as_str).unwrap_or("prod");
        out.push(build_context(tool, &args, env));
    }
    Ok(out)
}

fn cmd_verify(path: &str) -> ExitCode {
    match acp_ledger::verify_file(path) {
        Ok(()) => {
            println!("OK: {path} verifies");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_verify_pack(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let pack: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("acp: invalid pack: {e}");
            return ExitCode::from(1);
        }
    };
    match acp_ledger::verify_pack(&pack) {
        Ok(()) => {
            println!("OK: export pack verifies standalone");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_export(path: &str) -> ExitCode {
    match acp_ledger::export_file(path) {
        Ok(pack) => {
            println!("{}", serde_json::to_string_pretty(&pack).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("acp: export failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn label(ctx: &Value) -> String {
    ctx.get("tool")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}
