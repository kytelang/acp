//! Shared helpers for the acp CLI commands: argv flag parsing, ledger loading, call reading, and the
//! retired-command pointer.
use acp_core::policy::{build_context, PolicyEngine};
use serde_json::Value;
use std::process::ExitCode;

/// Read the value following a `--flag` in an argv slice, if present.
pub(crate) fn flag_value(rest: &[String], flag: &str) -> Option<String> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

pub(crate) fn load(path: &str) -> Result<PolicyEngine, ExitCode> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("acp: cannot read {path}: {e}");
        ExitCode::from(1)
    })?;
    PolicyEngine::from_yaml(&src).map_err(|e| {
        eprintln!("acp: invalid policy {path}: {e}");
        ExitCode::from(1)
    })
}

/// Each line of the calls file is `{"tool":"...","args":{...},"env":"..."}`. It is turned into a
/// namespaced context exactly as the proxy would build it.
pub(crate) fn read_calls(path: &str) -> Result<Vec<Value>, ExitCode> {
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

/// Management commands are retired from the CLI: registration, policy, approvals, the kill-switch, AI
/// endpoints and the GRC records are managed from the console or the control-plane API and stored
/// centrally. This prints where to do it instead and exits non-zero.
pub(crate) fn retired(cmd: &str, hint: &str) -> ExitCode {
    eprintln!("acp: `{cmd}` is retired from the CLI. Manage it from the console or the control-plane API. {hint}");
    ExitCode::from(2)
}

pub(crate) fn label(ctx: &Value) -> String {
    ctx.get("tool")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}

/// Print an endpoint registry as YAML (default) or, with --key, as a signed JSON registry.
pub(crate) fn emit_registry(registry: &acp_core::interception::EndpointRegistry, key: Option<String>) -> ExitCode {
    match key {
        Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
            Some(seed) => { println!("{}", serde_json::to_string_pretty(&registry.sign(&acp_core::sign::Ed25519Signer::from_seed(&seed))).unwrap_or_default()); ExitCode::SUCCESS }
            None => { eprintln!("acp: --key must be 32-byte hex"); ExitCode::from(2) }
        },
        None => { println!("{}", serde_yaml::to_string(registry).unwrap_or_default()); ExitCode::SUCCESS }
    }
}

pub(crate) fn usage(msg: &str) -> ExitCode {
    eprintln!("usage: {msg}");
    ExitCode::from(2)
}
