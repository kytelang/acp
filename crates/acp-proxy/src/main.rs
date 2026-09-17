//! acp-proxy: sits between an MCP client and the tool server(s), gates every `tools/call`, and
//! (from M3) streams a signed evidence record for each decision.
//!
//! `acp-proxy stdio [--policy <file.yaml>] [--env <env>] -- <mcp-server-cmd> [args...]`

mod evidence;
mod intercept;
mod limits;
mod policy;
mod stdio;

use acp_policy::PolicyEngine;
use std::process::ExitCode;
use std::sync::Arc;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("stdio") {
        eprintln!(
            "usage: acp-proxy stdio [--policy <file>] [--env <env>] -- <mcp-server-cmd> [args...]"
        );
        return ExitCode::SUCCESS;
    }

    // Split options (before `--`) from the child command (after `--`).
    let after: Vec<String> = args.iter().skip(2).cloned().collect();
    let split = after.iter().position(|a| a == "--");
    let (opts, cmd_args) = match split {
        Some(i) => (after[..i].to_vec(), after[i + 1..].to_vec()),
        None => (Vec::new(), after),
    };
    if cmd_args.is_empty() {
        eprintln!(
            "usage: acp-proxy stdio [--policy <file>] [--env <env>] -- <mcp-server-cmd> [args...]"
        );
        return ExitCode::from(2);
    }

    let mut policy_path: Option<String> = None;
    let mut ledger_path: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut env = "prod".to_string();
    let mut it = opts.iter();
    while let Some(o) = it.next() {
        match o.as_str() {
            "--policy" => policy_path = it.next().cloned(),
            "--ledger" => ledger_path = it.next().cloned(),
            "--key" => key_path = it.next().cloned(),
            "--env" => {
                if let Some(v) = it.next() {
                    env = v.clone();
                }
            }
            other => {
                eprintln!("acp-proxy: unknown option '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let engine = match policy_path {
        Some(p) => {
            let src = match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("acp-proxy: cannot read policy {p}: {e}");
                    return ExitCode::from(1);
                }
            };
            match PolicyEngine::from_yaml(&src) {
                Ok(e) => {
                    eprintln!(
                        "acp-proxy: policy loaded ({} ...)",
                        &e.hash()[..12.min(e.hash().len())]
                    );
                    Some(Arc::new(e))
                }
                Err(e) => {
                    eprintln!("acp-proxy: invalid policy {p}: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => None,
    };

    let evidence = match ledger_path {
        Some(lp) => {
            let kp = key_path.unwrap_or_else(|| format!("{lp}.key"));
            match evidence::Evidence::open(&lp, &kp) {
                Ok(ev) => {
                    eprintln!("acp-proxy: evidence ledger {lp} ({} records)", ev.size());
                    Some(ev)
                }
                Err(e) => {
                    eprintln!("acp-proxy: cannot open ledger {lp}: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => None,
    };

    match stdio::run(&cmd_args[0], &cmd_args[1..], engine, env, evidence).await {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("acp-proxy: {e}");
            ExitCode::from(1)
        }
    }
}
