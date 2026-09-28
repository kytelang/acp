//! acp-agent: the single workstation service. One binary; what it does is configuration.
//!
//!   acp-agent firewall --listen <addr> --control-plane <url> [opts]        # forward proxy + content firewall
//!   acp-agent mcp stdio --control-plane <url> [opts] -- <tool-server-cmd>  # govern an MCP tool server (stdio)
//!   acp-agent mcp http  --addr <addr> --upstream <url> --control-plane <url>
//!   acp-agent guard --listen <addr> --upstream <url> --control-plane <url> [opts]  # tool-server sidecar
//!
//! `--control-plane <url>` is the one thing an operator sets: it is expanded into the per-capability
//! control-plane URLs (rules, firewall config, reporting, evidence, approvals), so the workstation
//! carries no local rule or model files. Explicit per-URL flags still override.

mod jsonrpc;
mod proxy;
mod intercept;
mod guard;
use std::process::ExitCode;

enum Cap { Firewall, Mcp, Guard }

/// Read `--name <value>` from args (first occurrence), or None.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// Run several capabilities at once from one config: enable each with its listen address, all sharing
/// one --control-plane. This is the "one workstation service, multiple capabilities by configuration"
/// mode. Each enabled capability runs concurrently until it exits.
async fn run_multi(rest: Vec<String>) -> ExitCode {
    let cp = flag(&rest, "--control-plane");
    let token = flag(&rest, "--report-token");
    let ledger = flag(&rest, "--ledger");
    let mut set: tokio::task::JoinSet<ExitCode> = tokio::task::JoinSet::new();

    // Firewall (content firewall + forward proxy)
    if let Some(addr) = flag(&rest, "--firewall") {
        let mut a = vec!["--listen".to_string(), addr];
        if let Some(t) = &token { a.push("--report-token".into()); a.push(t.clone()); }
        if let Some(l) = &ledger { a.push("--ledger".into()); a.push(format!("{l}.firewall")); }
        let mut full = vec!["acp-agent-firewall".to_string()];
        full.extend(expand_cp(a, &cp, &["--registry-url", "--firewall-url", "--report-url"]));
        eprintln!("acp-agent: firewall capability enabled");
        set.spawn(crate::intercept::agent::run(full));
    }
    // Guard (tool-server sidecar)
    if let Some(addr) = flag(&rest, "--guard") {
        let up = flag(&rest, "--guard-upstream").unwrap_or_default();
        let mut a = vec!["--listen".to_string(), addr, "--upstream".to_string(), up];
        if let Some(pk) = flag(&rest, "--guard-pubkey") { a.push("--pubkey".into()); a.push(pk); }
        if let Some(l) = &ledger { a.push("--ledger".into()); a.push(format!("{l}.guard")); }
        if let Some(t) = &token { a.push("--report-token".into()); a.push(t.clone()); }
        let mut full = vec!["acp-agent-guard".to_string()];
        full.extend(expand_cp(a, &cp, &["--report-url"]));
        eprintln!("acp-agent: guard capability enabled");
        set.spawn(crate::guard::agent::run(full));
    }
    // MCP proxy over HTTP (stdio mode is launched per-session by the agent host, not here)
    if let Some(addr) = flag(&rest, "--mcp") {
        let up = flag(&rest, "--mcp-upstream").unwrap_or_default();
        let mut a = vec!["http".to_string(), "--addr".to_string(), addr, "--upstream".to_string(), up];
        if let Some(t) = &token { a.push("--report-token".into()); a.push(t.clone()); }
        let mut full = vec!["acp-agent-mcp".to_string()];
        full.extend(expand_cp(a, &cp, &["--registry-url", "--firewall-url", "--report-url", "--evidence-url", "--approvals-url", "--policy-url"]));
        eprintln!("acp-agent: mcp (http) capability enabled");
        set.spawn(crate::proxy::agent::run(full));
    }

    if set.is_empty() {
        eprintln!("acp-agent run: enable at least one capability, e.g. --firewall <addr> and/or --guard <addr> --guard-upstream <url> and/or --mcp <addr> --mcp-upstream <url>, with --control-plane <url>.");
        return ExitCode::from(2);
    }
    // Run until the first capability exits; a capability exiting is a fault worth surfacing.
    match set.join_next().await {
        Some(Ok(code)) => code,
        _ => ExitCode::from(1),
    }
}

/// Append the control-plane URL flags to a capability's args (only where not already present).
fn expand_cp(mut args: Vec<String>, cp: &Option<String>, url_flags: &[&str]) -> Vec<String> {
    if let Some(url) = cp {
        for f in url_flags {
            if !args.iter().any(|a| a == f) {
                args.push((*f).to_string());
                args.push(url.clone());
            }
        }
    }
    args
}

/// Expand `--control-plane <url>` into the capability's control-plane URL flags. Flags are added only
/// where the operator did not pass them explicitly, and always BEFORE any `--` (tool-server command).
fn expand(rest: Vec<String>, url_flags: &[&str]) -> Vec<String> {
    let split = rest.iter().position(|a| a == "--").unwrap_or(rest.len());
    let head = &rest[..split];
    let tail = &rest[split..];
    let mut cp: Option<String> = None;
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < head.len() {
        if head[i] == "--control-plane" && i + 1 < head.len() {
            cp = Some(head[i + 1].clone());
            i += 2;
            continue;
        }
        out.push(head[i].clone());
        i += 1;
    }
    if let Some(url) = cp {
        for f in url_flags {
            if !out.iter().any(|a| a == f) {
                out.push((*f).to_string());
                out.push(url.clone());
            }
        }
    }
    out.extend(tail.iter().cloned());
    out
}

async fn dispatch(prog: &str, args: Vec<String>, cap: Cap) -> ExitCode {
    let mut full = vec![prog.to_string()];
    full.extend(args);
    match cap {
        Cap::Firewall => crate::intercept::agent::run(full).await,
        Cap::Mcp => crate::proxy::agent::run(full).await,
        Cap::Guard => crate::guard::agent::run(full).await,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let rest: Vec<String> = argv.iter().skip(2).cloned().collect();
    match argv.get(1).map(String::as_str) {
        Some("firewall") => {
            let args = expand(rest, &["--registry-url", "--firewall-url", "--report-url"]);
            dispatch("acp-agent-firewall", args, Cap::Firewall).await
        }
        Some("mcp") => {
            let args = expand(rest, &["--registry-url", "--firewall-url", "--report-url", "--evidence-url", "--approvals-url", "--policy-url"]);
            dispatch("acp-agent-mcp", args, Cap::Mcp).await
        }
        Some("guard") => {
            let args = expand(rest, &["--report-url"]);
            dispatch("acp-agent-guard", args, Cap::Guard).await
        }
        Some("run") => run_multi(rest).await,
        _ => {
            eprintln!("acp-agent: one workstation service; the capability is configuration.");
            eprintln!("usage:");
            eprintln!("  acp-agent firewall --listen <addr> --control-plane <url> [opts]");
            eprintln!("  acp-agent mcp stdio --control-plane <url> [opts] -- <tool-server-cmd>");
            eprintln!("  acp-agent guard --listen <addr> --upstream <url> --control-plane <url>");
            eprintln!("  acp-agent run --control-plane <url> --firewall <addr> [--guard <addr> --guard-upstream <url> --guard-pubkey <hex>] [--mcp <addr> --mcp-upstream <url>]   # multiple capabilities at once");
            ExitCode::from(2)
        }
    }
}
