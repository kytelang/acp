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

use std::process::ExitCode;

enum Cap { Firewall, Mcp, Guard }

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
        Cap::Firewall => acp_intercept::agent::run(full).await,
        Cap::Mcp => acp_proxy::agent::run(full).await,
        Cap::Guard => acp_guard::agent::run(full).await,
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
            let args = expand(rest, &["--registry-url", "--firewall-url", "--report-url", "--evidence-url", "--approvals-url"]);
            dispatch("acp-agent-mcp", args, Cap::Mcp).await
        }
        Some("guard") => {
            let args = expand(rest, &["--report-url"]);
            dispatch("acp-agent-guard", args, Cap::Guard).await
        }
        _ => {
            eprintln!("acp-agent: one workstation service; the capability is configuration.");
            eprintln!("usage:");
            eprintln!("  acp-agent firewall --listen <addr> --control-plane <url> [opts]");
            eprintln!("  acp-agent mcp stdio --control-plane <url> [opts] -- <tool-server-cmd>");
            eprintln!("  acp-agent guard --listen <addr> --upstream <url> --control-plane <url>");
            ExitCode::from(2)
        }
    }
}
