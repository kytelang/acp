//! acp-proxy: sits between an MCP client and the tool server(s), gates every `tools/call`, and
//! streams a signed evidence record for each decision.
//!
//!   acp-proxy stdio [opts] -- <mcp-server-cmd> [args...]
//!   acp-proxy http  [opts] --addr <ip:port> --upstream <url>
//!
//! opts: --policy <file> --ledger <file> --key <file> --approvals <file> --env <name> --shadow

mod approvals;
mod dispatch;
mod events;
mod evidence;
mod http;
mod intercept;
mod limits;
mod policy;
mod stdio;

use acp_policy::PolicyEngine;
use dispatch::Controller;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Default)]
struct Opts {
    policy: Option<String>,
    ledger: Option<String>,
    key: Option<String>,
    approvals: Option<String>,
    env: Option<String>,
    shadow: bool,
    fail_open: bool,
    addr: Option<String>,
    upstream: Option<String>,
    events: Option<String>,
    otel: Option<String>,
    tool_hash: Option<String>,
    impact: Option<String>,
    cef: Option<String>,
    ocsf: Option<String>,
    break_glass: Option<String>,
}

fn parse_opts(items: &[String]) -> Result<(Opts, Vec<String>), String> {
    let mut o = Opts::default();
    let mut it = items.iter();
    let mut cmd = Vec::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--" => {
                cmd = it.cloned().collect();
                break;
            }
            "--policy" => o.policy = it.next().cloned(),
            "--ledger" => o.ledger = it.next().cloned(),
            "--key" => o.key = it.next().cloned(),
            "--approvals" => o.approvals = it.next().cloned(),
            "--env" => o.env = it.next().cloned(),
            "--addr" => o.addr = it.next().cloned(),
            "--upstream" => o.upstream = it.next().cloned(),
            "--events" => o.events = it.next().cloned(),
            "--otel" => o.otel = it.next().cloned(),
            "--tool-hash" => o.tool_hash = it.next().cloned(),
            "--impact" => o.impact = it.next().cloned(),
            "--cef" => o.cef = it.next().cloned(),
            "--ocsf" => o.ocsf = it.next().cloned(),
            "--break-glass-file" => o.break_glass = it.next().cloned(),
            "--shadow" => o.shadow = true,
            "--fail-open" => o.fail_open = true,
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok((o, cmd))
}

fn build_controller(o: &Opts) -> Result<Arc<Controller>, String> {
    let engine = match &o.policy {
        Some(p) => {
            let src =
                std::fs::read_to_string(p).map_err(|e| format!("cannot read policy {p}: {e}"))?;
            let eng =
                PolicyEngine::from_yaml(&src).map_err(|e| format!("invalid policy {p}: {e}"))?;
            eprintln!(
                "acp-proxy: policy loaded ({}...)",
                &eng.hash()[..12.min(eng.hash().len())]
            );
            Some(Arc::new(eng))
        }
        None => None,
    };
    let approvals_default = o.ledger.as_ref().map(|l| format!("{l}.approvals"));
    let evidence = match &o.ledger {
        Some(lp) => {
            let kp = o.key.clone().unwrap_or_else(|| format!("{lp}.key"));
            let ev = evidence::Evidence::open(lp, &kp)?;
            eprintln!("acp-proxy: evidence ledger {lp} ({} records)", ev.size());
            Some(ev)
        }
        None => None,
    };
    let approvals = match o.approvals.clone().or(approvals_default) {
        Some(ap) => {
            let s = acp_approvals::ApprovalStore::open(&ap)?;
            eprintln!("acp-proxy: approvals store {ap}");
            Some(s)
        }
        None => None,
    };
    let mut sinks: Vec<Box<dyn events::Sink>> = Vec::new();
    if let Some(ep) = &o.events {
        sinks.push(Box::new(
            events::FileSink::open(ep).map_err(|e| format!("cannot open events {ep}: {e}"))?,
        ));
        eprintln!("acp-proxy: governance events -> {ep}");
    }
    if let Some(url) = &o.otel {
        sinks.push(Box::new(events::OtelSink::new(url.clone())));
        eprintln!("acp-proxy: OTLP governance events -> {url}");
    }
    if let Some(cp) = &o.cef {
        sinks.push(Box::new(
            events::CefSink::open(cp).map_err(|e| format!("cannot open cef {cp}: {e}"))?,
        ));
        eprintln!("acp-proxy: CEF governance events -> {cp}");
    }
    if let Some(op) = &o.ocsf {
        sinks.push(Box::new(
            events::OcsfSink::open(op).map_err(|e| format!("cannot open ocsf {op}: {e}"))?,
        ));
        eprintln!("acp-proxy: OCSF governance events -> {op}");
    }
    let impact_tax = match &o.impact {
        Some(ip) => {
            let src = std::fs::read_to_string(ip)
                .map_err(|e| format!("cannot read impact taxonomy {ip}: {e}"))?;
            let tax = acp_core::impact::ImpactTaxonomy::from_yaml(&src)
                .map_err(|e| format!("invalid impact taxonomy {ip}: {e}"))?;
            eprintln!("acp-proxy: impact taxonomy {} loaded", tax.version);
            tax
        }
        None => acp_core::impact::ImpactTaxonomy::default(),
    };
    let env = o.env.clone().unwrap_or_else(|| "prod".to_string());
    if o.shadow {
        eprintln!("acp-proxy: SHADOW MODE (recording would-blocks, enforcing nothing)");
    }
    let controller = Arc::new(Controller::new(
        engine,
        env,
        o.shadow,
        evidence,
        approvals,
        sinks,
        o.fail_open,
        impact_tax,
    ));
    if let Some(bg) = &o.break_glass {
        controller.set_break_glass_file(bg.clone());
        eprintln!("acp-proxy: watching break-glass grant file {bg}");
    }
    Ok(controller)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str);
    let rest = if args.len() > 2 { &args[2..] } else { &[] };

    let (opts, cmd) = match sub {
        Some("stdio") | Some("http") => match parse_opts(rest) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("acp-proxy: {e}");
                return ExitCode::from(2);
            }
        },
        _ => {
            eprintln!("usage: acp-proxy stdio [opts] -- <cmd> | acp-proxy http [opts] --addr <ip:port> --upstream <url>");
            return ExitCode::SUCCESS;
        }
    };

    let controller = match build_controller(&opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("acp-proxy: {e}");
            return ExitCode::from(1);
        }
    };

    match sub {
        Some("stdio") => {
            if cmd.is_empty() {
                eprintln!("usage: acp-proxy stdio [opts] -- <mcp-server-cmd> [args...]");
                return ExitCode::from(2);
            }
            // B5/D10: verify the tool-server binary's fingerprint before launching it.
            if let Some(expected) = &opts.tool_hash {
                match std::fs::read(&cmd[0]) {
                    Ok(bytes) => {
                        let got = acp_core::canonical::sha256_hex_bytes(&bytes);
                        if &got != expected {
                            eprintln!("acp-proxy: tool binary {} fingerprint {} != expected {}; refusing to launch", cmd[0], &got[..16], &expected[..16.min(expected.len())]);
                            return ExitCode::from(1);
                        }
                        eprintln!("acp-proxy: tool binary verified ({}...)", &got[..16]);
                    }
                    Err(e) => {
                        eprintln!(
                            "acp-proxy: cannot read tool binary {} for verification: {e}",
                            cmd[0]
                        );
                        return ExitCode::from(1);
                    }
                }
            }
            match stdio::run(&cmd[0], &cmd[1..], controller).await {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    eprintln!("acp-proxy: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("http") => {
            let (addr, upstream) = match (opts.addr.clone(), opts.upstream.clone()) {
                (Some(a), Some(u)) => (a, u),
                _ => {
                    eprintln!("usage: acp-proxy http [opts] --addr <ip:port> --upstream <url>");
                    return ExitCode::from(2);
                }
            };
            match http::run(&addr, upstream, controller).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("acp-proxy: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => ExitCode::SUCCESS,
    }
}
