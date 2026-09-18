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
    syslog: Option<String>,
    break_glass: Option<String>,
    policy_dir: Option<String>,
    registry: Option<String>,
    agent_id: Option<String>,
    agent_token: Option<String>,
    principal: Option<String>,
    break_glass_key: Option<String>,
    tool_pins: Option<String>,
    enforcement_key: Option<String>,
    entra_tenant: Option<String>,
    entra_audience: Option<String>,
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
            "--syslog" => o.syslog = it.next().cloned(),
            "--break-glass-file" => o.break_glass = it.next().cloned(),
            "--break-glass-key" => o.break_glass_key = it.next().cloned(),
            "--tool-pins" => o.tool_pins = it.next().cloned(),
            "--enforcement-key" => o.enforcement_key = it.next().cloned(),
            "--entra-tenant" => o.entra_tenant = it.next().cloned(),
            "--entra-audience" => o.entra_audience = it.next().cloned(),
            "--policy-dir" => o.policy_dir = it.next().cloned(),
            "--registry" => o.registry = it.next().cloned(),
            "--agent-id" => o.agent_id = it.next().cloned(),
            "--agent-token" => o.agent_token = it.next().cloned(),
            "--principal" => o.principal = it.next().cloned(),
            "--shadow" => o.shadow = true,
            "--fail-open" => o.fail_open = true,
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok((o, cmd))
}

async fn load_jwks(source: &str) -> Result<acp_auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
}

fn build_controller(o: &Opts) -> Result<Arc<Controller>, String> {
    let engine = if let Some(dir) = &o.policy_dir {
        let eng = acp_policy::store::load_current(dir)
            .map_err(|e| format!("cannot load current policy from {dir}: {e}"))?;
        eprintln!("acp-proxy: signed policy loaded from {dir} ({}...)", &eng.hash()[..12.min(eng.hash().len())]);
        Some(Arc::new(eng))
    } else {
        match &o.policy {
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
        }
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
    if let Some(target) = &o.syslog {
        sinks.push(Box::new(
            events::SyslogSink::open(target).map_err(|e| format!("cannot open syslog {target}: {e}"))?,
        ));
        eprintln!("acp-proxy: CEF governance events -> syslog {target}");
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
    if let Some(k) = &o.break_glass_key {
        match hex::decode(k) {
            Ok(pk) => {
                controller.set_break_glass_key(pk);
                eprintln!("acp-proxy: break-glass grants must be signed by the pinned key");
            }
            Err(_) => return Err("--break-glass-key must be hex".to_string()),
        }
    }
    if let Some(dir) = &o.policy_dir {
        controller.set_policy_dir(dir.clone());
        eprintln!("acp-proxy: hot-reloading signed policies from {dir}");
    }
    if let Some(pins) = &o.tool_pins {
        controller.set_tool_pins_file(pins.clone());
        eprintln!("acp-proxy: tool-integrity pins persisted at {pins}");
    }
    if let Some(k) = &o.enforcement_key {
        match hex::decode(k) {
            Ok(b) if b.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&b);
                let pubkey = acp_core::sign::Ed25519Signer::from_seed(&seed);
                use acp_core::sign::Signer;
                eprintln!(
                    "acp-proxy: stamping enforcement attestations; guard tool servers with pubkey {}",
                    hex::encode(pubkey.public_key())
                );
                controller.set_enforcement_key(seed);
            }
            _ => return Err("--enforcement-key must be a 32-byte hex seed".to_string()),
        }
    }
    if o.fail_open {
        eprintln!("acp-proxy: WARNING --fail-open is set: on an evidence-write failure the proxy FORWARDS ungoverned. This weakens the fail-closed guarantee; use only for controlled testing.");
    }
    // Verified caller identity: when a registry is configured, the presented (agent-id, token) MUST
    // verify. Fail closed on a missing/invalid/revoked credential so a mis-enrolled agent cannot run
    // un-governed. Without a registry the proxy runs unidentified (agent/app rules simply do not match).
    // The human principal is bound at enrolment via --principal (the launching user for local
    // agents; the OAuth-token subject for remote agents once wired). It is proxy-supplied and
    // trusted, never asserted by the agent. Absent -> "unattributed" so the gap is governable.
    let principal = o.principal.clone().unwrap_or_else(|| "unattributed".to_string());
    if let Some(reg_path) = &o.registry {
        let reg = acp_registry::Registry::load(reg_path)
            .map_err(|e| format!("cannot load registry {reg_path}: {e}"))?;
        let (aid, tok) = match (&o.agent_id, &o.agent_token) {
            (Some(a), Some(t)) => (a.clone(), t.clone()),
            _ => return Err("--registry requires --agent-id and --agent-token".to_string()),
        };
        match reg.verify(&aid, &tok) {
            Some(id) => {
                eprintln!(
                    "acp-proxy: verified identity app={} ({}) agent={} ({}) principal={}",
                    id.app_name, id.app_id, id.agent_name, id.agent_id, principal
                );
                // Policy rules reference the human names; evidence-friendly ids remain in the registry.
                controller.set_identity(id.app_name, id.agent_name, principal);
            }
            None => return Err(format!("agent {aid} failed registry verification (unknown, revoked, or bad token)")),
        }
    } else if o.principal.is_some() {
        // No registry, but a principal was declared: still stamp it (agent/app stay empty).
        controller.set_identity(String::new(), String::new(), principal);
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

    // Per-request human identity (phase B): verify each request's bearer against the org IdP and
    // stamp the resulting human principal onto governed calls.
    if let (Some(tid), Some(aud)) = (&opts.entra_tenant, &opts.entra_audience) {
        let issuer = format!("https://login.microsoftonline.com/{tid}/v2.0");
        let jwks_url = format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys");
        match load_jwks(&jwks_url).await {
            Ok(jwks) => {
                controller.set_oidc(jwks, acp_auth::EntraConfig { issuer: issuer.clone(), audience: aud.clone() });
                eprintln!("acp-proxy: per-request human identity enabled (issuer {issuer})");
            }
            Err(e) => eprintln!("acp-proxy: could not load JWKS ({e}); human principal stays as configured"),
        }
    }

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
