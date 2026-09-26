//! acp-proxy: sits between an MCP client and the tool server(s), gates every `tools/call`, and
//! streams a signed evidence record for each decision.
//!
//!   acp-proxy stdio [opts] -- <mcp-server-cmd> [args...]
//!   acp-proxy http  [opts] --addr <ip:port> --upstream <url>
//!
//! opts: --policy <file> --ledger <file> --key <file> --approvals <file> --env <name> --shadow


use acp_policy::PolicyEngine;
use crate::dispatch::Controller;
use crate::{events, evidence, http, stdio};
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
    registry_url: Option<String>,
    agent_id: Option<String>,
    agent_token: Option<String>,
    principal: Option<String>,
    break_glass_key: Option<String>,
    tool_pins: Option<String>,
    enforcement_key: Option<String>,
    entra_tenant: Option<String>,
    entra_audience: Option<String>,
    content_firewall: bool,
    block_secrets: bool,
    deny_topics: Vec<String>,
    content_ml: Option<String>,
    pin_pg: Option<String>,
    trajectory: Option<String>,
    data_boundary: Option<String>,
    report_url: Option<String>,
    report_token: Option<String>,
    proxy_id: Option<String>,
    approvals_url: Option<String>,
    evidence_url: Option<String>,
    firewall_url: Option<String>,
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
            "--registry-url" => o.registry_url = it.next().cloned(),
            "--agent-id" => o.agent_id = it.next().cloned(),
            "--agent-token" => o.agent_token = it.next().cloned(),
            "--principal" => o.principal = it.next().cloned(),
            "--shadow" => o.shadow = true,
            "--fail-open" => o.fail_open = true,
            "--content-firewall" => o.content_firewall = true,
            "--block-secrets" => { o.content_firewall = true; o.block_secrets = true; }
            "--deny-topic" => { o.content_firewall = true; if let Some(v) = it.next() { o.deny_topics.push(v.clone()); } }
            "--content-ml" => { o.content_firewall = true; o.content_ml = it.next().cloned(); }
            "--pin-pg" => o.pin_pg = it.next().cloned(),
            "--trajectory" => o.trajectory = it.next().cloned(),
            "--data-boundary" => o.data_boundary = it.next().cloned(),
            "--report-url" => o.report_url = it.next().cloned(),
            "--report-token" => o.report_token = it.next().cloned(),
            "--proxy-id" => o.proxy_id = it.next().cloned(),
            "--approvals-url" => o.approvals_url = it.next().cloned(),
            "--evidence-url" => o.evidence_url = it.next().cloned(),
            "--firewall-url" => o.firewall_url = it.next().cloned(),
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

/// Stable id for this PEP in control-plane reports (heartbeats, events). Operator-set via
/// --proxy-id, else the agent id, else a generic default.
fn proxy_id(o: &Opts) -> String {
    o.proxy_id.clone().or_else(|| o.agent_id.clone()).unwrap_or_else(|| "proxy".to_string())
}

async fn build_controller(o: &Opts) -> Result<Arc<Controller>, String> {
    let engine = if let Some(dir) = &o.policy_dir {
        let eng = acp_policy::store::load_current(dir)
            .map_err(|e| format!("cannot load current policy from {dir}: {e}"))?;
        tracing::info!("signed policy loaded from {dir} ({}...)", &eng.hash()[..12.min(eng.hash().len())]);
        Some(Arc::new(eng))
    } else {
        match &o.policy {
        Some(p) => {
            let src =
                std::fs::read_to_string(p).map_err(|e| format!("cannot read policy {p}: {e}"))?;
            let eng =
                PolicyEngine::from_yaml(&src).map_err(|e| format!("invalid policy {p}: {e}"))?;
            tracing::info!(
                "policy loaded ({}...)",
                &eng.hash()[..12.min(eng.hash().len())]
            );
            Some(Arc::new(eng))
        }
        None => None,
        }
    };
    let approvals_default = o.ledger.as_ref().map(|l| format!("{l}.approvals"));
    let ev_reporter = o.evidence_url.as_ref().map(|u| events::EvidenceReporter::new(u.clone(), proxy_id(o), o.report_token.clone()));
    let evidence = match &o.ledger {
        Some(lp) => {
            let kp = o.key.clone().unwrap_or_else(|| format!("{lp}.key"));
            let ev = evidence::Evidence::open_with_reporter(lp, &kp, ev_reporter)?;
            tracing::info!("evidence ledger {lp} ({} records)", ev.size());
            Some(ev)
        }
        None => None,
    };
    let approvals = match o.approvals.clone().or(approvals_default) {
        Some(ap) => {
            let s = acp_approvals::ApprovalStore::open(&ap)?;
            tracing::info!("approvals store {ap}");
            Some(s)
        }
        None => None,
    };
    let mut sinks: Vec<Box<dyn events::Sink>> = Vec::new();
    if let Some(ep) = &o.events {
        sinks.push(Box::new(
            events::FileSink::open(ep).map_err(|e| format!("cannot open events {ep}: {e}"))?,
        ));
        tracing::info!("governance events -> {ep}");
    }
    if let Some(url) = &o.otel {
        sinks.push(Box::new(events::OtelSink::new(url.clone())));
        tracing::info!("OTLP governance events -> {url}");
    }
    if let Some(base) = &o.report_url {
        let pid = proxy_id(o);
        sinks.push(Box::new(events::ServerSink::new(base.clone(), pid.clone(), o.report_token.clone())));
        tracing::info!("reporting violations to control plane -> {base} (proxy {pid})");
    }
    if let Some(cp) = &o.cef {
        sinks.push(Box::new(
            events::CefSink::open(cp).map_err(|e| format!("cannot open cef {cp}: {e}"))?,
        ));
        tracing::info!("CEF governance events -> {cp}");
    }
    if let Some(target) = &o.syslog {
        sinks.push(Box::new(
            events::SyslogSink::open(target).map_err(|e| format!("cannot open syslog {target}: {e}"))?,
        ));
        tracing::info!("CEF governance events -> syslog {target}");
    }
    if let Some(op) = &o.ocsf {
        sinks.push(Box::new(
            events::OcsfSink::open(op).map_err(|e| format!("cannot open ocsf {op}: {e}"))?,
        ));
        tracing::info!("OCSF governance events -> {op}");
    }
    let impact_tax = match &o.impact {
        Some(ip) => {
            let src = std::fs::read_to_string(ip)
                .map_err(|e| format!("cannot read impact taxonomy {ip}: {e}"))?;
            let tax = acp_core::impact::ImpactTaxonomy::from_yaml(&src)
                .map_err(|e| format!("invalid impact taxonomy {ip}: {e}"))?;
            tracing::info!("impact taxonomy {} loaded", tax.version);
            tax
        }
        None => acp_core::impact::ImpactTaxonomy::default(),
    };
    let env = o.env.clone().unwrap_or_else(|| "prod".to_string());
    if o.shadow {
        tracing::info!("SHADOW MODE (recording would-blocks, enforcing nothing)");
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
        tracing::info!("watching break-glass grant file {bg}");
    }
    if let Some(k) = &o.break_glass_key {
        match hex::decode(acp_core::secret::resolve(k)) {
            Ok(pk) => {
                controller.set_break_glass_key(pk);
                tracing::error!("break-glass grants must be signed by the pinned key");
            }
            Err(_) => return Err("--break-glass-key must be hex".to_string()),
        }
    }
    if let Some(dir) = &o.policy_dir {
        controller.set_policy_dir(dir.clone());
        tracing::info!("hot-reloading signed policies from {dir}");
    }
    if let Some(pins) = &o.tool_pins {
        controller.set_tool_pins_file(pins.clone());
        tracing::info!("tool-integrity pins persisted at {pins}");
    }
    if let Some(k) = &o.enforcement_key {
        match hex::decode(acp_core::secret::resolve(k)) {
            Ok(b) if b.len() == 32 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&b);
                let pubkey = acp_core::sign::Ed25519Signer::from_seed(&seed);
                use acp_core::sign::Signer;
                tracing::info!(
                    "stamping enforcement attestations; guard tool servers with pubkey {}",
                    hex::encode(pubkey.public_key())
                );
                controller.set_enforcement_key(seed);
            }
            _ => return Err("--enforcement-key must be a 32-byte hex seed".to_string()),
        }
    }
    if o.fail_open {
        tracing::warn!("WARNING --fail-open is set: on an evidence-write failure the proxy FORWARDS ungoverned. This weakens the fail-closed guarantee; use only for controlled testing.");
    }
    if o.content_firewall {
        controller.set_content_policy(acp_core::content::ContentPolicy {
            block_injection: true,
            block_secrets: o.block_secrets,
            redact_pii: true,
            denied_topics: o.deny_topics.clone(),
        });
        tracing::info!("first-party content firewall enabled over tool-call arguments");
    }
    if let Some(mlp) = o.content_ml.as_ref() {
        match std::fs::read_to_string(mlp).ok().and_then(|s| acp_core::content::LinearScorer::from_json(&s).ok()) {
            Some(s) => { controller.set_content_ml(std::sync::Arc::new(s)); tracing::info!("ML content detector loaded from {mlp}"); }
            None => return Err(format!("cannot load --content-ml model {mlp}")),
        }
    }
    if let Some(conn) = o.pin_pg.as_ref() {
        match acp_pgstate::PgState::connect(conn).await {
            Ok(pg) => { controller.set_pin_pg(pg).await; tracing::info!("shared tool pins via Postgres ({conn})"); }
            Err(e) => return Err(format!("cannot connect --pin-pg: {e}")),
        }
    }
    if let Some(tp) = o.trajectory.as_ref() {
        let src = std::fs::read_to_string(tp).map_err(|e| format!("cannot read --trajectory {tp}: {e}"))?;
        let policy: acp_core::trajectory::TrajectoryPolicy = serde_yaml::from_str(&src).map_err(|e| format!("invalid trajectory policy: {e}"))?;
        controller.set_trajectory_policy(policy);
        tracing::info!("intent/trajectory governance enabled from {tp}");
    }
    if let Some(dp) = o.data_boundary.as_ref() {
        let src = std::fs::read_to_string(dp).map_err(|e| format!("cannot read --data-boundary {dp}: {e}"))?;
        let policy: acp_core::databoundary::DataBoundaryPolicy = serde_yaml::from_str(&src).map_err(|e| format!("invalid data-boundary policy: {e}"))?;
        controller.set_data_boundary(policy);
        tracing::info!("data-boundary enforcement enabled from {dp}");
    }
    // Verified caller identity: when a registry is configured, the presented (agent-id, token) MUST
    // verify. Fail closed on a missing/invalid/revoked credential so a mis-enrolled agent cannot run
    // un-governed. Without a registry the proxy runs unidentified (agent/app rules simply do not match).
    // The human principal is bound at enrolment via --principal (the launching user for local
    // agents; the OAuth-token subject for remote agents once wired). It is proxy-supplied and
    // trusted, never asserted by the agent. Absent -> "unattributed" so the gap is governable.
    let principal = o.principal.clone().unwrap_or_else(|| "unattributed".to_string());
    if let Some(base) = &o.registry_url {
        // Verify against the control-plane database (DB-registered agents, no registry file).
        let (aid, tok) = match (&o.agent_id, &o.agent_token) {
            (Some(a), Some(t)) => (a.clone(), t.clone()),
            _ => return Err("--registry-url requires --agent-id and --agent-token".to_string()),
        };
        let base = base.trim_end_matches('/');
        let resp = reqwest::Client::new()
            .post(format!("{base}/agents/verify"))
            .json(&serde_json::json!({"id": aid, "token": tok}))
            .send()
            .await
            .map_err(|e| format!("control-plane verify request failed: {e}"))?;
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        if v["verified"].as_bool().unwrap_or(false) {
            let app = v["app"].as_str().unwrap_or("").to_string();
            let agent = v["agent"].as_str().unwrap_or("").to_string();
            tracing::info!("verified identity via control plane agent={agent} app={app} principal={principal}");
            controller.set_identity(app, agent, principal);
        } else {
            return Err(format!("agent {aid} failed control-plane verification (unknown, revoked, or bad token)"));
        }
    } else if let Some(reg_path) = &o.registry {
        let reg = acp_registry::Registry::load(reg_path)
            .map_err(|e| format!("cannot load registry {reg_path}: {e}"))?;
        let (aid, tok) = match (&o.agent_id, &o.agent_token) {
            (Some(a), Some(t)) => (a.clone(), t.clone()),
            _ => return Err("--registry requires --agent-id and --agent-token".to_string()),
        };
        match reg.verify(&aid, &tok) {
            Some(id) => {
                tracing::info!(
                    "verified identity app={} ({}) agent={} ({}) principal={}",
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

pub async fn run(args: Vec<String>) -> ExitCode {
    acp_obs::init("acp-proxy");
    let sub = args.get(1).map(String::as_str);
    let rest = if args.len() > 2 { &args[2..] } else { &[] };

    let (opts, cmd) = match sub {
        Some("stdio") | Some("http") => match parse_opts(rest) {
            Ok(v) => v,
            Err(e) => {
                tracing::info!("{e}");
                return ExitCode::from(2);
            }
        },
        _ => {
            tracing::info!("usage: acp-proxy stdio [opts] -- <cmd> | acp-proxy http [opts] --addr <ip:port> --upstream <url>");
            return ExitCode::SUCCESS;
        }
    };

    // A11: transparent (no-policy) mode passes tool calls through by design, so we do not refuse to
    // start, but we make it impossible to run ungoverned unknowingly: a prominent warning when no
    // policy is configured. Any real governance deployment sets --policy or --policy-dir.
    if opts.policy.is_none() && opts.policy_dir.is_none() {
        tracing::warn!("NO POLICY configured (--policy / --policy-dir): running in TRANSPARENT mode; tool calls are forwarded ungoverned. Configure a policy for enforcement.");
    }

    let controller = match build_controller(&opts).await {
        Ok(c) => c,
        Err(e) => {
            tracing::info!("{e}");
            return ExitCode::from(1);
        }
    };

    // Liveness reporting (gap E1): a periodic heartbeat to the control plane so the console can show
    // this PEP as alive and its dead-man's-switch fires if it goes silent.
    if let Some(base) = opts.report_url.clone() {
        let pid = proxy_id(&opts);
        let token = opts.report_token.clone();
        let base = base.trim_end_matches('/').to_string();
        tracing::info!("heartbeat -> {base} every 10s (proxy {pid})");
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                let url = format!("{base}/heartbeat/{pid}");
                let mut req = client.post(&url);
                if let Some(t) = &token { req = req.bearer_auth(t); }
                let _ = req.send().await;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }

    // F1: field step-up approvals. Register new holds with the control plane (console inbox sees
    // them) and reconcile the operator's decision back into the local store so the agent's re-issue
    // is released or blocked. The sync decide path is untouched.
    if let Some(aurl) = opts.approvals_url.clone() {
        let base = aurl.trim_end_matches('/').to_string();
        controller.set_approvals_reporter(events::ApprovalReporter::new(base.clone(), opts.report_token.clone()));
        let apath = opts.approvals.clone().or_else(|| opts.ledger.as_ref().map(|l| format!("{l}.approvals")));
        if let Some(path) = apath {
            let token = opts.report_token.clone();
            tracing::info!("approval reconcile -> {base} (store {path})");
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let store = match acp_approvals::ApprovalStore::open(&path) { Ok(s) => s, Err(_) => continue };
                    let pending = match store.list_pending() { Ok(p) => p, Err(_) => continue };
                    for v in pending {
                        let url = format!("{base}/approvals/{}/status", v.id);
                        let mut req = client.get(&url);
                        if let Some(t) = &token { req = req.bearer_auth(t); }
                        let state = match req.send().await { Ok(r) => r.json::<serde_json::Value>().await.ok(), Err(_) => None };
                        let stt = state.as_ref().and_then(|j| j.get("state")).and_then(|x| x.as_str()).unwrap_or("");
                        let approver = state.as_ref().and_then(|j| j.get("approver")).and_then(|x| x.as_str()).unwrap_or("console");
                        if stt == "approved" { let _ = store.resolve(&v.id, true, approver, "console"); }
                        else if stt == "denied" { let _ = store.resolve(&v.id, false, approver, "console"); }
                    }
                }
            });
        }
    }

    // Central content-firewall config from the control plane (toggles + denied topics + ML model), so
    // this workstation proxy needs no local model file. Fetched at startup and refreshed at runtime.
    if let Some(base) = opts.firewall_url.clone() {
        let base = base.trim_end_matches('/').to_string();
        async fn fetch_fw(client: &reqwest::Client, base: &str) -> Option<(acp_core::content::ContentPolicy, Option<std::sync::Arc<acp_core::content::LinearScorer>>)> {
            let v: serde_json::Value = client.get(format!("{base}/firewall/config")).send().await.ok()?.json().await.ok()?;
            let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
            let block_secrets = enabled && v.get("block_secrets").and_then(|x| x.as_bool()).unwrap_or(false);
            let denied_topics: Vec<String> = v.get("deny_topics").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            let pol = acp_core::content::ContentPolicy { block_injection: enabled, block_secrets, redact_pii: enabled, denied_topics };
            let model = v.get("model").and_then(|x| x.as_str()).unwrap_or("");
            let ml = if enabled && !model.is_empty() { acp_core::content::LinearScorer::from_json(model).ok().map(std::sync::Arc::new) } else { None };
            Some((pol, ml))
        }
        let client = reqwest::Client::new();
        if let Some((pol, ml)) = fetch_fw(&client, &base).await {
            controller.set_content_policy(pol);
            if let Some(m) = ml { controller.set_content_ml(m); }
            tracing::info!("content firewall config fetched from {base}");
        } else {
            tracing::warn!("content firewall fetch from {base} failed; using local flags");
        }
        let c2 = controller.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                if let Some((pol, ml)) = fetch_fw(&client, &base).await {
                    c2.set_content_policy(pol);
                    if let Some(m) = ml { c2.set_content_ml(m); }
                }
            }
        });
    }

    // Per-request human identity (phase B): verify each request's bearer against the org IdP and
    // stamp the resulting human principal onto governed calls.
    if let (Some(tid), Some(aud)) = (&opts.entra_tenant, &opts.entra_audience) {
        let issuer = format!("https://login.microsoftonline.com/{tid}/v2.0");
        let jwks_url = format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys");
        match load_jwks(&jwks_url).await {
            Ok(jwks) => {
                controller.set_oidc(jwks, acp_auth::EntraConfig { issuer: issuer.clone(), audience: aud.clone() });
                tracing::info!("per-request human identity enabled (issuer {issuer})");
            }
            Err(e) => {
                tracing::error!("could not load JWKS ({e}); refusing to start (identity was requested, failing closed)");
                return ExitCode::from(1);
            }
        }
    }

    match sub {
        Some("stdio") => {
            if cmd.is_empty() {
                tracing::info!("usage: acp-proxy stdio [opts] -- <mcp-server-cmd> [args...]");
                return ExitCode::from(2);
            }
            // B5/D10: verify the tool-server binary's fingerprint before launching it.
            if let Some(expected) = &opts.tool_hash {
                match std::fs::read(&cmd[0]) {
                    Ok(bytes) => {
                        let got = acp_core::canonical::sha256_hex_bytes(&bytes);
                        if &got != expected {
                            tracing::error!("tool binary {} fingerprint {} != expected {}; refusing to launch", cmd[0], &got[..16], &expected[..16.min(expected.len())]);
                            return ExitCode::from(1);
                        }
                        tracing::info!("tool binary verified ({}...)", &got[..16]);
                    }
                    Err(e) => {
                        tracing::error!(
                            "cannot read tool binary {} for verification: {e}",
                            cmd[0]
                        );
                        return ExitCode::from(1);
                    }
                }
            }
            match stdio::run(&cmd[0], &cmd[1..], controller).await {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    tracing::info!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("http") => {
            let (addr, upstream) = match (opts.addr.clone(), opts.upstream.clone()) {
                (Some(a), Some(u)) => (a, u),
                _ => {
                    tracing::info!("usage: acp-proxy http [opts] --addr <ip:port> --upstream <url>");
                    return ExitCode::from(2);
                }
            };
            match http::run(&addr, upstream, controller).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::info!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => ExitCode::SUCCESS,
    }
}
