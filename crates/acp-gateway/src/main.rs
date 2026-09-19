//! acp-gateway: the LLM gateway PEP (phase C, C2). A reverse proxy in front of model APIs. Every
//! request is classified and evaluated by the shared policy engine before it may reach a model, and
//! the gateway holds the upstream model credential so a caller cannot bypass it (credential
//! brokering): the app authenticates to the gateway, the gateway authenticates to the model.

use acp_core::modelclass::ModelTaxonomy;
use acp_core::types::Verdict;
use acp_gateway::decide;
use acp_policy::PolicyEngine;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Json, Router,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct GwState {
    engine: PolicyEngine,
    tax: ModelTaxonomy,
    upstream: String,
    upstream_key: Option<String>,
    env: String,
    oidc: Option<(acp_auth::Jwks, acp_auth::EntraConfig)>,
    client: reqwest::Client,
    limiters: Mutex<HashMap<String, acp_core::ratelimit::TokenBucket>>,
    ledger: Option<Mutex<acp_ledger::Ledger>>,
    breakglass: Mutex<acp_core::breakglass::BreakGlassRegistry>,
    bg_file: Option<String>,
    bg_mtime: Mutex<Option<std::time::SystemTime>>,
    bg_key: Option<Vec<u8>>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8799".to_string();
    let (mut policy, mut upstream, mut upstream_key, mut env) = (None, None, None, "prod".to_string());
    let mut ledger_path: Option<String> = None;
    let mut bg_file: Option<String> = None;
    let mut bg_key_hex: Option<String> = None;
    let (mut entra_tenant, mut entra_audience): (Option<String>, Option<String>) = (None, None);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or(addr),
            "--policy" => policy = it.next().cloned(),
            "--upstream" => upstream = it.next().cloned(),
            "--upstream-key" => upstream_key = it.next().cloned(),
            "--ledger" => ledger_path = it.next().cloned(),
            "--break-glass-file" => bg_file = it.next().cloned(),
            "--break-glass-key" => bg_key_hex = it.next().cloned(),
            "--env" => env = it.next().cloned().unwrap_or(env),
            "--entra-tenant" => entra_tenant = it.next().cloned(),
            "--entra-audience" => entra_audience = it.next().cloned(),
            other => {
                eprintln!("acp-gateway: unknown option '{other}'");
                return std::process::ExitCode::from(2);
            }
        }
    }
    let engine = match policy.as_ref().map(|p| std::fs::read_to_string(p)) {
        Some(Ok(src)) => match PolicyEngine::from_yaml(&src) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("acp-gateway: bad policy: {e}");
                return std::process::ExitCode::from(1);
            }
        },
        _ => {
            eprintln!("acp-gateway: --policy <file> is required");
            return std::process::ExitCode::from(2);
        }
    };
    let upstream = match upstream {
        Some(u) => u,
        None => {
            eprintln!("acp-gateway: --upstream <base-url> is required");
            return std::process::ExitCode::from(2);
        }
    };
    let oidc = match (entra_tenant, entra_audience) {
        (Some(tid), Some(aud)) => {
            let url = format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys");
            match reqwest::get(&url).await.ok() {
                Some(r) => match r.text().await.ok().and_then(|s| acp_auth::Jwks::from_jwks_json(&s).ok()) {
                    Some(jwks) => {
                        eprintln!("acp-gateway: per-request human identity enabled");
                        Some((jwks, acp_auth::EntraConfig {
                            issuer: format!("https://login.microsoftonline.com/{tid}/v2.0"),
                            audience: aud,
                        }))
                    }
                    None => None,
                },
                None => None,
            }
        }
        _ => None,
    };
    let ledger = ledger_path.as_ref().and_then(|p| open_ledger(p));
    if ledger.is_some() {
        eprintln!("acp-gateway: recording decisions to the tamper-evident ledger");
    }
    let bg_key = bg_key_hex.as_ref().and_then(|h| hex::decode(h).ok());
    let st = Arc::new(GwState {
        engine,
        tax: ModelTaxonomy::default(),
        upstream,
        upstream_key,
        env,
        oidc,
        client: reqwest::Client::new(),
        limiters: Mutex::new(HashMap::new()),
        ledger: ledger.map(Mutex::new),
        breakglass: Mutex::new(acp_core::breakglass::BreakGlassRegistry::new()),
        bg_file,
        bg_mtime: Mutex::new(None),
        bg_key,
    });
    let upstream_log = st.upstream.clone();
    let app = Router::new().route("/*path", any(handle)).with_state(st);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("acp-gateway: bind {addr}: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    eprintln!("acp-gateway: governing model calls on http://{addr} -> {upstream_log}");
    let _ = axum::serve(listener, app).await;
    std::process::ExitCode::SUCCESS
}

/// Reload the break-glass grant file when it changes (mtime-cached); verify its signature against a
/// pinned key if configured; a forged/invalid grant is kept-current, an absent file clears.
fn refresh_break_glass(st: &GwState) {
    let path = match &st.bg_file { Some(p) => p.clone(), None => return };
    let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
    {
        let mut last = st.bg_mtime.lock().unwrap();
        if *last == mtime { return; }
        *last = mtime;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => { st.breakglass.lock().unwrap().replace_all(None); return; }
    };
    let gf = match serde_json::from_slice::<acp_core::breakglass::GrantFile>(&bytes) {
        Ok(g) => g,
        Err(_) => return,
    };
    if !gf.verify(st.bg_key.as_deref()) {
        eprintln!("acp-gateway: break-glass grant REJECTED (signature/pin); keeping current");
        return;
    }
    st.breakglass.lock().unwrap().replace_all(gf.to_break_glass());
}

/// Apply any active, scope-matching break-glass grant to the decision (e.g. a resource:frontier
/// lockdown freezes frontier model calls). Mutates the verdict in place.
fn apply_break_glass(st: &GwState, app: &str, model: &str, d: &mut acp_gateway::GatewayDecision) {
    refresh_break_glass(st);
    let eff = st.breakglass.lock().unwrap().effective(d.verdict, now_ms(), app, &d.resource, model);
    if eff != d.verdict {
        d.verdict = eff;
        d.rule_id = Some("break-glass".to_string());
        d.reason = Some("emergency control".to_string());
    }
}

fn open_ledger(path: &str) -> Option<acp_ledger::Ledger> {
    let key_path = format!("{path}.key");
    let signer: Box<dyn acp_core::sign::Signer + Send> = match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            Box::new(acp_core::sign::Ed25519Signer::from_seed(&s))
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = std::fs::write(&key_path, s.seed());
            Box::new(s)
        }
    };
    acp_ledger::Ledger::open(path, signer).ok()
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::StepUp => "step_up",
        Verdict::Shadow => "shadow",
    }
}

/// Record a governed model-call decision to the tamper-evident ledger (same shape as the MCP proxy,
/// surface = llm-gateway). Args are never recorded (no prompt in the ledger).
fn record_decision(st: &GwState, app: &str, principal: &str, model: &str, d: &acp_gateway::GatewayDecision) {
    let ledger = match &st.ledger {
        Some(l) => l,
        None => return,
    };
    let did = format!("gw-{}-{}", now_ms(), SEQ.fetch_add(1, Ordering::Relaxed));
    let verified = !principal.is_empty() && principal != "unattributed";
    let obs: Vec<String> = d.obligations.iter().map(|o| format!("{:?}", o.kind)).collect();
    let record = serde_json::json!({
        "schema": 1, "type": "decision", "ts_ms": now_ms(),
        "agent_id": app,
        "principal": {"id": principal, "verified": verified},
        "action": {"tool": model, "resource": d.resource, "operation": d.operation, "surface": "llm-gateway"},
        "decision": {"verdict": verdict_str(d.verdict), "rule_id": d.rule_id, "reason": d.reason, "obligations": obs},
    });
    if let Ok(mut l) = ledger.lock() {
        let _ = l.append(&did, "decision", &record, None);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn handle(
    State(st): State<Arc<GwState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The model is in the request body (OpenAI/Anthropic style). No model -> nothing to govern here.
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let model = parsed.get("model").and_then(|v| v.as_str()).unwrap_or("");

    // Subject: the calling app (an id header the caller cannot forge for policy is a future hardening;
    // for now an explicit header) and the verified human principal from the bearer.
    let app = headers.get("x-acp-app").and_then(|v| v.to_str().ok()).unwrap_or("unknown-app");
    let principal = resolve_principal(&st, &headers).unwrap_or_else(|| "unattributed".to_string());

    // A small, non-sensitive summary for policy matching. Never the prompt (that is a scan obligation).
    let argsum = json!({
        "model": model,
        "stream": parsed.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
        "max_tokens": parsed.get("max_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
    });

    let mut d = decide(&st.engine, &st.tax, model, app, &principal, &argsum, &st.env);
    apply_break_glass(&st, app, model, &mut d);
    record_decision(&st, app, &principal, model, &d);
    eprintln!(
        "acp-gateway: {} model={} class={} op={} app={} principal={} -> {:?}",
        path, model, d.resource, d.operation, app, principal, d.verdict
    );

    match d.verdict {
        Verdict::Deny => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": {"message": format!("blocked by ACP rule '{}': {}", d.rule_id.unwrap_or_default(), d.reason.unwrap_or_else(|| "policy".into())), "type": "acp_policy_denied"}})),
        )
            .into_response(),
        Verdict::StepUp => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"error": {"message": "human approval required (step-up) by ACP policy", "type": "acp_step_up"}})),
        )
            .into_response(),
        Verdict::Allow | Verdict::Shadow => {
            // Obligations (model v2, D4) on the gateway: a rate_limit acts as a per-(app, model-class)
            // token/cost budget and denies once spent; a confirm routes to step-up. Deny-overrides.
            use acp_policy::dsl::ObligationKind;
            let (mut over_budget, mut needs_confirm) = (false, false);
            for ob in &d.obligations {
                match ob.kind {
                    ObligationKind::Confirm => needs_confirm = true,
                    ObligationKind::RateLimit => {
                        let key = format!("{}|{}", app, d.resource);
                        let max = ob.max.unwrap_or(1_000_000);
                        let window = ob.window_ms.unwrap_or(86_400_000);
                        let ok = {
                            let mut lims = st.limiters.lock().unwrap();
                            let bucket = lims.entry(key).or_insert_with(|| {
                                let rate = (max as f64) * 1000.0 / (window as f64);
                                acp_core::ratelimit::TokenBucket::new(max as f64, rate, now_ms())
                            });
                            bucket.allow(now_ms())
                        };
                        if !ok {
                            over_budget = true;
                        }
                    }
                    ObligationKind::Redact => { /* prompt/response redaction is C3-scan, wired with the content plane */ }
                }
            }
            if over_budget {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error": {"message": "model budget exceeded for this app/model class", "type": "acp_budget_exceeded"}})),
                ).into_response();
            }
            if needs_confirm {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({"error": {"message": "human approval required (confirm obligation)", "type": "acp_step_up"}})),
                ).into_response();
            }
            forward(&st, &path, body).await
        }
    }
}

/// Verify the request bearer against the org IdP and return the human principal, if configured.
fn resolve_principal(st: &GwState, headers: &HeaderMap) -> Option<String> {
    let (jwks, cfg) = st.oidc.as_ref()?;
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;
    match acp_auth::verify(token, jwks, cfg, now_ms()) {
        Ok(p) => Some(if p.username.is_empty() { p.oid } else { p.username }),
        Err(_) => None,
    }
}

/// Forward the (allowed) call to the model provider, attaching the gateway's upstream credential so
/// the caller never holds it. Credential brokering: the gateway is the only path to the model.
async fn forward(st: &GwState, path: &str, body: Bytes) -> Response {
    let url = format!("{}/{}", st.upstream.trim_end_matches('/'), path);
    let mut req = st.client.post(&url).header("content-type", "application/json").body(body);
    if let Some(key) = &st.upstream_key {
        req = req.header("authorization", format!("Bearer {key}"));
    }
    match req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let ctype = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            let bytes = resp.bytes().await.unwrap_or_default();
            (status, [("content-type", ctype)], bytes).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
    }
}
