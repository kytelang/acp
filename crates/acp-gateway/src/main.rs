//! acp-gateway: the LLM gateway PEP (phase C, C2). A reverse proxy in front of model APIs. Every
//! request is classified and evaluated by the shared policy engine before it may reach a model, and
//! the gateway holds the upstream model credential so a caller cannot bypass it (credential
//! brokering): the app authenticates to the gateway, the gateway authenticates to the model.

use acp_core::modelclass::ModelTaxonomy;
use acp_core::types::Verdict;
use acp_gateway::decide;
use acp_core::policy::PolicyEngine;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    extract::DefaultBodyLimit,
    Json, Router,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::sync::{Arc, Mutex};

static SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
    step_up: AtomicU64,
    shed: AtomicU64,
}

struct GwState {
    engine: PolicyEngine,
    tax: ModelTaxonomy,
    upstream: String,
    upstream_key: Option<String>,
    env: String,
    oidc: Option<(acp_core::auth::Jwks, acp_core::auth::EntraConfig)>,
    client: reqwest::Client,
    limiters: Mutex<HashMap<String, acp_core::ratelimit::TokenBucket>>,
    ledger: Option<Mutex<acp_core::ledger::Ledger>>,
    breakglass: Mutex<acp_core::breakglass::BreakGlassRegistry>,
    bg_file: Option<String>,
    bg_mtime: Mutex<Option<std::time::SystemTime>>,
    report_url: Option<String>,
    report_token: Option<String>,
    proxy_id: String,
    bg_key: Option<Vec<u8>>,
    content_scan: Option<String>,
    content_fw: Option<acp_core::content::ContentPolicy>,
    content_ml: Option<std::sync::Arc<acp_core::content::LinearScorer>>,
    budget_pg: Option<tokio::sync::Mutex<acp_core::pgstate::PgState>>,
    sem: std::sync::Arc<tokio::sync::Semaphore>,
    budget_state: Option<String>,
    metrics: Metrics,
    // B2: when set, the gateway checks each model response for groundedness against the request
    // context and blocks/flags below this threshold.
    groundedness_threshold: Option<f32>,
    // Audit P0 F1: cache of per-agent virtual key -> (agent_id, app_id), resolved against the control
    // plane so the caller identity is authenticated, not a spoofable header.
    identity_cache: Mutex<HashMap<String, (String, String)>>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_core::obs::init("acp-gateway");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8799".to_string();
    let (mut policy, mut upstream, mut upstream_key, mut env) = (None, None, None, "prod".to_string());
    let mut ledger_path: Option<String> = None;
    let mut bg_file: Option<String> = None;
    let mut bg_key_hex: Option<String> = None;
    let mut content_scan: Option<String> = None;
    let mut groundedness_threshold: Option<f32> = None;
    let mut content_fw = false;
    let mut fw_block_secrets = false;
    let mut fw_block_toxicity = false;
    let mut fw_deny_topics: Vec<String> = Vec::new();
    let mut content_ml_path: Option<String> = None;
    let mut budget_pg_conn: Option<String> = None;
    let mut report_url: Option<String> = None;
    let mut report_token: Option<String> = None;
    let mut gw_id: Option<String> = None;
    let mut budget_state: Option<String> = None;
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
            "--content-scan" => content_scan = it.next().cloned(),
            "--groundedness-threshold" => groundedness_threshold = it.next().and_then(|v| v.parse().ok()),
            "--content-firewall" => content_fw = true,
            "--block-secrets" => { content_fw = true; fw_block_secrets = true; }
            "--block-toxicity" => { content_fw = true; fw_block_toxicity = true; }
            "--deny-topic" => { content_fw = true; if let Some(v) = it.next() { fw_deny_topics.push(v.clone()); } }
            "--content-ml" => { content_fw = true; content_ml_path = it.next().cloned(); }
            "--budget-pg" => budget_pg_conn = it.next().cloned(),
            "--report-url" => report_url = it.next().cloned(),
            "--report-token" => report_token = it.next().cloned(),
            "--proxy-id" => gw_id = it.next().cloned(),
            "--budget-state" => budget_state = it.next().cloned(),
            "--env" => env = it.next().cloned().unwrap_or(env),
            "--entra-tenant" => entra_tenant = it.next().cloned(),
            "--entra-audience" => entra_audience = it.next().cloned(),
            other => {
                tracing::warn!("unknown option '{other}'");
                return std::process::ExitCode::from(2);
            }
        }
    }
    let engine = match policy.as_ref().map(|p| std::fs::read_to_string(p)) {
        Some(Ok(src)) => match PolicyEngine::from_yaml(&src) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("bad policy: {e}");
                return std::process::ExitCode::from(1);
            }
        },
        _ => {
            tracing::error!("--policy <file> is required");
            return std::process::ExitCode::from(2);
        }
    };
    let upstream = match upstream {
        Some(u) => u,
        None => {
            tracing::error!("--upstream <base-url> is required");
            return std::process::ExitCode::from(2);
        }
    };
    let oidc = match (entra_tenant, entra_audience) {
        (Some(tid), Some(aud)) => {
            let url = format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys");
            match load_jwks(&url).await {
                Ok(jwks) => {
                    tracing::info!("per-request human identity enabled");
                    Some((jwks, acp_core::auth::EntraConfig {
                        issuer: format!("https://login.microsoftonline.com/{tid}/v2.0"),
                        audience: aud,
                    }))
                }
                Err(e) => {
                    tracing::error!("could not load JWKS ({e}); refusing to start (identity requested, failing closed)");
                    return std::process::ExitCode::from(1);
                }
            }
        }
        _ => None,
    };
    let ledger = ledger_path.as_ref().and_then(|p| open_ledger(p));
    if ledger.is_some() {
        tracing::info!("recording decisions to the tamper-evident ledger");
    }
    let upstream_key = upstream_key.map(|k| acp_core::secret::resolve(&k));
    let bg_key = bg_key_hex.as_ref().and_then(|h| hex::decode(acp_core::secret::resolve(h)).ok());
    let content_fw = if content_fw {
        Some(acp_core::content::ContentPolicy { block_injection: true, block_secrets: fw_block_secrets, redact_pii: true, denied_topics: fw_deny_topics, block_toxicity: fw_block_toxicity })
    } else { None };
    let budget_pg = match budget_pg_conn.as_ref() {
        Some(conn) => match acp_core::pgstate::PgState::connect(conn).await {
            Ok(s) => { tracing::info!("shared budgets via Postgres ({conn})"); Some(tokio::sync::Mutex::new(s)) }
            Err(e) => { tracing::error!("cannot connect --budget-pg: {e}"); return std::process::ExitCode::from(1); }
        },
        None => None,
    };
    let content_ml = match content_ml_path.as_ref() {
        Some(path) => match std::fs::read_to_string(path).ok().and_then(|s| acp_core::content::LinearScorer::from_json(&s).ok()) {
            Some(s) => { tracing::info!("ML content detector loaded from {path}"); Some(std::sync::Arc::new(s)) }
            None => { tracing::error!("cannot load --content-ml model {path}"); return std::process::ExitCode::from(1); }
        },
        None => None,
    };
    let st = Arc::new(GwState {
        engine,
        tax: ModelTaxonomy::default(),
        upstream,
        upstream_key,
        env,
        report_url: report_url.clone(),
        report_token: report_token.clone(),
        proxy_id: gw_id.clone().unwrap_or_else(|| "gateway".to_string()),
        oidc,
        client: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap_or_default(),
        sem: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
        limiters: Mutex::new(
            budget_state
                .as_ref()
                .and_then(|f| std::fs::read_to_string(f).ok())
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
        ),
        ledger: ledger.map(Mutex::new),
        breakglass: Mutex::new(acp_core::breakglass::BreakGlassRegistry::new()),
        bg_file,
        bg_mtime: Mutex::new(None),
        bg_key,
        content_scan,
        content_fw,
        content_ml,
        budget_pg,
        budget_state,
        metrics: Metrics::default(),
        groundedness_threshold,
        identity_cache: Mutex::new(HashMap::new()),
    });
    let upstream_log = st.upstream.clone();
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route("/metrics", get(metrics))
        .route("/*path", any(handle))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(st);
    if let Some(base) = report_url.clone() {
        let pid = gw_id.clone().unwrap_or_else(|| "gateway".to_string());
        let token = report_token.clone();
        let base = base.trim_end_matches('/').to_string();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                let mut req = client.post(format!("{base}/heartbeat/{pid}"));
                if let Some(t) = &token { req = req.bearer_auth(t); }
                let _ = req.send().await;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("bind {addr}: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    tracing::info!("governing model calls on http://{addr} -> {upstream_log}");
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
        tracing::warn!("break-glass grant REJECTED (signature/pin); keeping current");
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

/// Ask the configured content firewall (Lakera / Azure AI Content Safety / your endpoint) whether a
/// prompt is safe to forward. Contract: POST {"text": "..."} -> {"block": bool}. INTEGRATE, do not
/// build: ACP owns authorization, the content plane owns content. Fail-open on an unreachable scanner
/// would be unsafe, so a scan error blocks (fail-closed) when scanning is configured.
/// Gather the prompt text from OpenAI-style messages[].content or a "prompt"/"input" field.
fn gather_prompt_text(body: &serde_json::Value) -> String {
    let mut text = String::new();
    if let Some(msgs) = body.get("messages").and_then(|v| v.as_array()) {
        for m in msgs {
            if let Some(c) = m.get("content").and_then(|v| v.as_str()) {
                text.push_str(c);
                text.push('\n');
            }
        }
    }
    for k in ["prompt", "input"] {
        if let Some(s) = body.get(k).and_then(|v| v.as_str()) {
            text.push_str(s);
        }
    }
    text
}

/// First-party content firewall (native): scan the prompt with acp_core::content before it reaches
/// the model. Returns a block reason if the built-in engine blocks.
fn native_content_blocked(st: &GwState, body: &serde_json::Value) -> Option<String> {
    let policy = st.content_fw.as_ref()?;
    let text = gather_prompt_text(body);
    if text.is_empty() {
        return None;
    }
    let v = acp_core::content::scan_with_ml(policy, &text, st.content_ml.as_deref());
    if v.block {
        let kinds: Vec<String> = v.findings.iter().map(|f| f.kind.clone()).collect();
        Some(format!("content firewall: {}", kinds.join(", ")))
    } else {
        None
    }
}

async fn content_blocked(st: &GwState, body: &serde_json::Value) -> Option<String> {
    let url = st.content_scan.as_ref()?;
    let text = gather_prompt_text(body);
    if text.is_empty() {
        return None;
    }
    match st.client.post(url).json(&serde_json::json!({"text": text})).send().await {
        Ok(r) => {
            let v: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({}));
            if v.get("block").and_then(|b| b.as_bool()).unwrap_or(false) {
                Some(v.get("reason").and_then(|x| x.as_str()).unwrap_or("content policy").to_string())
            } else {
                None
            }
        }
        Err(e) => Some(format!("content scanner unreachable (fail-closed): {e}")),
    }
}

async fn load_jwks(source: &str) -> Result<acp_core::auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_core::auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
}

fn open_ledger(path: &str) -> Option<acp_core::ledger::Ledger> {
    let key_path = format!("{path}.key");
    let signer: Box<dyn acp_core::sign::Signer + Send> = match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            Box::new(acp_core::sign::Ed25519Signer::from_seed(&s))
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            Box::new(s)
        }
    };
    // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE) for evidence signing.
    let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_core::hsm::signer_from_env() {
        Some(Ok(hsm)) => { tracing::info!("gateway signing evidence with a PKCS#11 HSM"); hsm }
        Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
        None => signer,
    };
    acp_core::ledger::Ledger::open(path, signer).ok()
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
fn record_decision(st: &GwState, app: &str, principal: &str, model: &str, d: &acp_gateway::GatewayDecision) -> bool {
    let ledger = match &st.ledger {
        Some(l) => l,
        None => return true, // no ledger configured: nothing to fail closed on
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
    match ledger.lock() {
        Ok(mut l) => l.append(&did, "decision", &record, None).is_ok(),
        Err(_) => false,
    }
}

/// Prometheus text-format metrics for the gateway.
async fn metrics(State(st): State<Arc<GwState>>) -> impl IntoResponse {
    use std::sync::atomic::Ordering::Relaxed;
    let m = &st.metrics;
    let body = format!(
        "# TYPE acp_gateway_requests_total counter\nacp_gateway_requests_total {}\n\
         # TYPE acp_gateway_allowed_total counter\nacp_gateway_allowed_total {}\n\
         # TYPE acp_gateway_denied_total counter\nacp_gateway_denied_total {}\n\
         # TYPE acp_gateway_step_up_total counter\nacp_gateway_step_up_total {}\n\
         # TYPE acp_gateway_shed_total counter\nacp_gateway_shed_total {}\n",
        m.requests.load(Relaxed), m.allowed.load(Relaxed), m.denied.load(Relaxed),
        m.step_up.load(Relaxed), m.shed.load(Relaxed),
    );
    ([("content-type", "text/plain; version=0.0.4")], body)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Resolve an agent's authenticated identity from its per-agent virtual key against the control plane
/// (audit P0 F1). Cached in-process. Returns (agent_id, app_id) for a valid key, None otherwise.
async fn resolve_virtual_key(st: &GwState, key: &str) -> Option<(String, String)> {
    if key.is_empty() { return None; }
    if let Ok(cache) = st.identity_cache.lock() {
        if let Some(v) = cache.get(key) { return Some(v.clone()); }
    }
    let base = st.report_url.clone()?; // the control-plane base
    let url = format!("{}/agents/resolve-key", base.trim_end_matches('/'));
    let resp = st.client.post(&url).json(&json!({"key": key})).send().await.ok()?;
    let v: serde_json::Value = resp.json().await.ok()?;
    if v.get("verified").and_then(|b| b.as_bool()).unwrap_or(false) {
        let agent_id = v.get("agent_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let app_id = v.get("app_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if !app_id.is_empty() {
            if let Ok(mut cache) = st.identity_cache.lock() { cache.insert(key.to_string(), (agent_id.clone(), app_id.clone())); }
            return Some((agent_id, app_id));
        }
    }
    None
}

async fn handle(
    State(st): State<Arc<GwState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let _permit = match st.sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            st.metrics.shed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "1")], "gateway at capacity").into_response();
        }
    };
    st.metrics.requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // The model is in the request body (OpenAI/Anthropic style). No model -> nothing to govern here.
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!({}));
    let model = parsed.get("model").and_then(|v| v.as_str()).unwrap_or("");

    // Subject identity. Preferred: a per-agent virtual key (x-acp-agent-key) resolved and verified
    // against the control plane, so the app/agent subject is authenticated, not a spoofable header
    // (audit P0 F1). Fallback: the legacy x-acp-app header, marked unverified so policy can deny or
    // step-up unattributed high-risk calls.
    let vkey = headers.get("x-acp-agent-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    let (app_owned, agent_id, verified_identity) = match resolve_virtual_key(&st, vkey).await {
        Some((agent, app_id)) => (app_id, agent, true),
        None => (headers.get("x-acp-app").and_then(|v| v.to_str().ok()).unwrap_or("unknown-app").to_string(), String::new(), false),
    };
    let app = app_owned.as_str();
    let (principal, groups) = resolve_principal(&st, &headers).unwrap_or_else(|| ("unattributed".to_string(), Vec::new()));

    // A small, non-sensitive summary for policy matching. Never the prompt (that is a scan obligation).
    let argsum = json!({
        "model": model,
        "stream": parsed.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
        "max_tokens": parsed.get("max_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
    });

    let mut d = decide(&st.engine, &st.tax, model, app, &principal, &groups, &argsum, &st.env);
    apply_break_glass(&st, app, model, &mut d);
    if !record_decision(&st, app, &principal, model, &d) {
        // Record-before-forward: if the evidence write failed, fail closed rather than act unrecorded.
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": {"message": "evidence unavailable, failing closed", "type": "acp_fail_closed"}})),
        ).into_response();
    }
    tracing::info!(
        "{} model={} class={} op={} app={} principal={} -> {:?}",
        path, model, d.resource, d.operation, app, principal, d.verdict
    );

    // Producers: report a model-call denial to the control plane for the console Violations feed.
    if d.verdict == Verdict::Deny {
        if let Some(base) = st.report_url.clone() {
            let token = st.report_token.clone();
            let body = json!({
                "kind": "deny", "verdict": "deny", "ts_ms": now_ms(), "proxy": st.proxy_id,
                "agent": if agent_id.is_empty() { app } else { agent_id.as_str() }, "verified_identity": verified_identity, "tool": model, "resource": d.resource, "rule_id": d.rule_id,
                "impact": "model-call", "outcome": "blocked",
            }).to_string();
            let client = st.client.clone();
            tokio::spawn(async move {
                let url = format!("{}/event/deny", base.trim_end_matches('/'));
                let mut req = client.post(&url);
                if let Some(t) = &token { req = req.bearer_auth(t); }
                let _ = req.send().await;
            });
        }
    }
    match d.verdict {
        Verdict::Deny => {
            st.metrics.denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (
            StatusCode::FORBIDDEN,
            Json(json!({"error": {"message": format!("blocked by ACP rule '{}': {}", d.rule_id.unwrap_or_default(), d.reason.unwrap_or_else(|| "policy".into())), "type": "acp_policy_denied"}})),
        )
            .into_response()
        }
        Verdict::StepUp => {
            st.metrics.step_up.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"error": {"message": "human approval required (step-up) by ACP policy", "type": "acp_step_up"}})),
        )
            .into_response()
        }
        Verdict::Allow | Verdict::Shadow => {
            // Obligations (model v2, D4) on the gateway: a rate_limit acts as a per-(app, model-class)
            // token/cost budget and denies once spent; a confirm routes to step-up. Deny-overrides.
            use acp_core::policy::dsl::ObligationKind;
            let (mut over_budget, mut needs_confirm) = (false, false);
            for ob in &d.obligations {
                match ob.kind {
                    ObligationKind::Confirm => needs_confirm = true,
                    ObligationKind::RateLimit => {
                        let key = format!("{}|{}", app, d.resource);
                        let max = ob.max.unwrap_or(1_000_000);
                        let window = ob.window_ms.unwrap_or(86_400_000);
                        let rate = (max as f64) * 1000.0 / (window as f64);
                        // Shared budget via Postgres when configured (multi-replica); the in-process
                        // token bucket is the single-instance default and the fallback on a store error.
                        let inproc = |st: &GwState, key: String| -> bool {
                            let mut lims = st.limiters.lock().unwrap();
                            let bucket = lims.entry(key).or_insert_with(|| {
                                acp_core::ratelimit::TokenBucket::new(max as f64, rate, now_ms())
                            });
                            bucket.allow(now_ms())
                        };
                        let ok = if let Some(pg) = st.budget_pg.as_ref() {
                            match pg.lock().await.allow(&key, max as f64, rate, now_ms() as i64).await {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::warn!("budget store error (falling back in-process): {e}");
                                    inproc(&st, key.clone())
                                }
                            }
                        } else {
                            inproc(&st, key.clone())
                        };
                        if !ok {
                            over_budget = true;
                        }
                        // Persist budgets so a restart cannot reset a spent budget (best-effort).
                        if let Some(f) = &st.budget_state {
                            let snap = st.limiters.lock().unwrap().clone();
                            if let Ok(js) = serde_json::to_string(&snap) {
                                let _ = std::fs::write(f, js);
                            }
                        }
                    }
                    ObligationKind::Redact => { /* prompt/response redaction is C3-scan, wired with the content plane */ }
                    ObligationKind::Disclose => { /* G11: AI-disclosure is annotated on the response at the PEP */ }
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
            // Content plane: first-party firewall (native), then the external scanner if configured.
            if let Some(reason) = native_content_blocked(&st, &parsed) {
                st.metrics.denied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": {"message": format!("blocked by content policy: {reason}"), "type": "acp_content_blocked"}})),
                ).into_response();
            }
            if let Some(reason) = content_blocked(&st, &parsed).await {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": {"message": format!("blocked by content policy: {reason}"), "type": "acp_content_blocked"}})),
                ).into_response();
            }
            st.metrics.allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            forward(&st, &path, body).await
        }
    }
}

/// Verify the request bearer against the org IdP and return the human principal, if configured.
fn resolve_principal(st: &GwState, headers: &HeaderMap) -> Option<(String, Vec<String>)> {
    let (jwks, cfg) = st.oidc.as_ref()?;
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))?;
    match acp_core::auth::verify(token, jwks, cfg, now_ms()) {
        // The principal's IdP groups/roles ride along so a policy rule can match on group membership.
        Ok(p) => Some((if p.username.is_empty() { p.oid } else { p.username }, p.roles)),
        Err(_) => None,
    }
}

/// F1: is any response gate active (content firewall, external hook or groundedness)?
fn response_gate_active(st: &GwState) -> bool {
    st.content_fw.is_some() || st.content_scan.is_some() || st.groundedness_threshold.is_some()
}

/// F1: gather assistant text from a buffered SSE body by parsing each `data:` event and collecting
/// `content`/`text` string values (covers OpenAI delta chunks and Anthropic content blocks).
fn gather_sse_text(bytes: &[u8]) -> String {
    fn collect(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, val) in m {
                    if (k == "content" || k == "text") {
                        if let Some(sx) = val.as_str() { out.push_str(sx); out.push(' '); }
                    }
                    collect(val, out);
                }
            }
            serde_json::Value::Array(a) => { for x in a { collect(x, out); } }
            _ => {}
        }
    }
    let body = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for line in body.lines() {
        let line = line.trim_start();
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" { continue; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) { collect(&v, &mut out); }
        }
    }
    out
}

/// B2: extract the assistant/answer text from a model response (OpenAI/Anthropic-style shapes).
fn gather_response_text(v: &serde_json::Value) -> String {
    let mut out = String::new();
    // OpenAI chat: choices[].message.content
    if let Some(cs) = v.get("choices").and_then(|c| c.as_array()) {
        for c in cs {
            if let Some(t) = c.pointer("/message/content").and_then(|x| x.as_str()) { out.push_str(t); out.push('\n'); }
            if let Some(t) = c.get("text").and_then(|x| x.as_str()) { out.push_str(t); out.push('\n'); }
        }
    }
    // Anthropic messages: content[].text
    if let Some(cs) = v.get("content").and_then(|c| c.as_array()) {
        for c in cs {
            if let Some(t) = c.get("text").and_then(|x| x.as_str()) { out.push_str(t); out.push('\n'); }
        }
    }
    // Fallbacks.
    if out.is_empty() {
        if let Some(t) = v.get("output_text").and_then(|x| x.as_str()) { out.push_str(t); }
    }
    out
}

/// B2: scan a model response with the content engine (+ external hook), then check groundedness
/// against the request context. Returns Some(block_reason) to block, or None to pass. Also returns an
/// optional groundedness score to surface as a header.
async fn response_gate(st: &GwState, req_body: &serde_json::Value, resp: &serde_json::Value) -> (Option<String>, Option<f32>) {
    let answer = gather_response_text(resp);
    // 1. content engine over the response.
    if let Some(policy) = st.content_fw.as_ref() {
        if !answer.is_empty() {
            let v = acp_core::content::scan_with_ml(policy, &answer, st.content_ml.as_deref());
            if v.block {
                let kinds: Vec<String> = v.findings.iter().map(|f| f.kind.clone()).collect();
                return (Some(format!("response blocked by content firewall: {}", kinds.join(", "))), None);
            }
        }
    }
    // 2. external content-scan hook over the response (direction=response).
    if let Some(url) = st.content_scan.as_ref() {
        if !answer.is_empty() {
            match st.client.post(url).json(&serde_json::json!({"text": answer, "direction": "response"})).send().await {
                Ok(r) => {
                    let v: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({}));
                    if v.get("block").and_then(|b| b.as_bool()).unwrap_or(false) {
                        return (Some(v.get("reason").and_then(|x| x.as_str()).unwrap_or("response content policy").to_string()), None);
                    }
                }
                Err(e) => return (Some(format!("response content scanner unreachable (fail-closed): {e}")), None),
            }
        }
    }
    // 3. groundedness against the request context (obligation, config-driven).
    if let Some(thr) = st.groundedness_threshold {
        let context = gather_prompt_text(req_body);
        if !answer.is_empty() && !context.is_empty() {
            let report = acp_core::groundedness::groundedness(&answer, &context, 0.5);
            if report.score < thr {
                return (Some(format!("response not grounded ({:.2} < {:.2})", report.score, thr)), Some(report.score));
            }
            return (None, Some(report.score));
        }
    }
    (None, None)
}

/// Forward the (allowed) call to the model provider, attaching the gateway's upstream credential so
/// the caller never holds it. Credential brokering: the gateway is the only path to the model.
async fn forward(st: &GwState, path: &str, body: Bytes) -> Response {
    let url = format!("{}/{}", st.upstream.trim_end_matches('/'), path);
    let req_body_for_gate = body.clone();
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
            if ctype.starts_with("text/event-stream") {
                // F1: when a response gate is active, buffer the stream, gate the accumulated text, then
                // emit (or block). With no gate active, relay chunk-by-chunk without buffering.
                if response_gate_active(st) {
                    let bytes = resp.bytes().await.unwrap_or_default();
                    let answer = gather_sse_text(&bytes);
                    let reqv: serde_json::Value = serde_json::from_slice(&req_body_for_gate).unwrap_or_else(|_| serde_json::json!({}));
                    // Reuse response_gate by wrapping the gathered answer as a synthetic response object.
                    let synth = serde_json::json!({"choices": [{"message": {"content": answer}}]});
                    let (block, _score) = response_gate(st, &reqv, &synth).await;
                    if let Some(reason) = block {
                        let ev = format!("data: {}\n\ndata: [DONE]\n\n", serde_json::json!({"error": {"message": reason, "type": "acp_response_blocked"}}));
                        return (status, [("content-type", "text/event-stream")], ev).into_response();
                    }
                    return (status, [("content-type", "text/event-stream")], bytes).into_response();
                }
                let s = futures_util::stream::unfold(resp, |mut r| async move {
                    match r.chunk().await {
                        Ok(Some(chunk)) => Some((Ok::<_, std::io::Error>(chunk), r)),
                        _ => None,
                    }
                });
                (status, [("content-type", "text/event-stream")], axum::body::Body::from_stream(s)).into_response()
            } else {
                let bytes = resp.bytes().await.unwrap_or_default();
                // B2: gate the model response (content firewall + external hook + groundedness).
                if let Ok(rv) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let reqv: serde_json::Value = serde_json::from_slice(&req_body_for_gate).unwrap_or_else(|_| serde_json::json!({}));
                    let (block, score) = response_gate(st, &reqv, &rv).await;
                    if let Some(reason) = block {
                        return (StatusCode::FORBIDDEN, [("content-type", "application/json")],
                            serde_json::json!({"error": {"message": reason, "type": "acp_response_blocked"}}).to_string()).into_response();
                    }
                    if let Some(sc) = score {
                        return (status, [("content-type", ctype.as_str()), ("x-acp-groundedness", Box::leak(format!("{sc:.3}").into_boxed_str()))], bytes).into_response();
                    }
                }
                (status, [("content-type", ctype)], bytes).into_response()
            }
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
    }
}
