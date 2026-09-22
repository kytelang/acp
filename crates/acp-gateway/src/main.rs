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
    oidc: Option<(acp_auth::Jwks, acp_auth::EntraConfig)>,
    client: reqwest::Client,
    limiters: Mutex<HashMap<String, acp_core::ratelimit::TokenBucket>>,
    ledger: Option<Mutex<acp_ledger::Ledger>>,
    breakglass: Mutex<acp_core::breakglass::BreakGlassRegistry>,
    bg_file: Option<String>,
    bg_mtime: Mutex<Option<std::time::SystemTime>>,
    bg_key: Option<Vec<u8>>,
    content_scan: Option<String>,
    content_fw: Option<acp_core::content::ContentPolicy>,
    content_ml: Option<std::sync::Arc<acp_core::content::LinearScorer>>,
    budget_pg: Option<tokio::sync::Mutex<acp_pgstate::PgState>>,
    sem: std::sync::Arc<tokio::sync::Semaphore>,
    budget_state: Option<String>,
    metrics: Metrics,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_obs::init("acp-gateway");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8799".to_string();
    let (mut policy, mut upstream, mut upstream_key, mut env) = (None, None, None, "prod".to_string());
    let mut ledger_path: Option<String> = None;
    let mut bg_file: Option<String> = None;
    let mut bg_key_hex: Option<String> = None;
    let mut content_scan: Option<String> = None;
    let mut content_fw = false;
    let mut fw_block_secrets = false;
    let mut fw_deny_topics: Vec<String> = Vec::new();
    let mut content_ml_path: Option<String> = None;
    let mut budget_pg_conn: Option<String> = None;
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
            "--content-firewall" => content_fw = true,
            "--block-secrets" => { content_fw = true; fw_block_secrets = true; }
            "--deny-topic" => { content_fw = true; if let Some(v) = it.next() { fw_deny_topics.push(v.clone()); } }
            "--content-ml" => { content_fw = true; content_ml_path = it.next().cloned(); }
            "--budget-pg" => budget_pg_conn = it.next().cloned(),
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
                    Some((jwks, acp_auth::EntraConfig {
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
        Some(acp_core::content::ContentPolicy { block_injection: true, block_secrets: fw_block_secrets, redact_pii: true, denied_topics: fw_deny_topics })
    } else { None };
    let budget_pg = match budget_pg_conn.as_ref() {
        Some(conn) => match acp_pgstate::PgState::connect(conn).await {
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
    });
    let upstream_log = st.upstream.clone();
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route("/metrics", get(metrics))
        .route("/*path", any(handle))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(st);
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

async fn load_jwks(source: &str) -> Result<acp_auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
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
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            Box::new(s)
        }
    };
    // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE) for evidence signing.
    let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_hsm::signer_from_env() {
        Some(Ok(hsm)) => { tracing::info!("gateway signing evidence with a PKCS#11 HSM"); hsm }
        Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
        None => signer,
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
            use acp_policy::dsl::ObligationKind;
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
            if ctype.starts_with("text/event-stream") {
                // Model APIs stream by default; relay chunk-by-chunk without buffering.
                let s = futures_util::stream::unfold(resp, |mut r| async move {
                    match r.chunk().await {
                        Ok(Some(chunk)) => Some((Ok::<_, std::io::Error>(chunk), r)),
                        _ => None,
                    }
                });
                (status, [("content-type", "text/event-stream")], axum::body::Body::from_stream(s)).into_response()
            } else {
                let bytes = resp.bytes().await.unwrap_or_default();
                (status, [("content-type", ctype)], bytes).into_response()
            }
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
    }
}
