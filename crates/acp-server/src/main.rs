//! acp-server: the control-plane HTTP service (v1.1 seed, single-tenant).
//!
//! Serves the web approval inbox (M4.3), the current policy endpoint (M2.2), a read-only
//! evidence-verify endpoint, and a basic governance report. HTML is rendered with `maud`, which
//! auto-escapes, so attacker-controlled content in the inbox cannot inject markup (M4.5).
//! Multi-tenant Postgres, per-tenant keys, and SSO are the next layer (v1.1.1-1.1.3 / H1).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap as StdHashMap;
use maud::{html, DOCTYPE};
use std::sync::Arc;

struct AppState {
    approvals: Option<String>,
    policy: Option<(String, String)>, // (hash, yaml body)
    ledger: Option<String>,
    // B1: server-side liveness of enrolled proxies (dead-man's-switch).
    liveness: std::sync::Mutex<acp_core::liveness::GapDetector>,
    // B3: fail-open/deny spike detectors, one per event kind.
    spikes: std::sync::Mutex<std::collections::HashMap<String, acp_core::anomaly::SpikeDetector>>,
    // H0.7: tamper-evident self-governance meta-audit log (None if not configured).
    meta: Option<std::sync::Mutex<acp_ledger::Ledger>>,
    registry: Option<String>,
    policy_store: Option<String>,
    enrollment: Option<String>,
    store: Option<std::sync::Arc<acp_cpstore::ControlStore>>,
    cp_key: String,
    break_glass_file: Option<String>,
    break_glass_seed: Option<[u8; 32]>,
    auth: Option<Auth>,
}

/// Optional control-plane RBAC. When present, mutating endpoints require a verified bearer token
/// with the right capability. `dev` is an in-memory mock issuer for local use (issues test tokens);
/// production sets jwks+cfg from the org IdP and leaves dev None.
struct Auth {
    jwks: std::sync::Arc<std::sync::RwLock<acp_auth::Jwks>>,
    cfg: acp_auth::EntraConfig,
    dev: Option<acp_auth::MockEntra>,
}

/// Load a JWKS from a URL (fetched) or a file path (read). Used for real Entra keys.
async fn load_jwks(source: &str) -> Result<acp_auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?
            .text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
}

/// Authorise a request for a capability. RBAC disabled (auth None) allows everything (local demo).
fn authorize(auth: &Option<Auth>, headers: &HeaderMap, cap: acp_auth::Capability) -> Result<(), Response> {
    let a = match auth { Some(a) => a, None => return Ok(()) };
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"missing bearer token"}))).into_response())?;
    let jwks = a.jwks.read().unwrap();
    let p = acp_auth::verify(token, &jwks, &a.cfg, now_ms())
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":format!("invalid token: {e:?}")}))).into_response())?;
    if !p.can(cap) {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"ok":false,"error":format!("principal lacks {cap:?}")}))).into_response());
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    acp_obs::init("acp-server");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8787".to_string();
    let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
    let mut meta_ledger: Option<String> = None;
    let mut registry: Option<String> = None;
    let mut policy_store: Option<String> = None;
    let mut break_glass_file: Option<String> = None;
    let mut enrollment: Option<String> = None;
    let mut store_url: Option<String> = None;
    let mut cp_key = "acp-cp.key".to_string();
    let mut tls_ca: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut break_glass_seed: Option<[u8; 32]> = None;
    let mut oidc_jwks: Option<String> = None;
    let mut oidc_issuer: Option<String> = None;
    let mut oidc_audience: Option<String> = None;
    let mut dev_auth = false;
    let mut entra_tenant: Option<String> = None;
    let mut entra_audience: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or(addr),
            "--approvals" => approvals = it.next().cloned(),
            "--policy" => policy_path = it.next().cloned(),
            "--ledger" => ledger = it.next().cloned(),
            "--meta-ledger" => meta_ledger = it.next().cloned(),
            "--registry" => registry = it.next().cloned(),
            "--policy-store" => policy_store = it.next().cloned(),
            "--enrollment" => enrollment = it.next().cloned(),
            "--store" => store_url = it.next().cloned(),
            "--cp-key" => { if let Some(v) = it.next() { cp_key = v.clone(); } }
            "--oidc-jwks" => oidc_jwks = it.next().cloned(),
            "--oidc-issuer" => oidc_issuer = it.next().cloned(),
            "--oidc-audience" => oidc_audience = it.next().cloned(),
            "--dev-auth" => dev_auth = true,
            "--entra-tenant" => entra_tenant = it.next().cloned(),
            "--entra-audience" => entra_audience = it.next().cloned(),
            "--break-glass-file" => break_glass_file = it.next().cloned(),
            "--tls-ca" => tls_ca = it.next().cloned(),
            "--tls-cert" => tls_cert = it.next().cloned(),
            "--tls-key" => tls_key = it.next().cloned(),
            "--break-glass-key" => {
                if let Some(h) = it.next() {
                    match hex::decode(acp_core::secret::resolve(h)) {
                        Ok(b) if b.len() == 32 => {
                            let mut s = [0u8; 32];
                            s.copy_from_slice(&b);
                            break_glass_seed = Some(s);
                        }
                        _ => {
                            tracing::error!("--break-glass-key must be a 32-byte hex seed");
                            std::process::exit(2);
                        }
                    }
                }
            }
            other => {
                tracing::warn!("unknown option '{other}'");
                std::process::exit(2);
            }
        }
    }

    let policy = match policy_path {
        Some(p) => match std::fs::read_to_string(&p).ok().and_then(|src| {
            acp_policy::PolicyEngine::from_yaml(&src)
                .ok()
                .map(|e| (e.hash().to_string(), src))
        }) {
            Some(v) => Some(v),
            None => {
                tracing::error!("could not load policy {p}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    // H0.7: a tamper-evident meta-audit ledger for admin actions (policy/key/RBAC changes).
    let meta = meta_ledger.and_then(|path| {
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
        // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE).
        let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_hsm::signer_from_env() {
            Some(Ok(hsm)) => { tracing::info!("meta-ledger signing with a PKCS#11 HSM"); hsm }
            Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
            None => signer,
        };
        match acp_ledger::Ledger::open(&path, signer) {
            Ok(l) => Some(std::sync::Mutex::new(l)),
            Err(e) => {
                tracing::error!("could not open meta-ledger {path}: {e}");
                None
            }
        }
    });

    if dev_auth && std::env::var("ACP_ALLOW_DEV_AUTH").ok().as_deref() != Some("1") {
        tracing::info!("--dev-auth requires ACP_ALLOW_DEV_AUTH=1 (never enable in production)");
        std::process::exit(2);
    }
    // Control-plane RBAC (opt-in). Three ways to enable, in priority order:
    //   --dev-auth                         : in-memory mock issuer (local use)
    //   --entra-tenant + --entra-audience  : real Entra; issuer + JWKS URL derived from the tenant
    //   --oidc-jwks(url|file) + --oidc-issuer + --oidc-audience : explicit
    // With none, RBAC is off and the local demo is unaffected.
    let auth: Option<Auth> = if dev_auth {
        let mock = acp_auth::MockEntra::new("common", "acp-app");
        tracing::info!("DEV auth enabled (mock issuer); GET /auth/dev-token?role=PolicyAdmin");
        Some(Auth {
            jwks: std::sync::Arc::new(std::sync::RwLock::new(mock.jwks())),
            cfg: mock.config(),
            dev: Some(mock),
        })
    } else {
        // Resolve (issuer, audience, jwks_source) from either the Entra convenience flags or the
        // explicit OIDC flags.
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        match resolved {
            Some((issuer, audience, source)) => match load_jwks(&source).await {
                Ok(jwks) => {
                    tracing::info!("OIDC RBAC enabled (issuer {issuer}, aud {audience})");
                    let jwks_arc = std::sync::Arc::new(std::sync::RwLock::new(jwks));
                    // Key rotation: refresh the JWKS hourly when it came from a URL.
                    if source.starts_with("http") {
                        let arc = jwks_arc.clone();
                        let url = source.clone();
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                                if let Ok(fresh) = load_jwks(&url).await {
                                    *arc.write().unwrap() = fresh;
                                }
                            }
                        });
                    }
                    Some(Auth {
                        jwks: jwks_arc,
                        cfg: acp_auth::EntraConfig { issuer, audience },
                        dev: None,
                    })
                }
                Err(e) => {
                    tracing::error!("could not load JWKS from {source}: {e}; refusing to start (auth was requested, failing closed)");
                    std::process::exit(1);
                }
            },
            None => None,
        }
    };
    // Config-driven control-plane store (identity, endpoints; GRC later). The backend is chosen by
    // the --store URL (sqlite / postgres / mysql). Fail closed if it was requested but cannot connect.
    let store = match store_url {
        Some(u) => match acp_cpstore::ControlStore::connect(&u).await {
            Ok(s) => {
                tracing::info!("control-plane store connected");
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::error!("cannot connect --store: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
        liveness: std::sync::Mutex::new(acp_core::liveness::GapDetector::new()),
        spikes: std::sync::Mutex::new(std::collections::HashMap::new()),
        meta,
        registry,
        policy_store,
        enrollment,
        store,
        cp_key,
        break_glass_file,
        break_glass_seed,
        auth,
    });
    let app = Router::new()
        .route("/", get(inbox))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route("/approvals/:id/approve", post(approve))
        .route("/approvals/:id/deny", post(deny))
        .route("/policy/current", get(policy_current))
        .route("/verify", get(verify))
        .route("/report", get(report))
        .route("/metrics", get(metrics))
        .route("/heartbeat/:proxy", post(heartbeat))
        .route("/liveness", get(liveness))
        .route("/event/:kind", post(record_event))
        .route("/alerts", get(alerts))
        .route("/admin/meta", post(record_meta))
        .route("/meta-audit", get(meta_audit))
        .route("/timeline", get(timeline))
        .route("/apps", get(apps))
        .route("/agents", get(agents))
        .route("/policy-store", get(policy_store_current))
        .route("/policy-store/rules", get(policy_store_rules))
        .route("/policy-store/deploy", post(policy_store_deploy))
        .route("/endpoints", get(endpoints_list))
        .route("/endpoints/register", post(endpoints_register))
        .route("/apps", post(app_register))
        .route("/agents", post(agent_register))
        .route("/agents/:id/deactivate", post(agent_deactivate))
        .route("/agents/verify", post(agent_verify))
        .route("/grc", get(grc_list).post(grc_create))
        .route("/grc/:id/status", post(grc_status))
        .route("/approvals/pending", get(approvals_pending))
        .route("/evidence/recent", get(evidence_recent))
        .route("/break-glass", get(break_glass_status))
        .route("/break-glass/engage", post(break_glass_engage))
        .route("/break-glass/clear", post(break_glass_clear))
        .route("/auth/dev-token", get(dev_token))
        .with_state(state);

    // mTLS between components: when TLS flags are given, require a client cert signed by the ACP CA.
    if let (Some(ca), Some(cert), Some(key)) = (&tls_ca, &tls_cert, &tls_key) {
        tracing::error!("listening on https://{addr} (mTLS, client cert required)");
        serve_mtls(&addr, app, ca, cert, key).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!("listening on http://{addr}");
    // X.7: drain in-flight requests on SIGTERM/Ctrl-C instead of dropping them. The evidence
    // ledger is durable per-append, so a clean drain loses no decision and double-executes none.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");
}

async fn inbox(State(st): State<Arc<AppState>>) -> Html<String> {
    let items = match &st.approvals {
        Some(p) => acp_approvals::ApprovalStore::open(p)
            .and_then(|s| s.list_pending())
            .unwrap_or_default(),
        None => vec![],
    };
    let page = html! {
        (DOCTYPE)
        html {
            head { title { "ACP approvals" }
                style { "body{font:15px system-ui;margin:2rem;max-width:760px} .card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:10px 0} button{margin-right:8px;padding:6px 12px} .meta{color:#666;font-size:.85em}" } }
            body {
                h1 { "Pending approvals" }
                @if items.is_empty() { p { "No pending approvals." } }
                @for a in &items {
                    div.card {
                        div { b { (a.tool) } }
                        // maud auto-escapes: attacker-controlled presented context cannot inject markup (M4.5)
                        div.meta { "presented: " (a.presented.to_string()) }
                        div.meta { "id: " (a.id) }
                        form method="post" action=(format!("/approvals/{}/approve", a.id)) style="display:inline" { button { "Approve" } }
                        form method="post" action=(format!("/approvals/{}/deny", a.id)) style="display:inline" { button { "Deny" } }
                    }
                }
            }
        }
    };
    Html(page.into_string())
}

async fn approve(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    resolve(&st, &id, true);
    Redirect::to("/")
}
async fn deny(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    resolve(&st, &id, false);
    Redirect::to("/")
}
fn resolve(st: &AppState, id: &str, ok: bool) {
    if let Some(p) = &st.approvals {
        if let Ok(store) = acp_approvals::ApprovalStore::open(p) {
            let _ = store.resolve(id, ok, "web-user", "web");
        }
    }
}

async fn policy_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.policy {
        Some((hash, body)) => {
            Json(serde_json::json!({"hash": hash, "body": body, "max_staleness_s": 30}))
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no policy configured").into_response(),
    }
}

async fn verify(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.ledger {
        Some(l) => match acp_ledger::verify_file(l) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => Json(serde_json::json!({"ok": false, "detail": e})).into_response(),
        },
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}

async fn metrics(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let pack = st
        .ledger
        .as_ref()
        .and_then(|l| acp_ledger::export_file(l).ok());
    let recs = pack
        .as_ref()
        .and_then(|p| p["records"].as_array().cloned())
        .unwrap_or_default();
    let mut decisions = 0u64;
    let mut verdicts = std::collections::BTreeMap::<String, u64>::new();
    for r in &recs {
        if let Some(j) = r["canonical"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            if j["type"] == "decision" {
                decisions += 1;
                *verdicts
                    .entry(
                        j["decision"]["verdict"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string(),
                    )
                    .or_default() += 1;
            }
        }
    }
    let mut out = String::new();
    out.push_str("# HELP acp_records_total Evidence records in the ledger.\n# TYPE acp_records_total counter\n");
    out.push_str(&format!("acp_records_total {}\n", recs.len()));
    out.push_str("# HELP acp_decisions_total Policy decisions recorded.\n# TYPE acp_decisions_total counter\n");
    out.push_str(&format!("acp_decisions_total {decisions}\n"));
    out.push_str("# HELP acp_decisions_by_verdict Decisions by verdict.\n# TYPE acp_decisions_by_verdict counter\n");
    for (v, n) in &verdicts {
        out.push_str(&format!(
            "acp_decisions_by_verdict{{verdict=\"{v}\"}} {n}\n"
        ));
    }
    ([("content-type", "text/plain; version=0.0.4")], out)
}

async fn report(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st
        .ledger
        .as_ref()
        .and_then(|l| acp_ledger::export_file(l).ok())
    {
        Some(pack) => {
            let recs = pack["records"].as_array().cloned().unwrap_or_default();
            let mut verdicts = std::collections::BTreeMap::<String, u64>::new();
            let mut outcomes = std::collections::BTreeMap::<String, u64>::new();
            let (mut decisions, mut with_rule) = (0u64, 0u64);
            for r in &recs {
                if let Some(json) = r["canonical"]
                    .as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                {
                    match json["type"].as_str() {
                        Some("decision") => {
                            decisions += 1;
                            let v = json["decision"]["verdict"]
                                .as_str()
                                .unwrap_or("?")
                                .to_string();
                            *verdicts.entry(v).or_default() += 1;
                            if json["decision"]["rule_id"].is_string() {
                                with_rule += 1;
                            }
                        }
                        Some("outcome") => {
                            let k = json["kind"].as_str().unwrap_or("?").to_string();
                            *outcomes.entry(k).or_default() += 1;
                        }
                        _ => {}
                    }
                }
            }
            let coverage = if decisions > 0 {
                with_rule as f64 / decisions as f64
            } else {
                0.0
            };
            Json(serde_json::json!({
                "records": recs.len(),
                "decisions": decisions,
                "billable_units": decisions,
                "verdicts": verdicts,
                "outcomes": outcomes,
                "policy_coverage": (coverage * 1000.0).round() / 1000.0
            }))
            .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}

/// F11: a single causally-ordered timeline (by HLC) over the evidence ledger, so an investigator
/// sees one ordered view even across proxies.
async fn timeline(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.ledger.as_ref() {
        Some(path) => match acp_ledger::ordered_by_hlc(path) {
            Ok(rows) => {
                let entries: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|(seq, hlc)| serde_json::json!({"seq": seq, "hlc": hlc}))
                    .collect();
                Json(serde_json::json!({"count": entries.len(), "timeline": entries}))
            }
            Err(e) => Json(serde_json::json!({"error": e})),
        },
        None => Json(serde_json::json!({"error": "no ledger configured"})),
    }
}

/// H0.7: record a self-governance change (policy/key/RBAC/approver/break-glass) to the tamper-
/// evident meta-audit log. Body: {kind, actor, reason, before?, after?}.
async fn record_meta(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let Some(meta) = st.meta.as_ref() else {
        return Json(serde_json::json!({"ok": false, "detail": "meta-audit not configured"}));
    };
    let kind = match body.get("kind").and_then(|v| v.as_str()) {
        Some("policy_change") => acp_core::metaaudit::MetaKind::PolicyChange,
        Some("key_rotation") => acp_core::metaaudit::MetaKind::KeyRotation,
        Some("rbac_change") => acp_core::metaaudit::MetaKind::RbacChange,
        Some("approver_group_change") => acp_core::metaaudit::MetaKind::ApproverGroupChange,
        Some("break_glass_engage") => acp_core::metaaudit::MetaKind::BreakGlassEngage,
        Some("break_glass_revert") => acp_core::metaaudit::MetaKind::BreakGlassRevert,
        _ => return Json(serde_json::json!({"ok": false, "detail": "unknown kind"})),
    };
    let actor = body.get("actor").and_then(|v| v.as_str()).unwrap_or("unknown");
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let ev = match acp_core::metaaudit::MetaEvent::new(kind, actor, reason, now_ms()) {
        Ok(e) => e.transition(
            body.get("before").and_then(|v| v.as_str()),
            body.get("after").and_then(|v| v.as_str()),
        ),
        Err(e) => return Json(serde_json::json!({"ok": false, "detail": e})),
    };
    let mut l = meta.lock().unwrap();
    let id = format!("meta-{}", l.size() + 1);
    let _ = l.append(&id, "meta", &ev.to_record(), None);
    Json(serde_json::json!({"ok": true, "id": id, "size": l.size()}))
}

/// H0.7: the meta-audit log status, verifiable like any evidence.
async fn meta_audit(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.meta.as_ref() {
        Some(meta) => {
            let l = meta.lock().unwrap();
            Json(serde_json::json!({"configured": true, "size": l.size(), "verified": l.verify().is_ok()}))
        }
        None => Json(serde_json::json!({"configured": false})),
    }
}

/// Recent governed decisions (tool, verdict, agent, hlc) for the console evidence view.
async fn evidence_recent(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let recs = match st.ledger.as_ref().and_then(|p| acp_ledger::export_file(p).ok()) {
        Some(pack) => pack.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default(),
        None => vec![],
    };
    let mut out: Vec<serde_json::Value> = Vec::new();
    for r in recs.iter().rev() {
        let canon = r.get("canonical").and_then(|c| c.as_str()).unwrap_or("");
        let bytes = match hex::decode(canon) { Ok(b) => b, Err(_) => continue };
        let rec: serde_json::Value = match serde_json::from_slice(&bytes) { Ok(v) => v, Err(_) => continue };
        if rec.get("type").and_then(|t| t.as_str()) != Some("decision") { continue; }
        out.push(serde_json::json!({
            "seq": r.get("seq"),
            "tool": rec.pointer("/action/tool"),
            "resource": rec.pointer("/action/resource"),
            "operation": rec.pointer("/action/operation"),
            "verdict": rec.pointer("/decision/verdict"),
            "agent": rec.get("agent_id"),
            "principal": rec.pointer("/principal/id"),
            "principal_verified": rec.pointer("/principal/verified"),
            "hlc": rec.get("hlc"),
        }));
        if out.len() >= 25 { break; }
    }
    Json(serde_json::json!({"evidence": out}))
}

/// Pending approvals as JSON (for the console).
async fn approvals_pending(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let items = match &st.approvals {
        Some(p) => acp_approvals::ApprovalStore::open(p).and_then(|s| s.list_pending()).unwrap_or_default(),
        None => vec![],
    };
    let list: Vec<_> = items.iter().map(|a| serde_json::json!({"id": a.id, "tool": a.tool})).collect();
    Json(serde_json::json!({"pending": list}))
}

/// Registered apps (read-only view for the console).
async fn apps(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(store) = &st.store {
        match store.list_apps().await {
            Ok(apps) => return Json(serde_json::json!({"apps": apps})).into_response(),
            Err(e) => return Json(serde_json::json!({"apps": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.apps().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"owner":a.owner})).collect();
            Json(serde_json::json!({"apps": list})).into_response()
        }
        _ => Json(serde_json::json!({"apps": []})).into_response(),
    }
}

/// Registered agents (read-only).
async fn agents(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(store) = &st.store {
        match store.list_agents().await {
            Ok(agents) => return Json(serde_json::json!({"agents": agents})).into_response(),
            Err(e) => return Json(serde_json::json!({"agents": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.agents().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"app_id":a.app_id,"active":a.active})).collect();
            Json(serde_json::json!({"agents": list})).into_response()
        }
        _ => Json(serde_json::json!({"agents": []})).into_response(),
    }
}

/// Current deployed signed policy (version/hash/author) from the policy store.
async fn policy_store_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.policy_store.as_ref().map(|p| acp_policy::store::current_info(p)) {
        Some(Ok(v)) => Json(v),
        _ => Json(serde_json::json!({"version": 0})),
    }
}

/// Load-or-create the Ed25519 signer used to sign console-initiated deployments. Persisted next to
/// the store so the signed manifest stays verifiable across restarts. The proxy trusts the pubkey
/// embedded in current.json (tamper-evidence of the file against the signed hash).
/// Sign endpoint dispositions with a key kept next to the enrollment log (created 0600 if absent).
fn enroll_signer(path: &str) -> acp_core::sign::Ed25519Signer {
    let key_path = format!("{path}.key");
    match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            acp_core::sign::Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            s
        }
    }
}

fn load_enrollment(path: &str) -> acp_core::enrollment::EnrollmentLog {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn ai_kind_str(ep: &str) -> (String, String) {
    // (kind, provider) from the discovery classifier; falls back to a generic endpoint.
    match acp_core::discovery::classify_ai(ep) {
        Some(ai) => {
            let kind = match ai.kind {
                acp_core::discovery::AiKind::ModelApi => "model-api",
                acp_core::discovery::AiKind::Mcp => "mcp",
            };
            (kind.to_string(), ai.provider)
        }
        None => ("endpoint".to_string(), "unclassified".to_string()),
    }
}

/// GET /endpoints: the latest disposition per registered AI endpoint, with the provider classified
/// (OpenAI / Anthropic / xAI / Google / ...), for the console to list.
async fn endpoints_list(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    // Config-driven store first (identity/endpoints in a DB). Falls back to the enrollment file.
    if let Some(store) = &st.store {
        let now = now_ms();
        return match store.list_endpoints().await {
            Ok(eps) => {
                let out: Vec<serde_json::Value> = eps
                    .iter()
                    .map(|e| {
                        let active = e.expires_ms == 0 || now < e.expires_ms as u64;
                        serde_json::json!({
                            "endpoint": e.endpoint, "provider": e.provider, "kind": e.kind,
                            "disposition": e.disposition, "operator": e.operator, "reason": e.reason,
                            "active": active, "verified": true,
                        })
                    })
                    .collect();
                Json(serde_json::json!({"configured": true, "endpoints": out})).into_response()
            }
            Err(e) => Json(serde_json::json!({"configured": true, "endpoints": [], "error": e})).into_response(),
        };
    }
    let path = match &st.enrollment {
        Some(p) => p.clone(),
        None => return Json(serde_json::json!({"configured": false, "endpoints": []})).into_response(),
    };
    let log = load_enrollment(&path);
    let mut by_ep: std::collections::BTreeMap<&str, &acp_core::enrollment::EndpointDisposition> =
        std::collections::BTreeMap::new();
    for d in &log.dispositions {
        match by_ep.get(d.endpoint.as_str()) {
            Some(existing) if existing.decided_ms >= d.decided_ms => {}
            _ => {
                by_ep.insert(&d.endpoint, d);
            }
        }
    }
    let now = now_ms();
    let out: Vec<serde_json::Value> = by_ep
        .values()
        .map(|d| {
            let (_kind, provider) = ai_kind_str(&d.endpoint);
            let (dispo, active) = match d.disposition {
                acp_core::enrollment::Disposition::Enroll => ("govern", true),
                acp_core::enrollment::Disposition::Quarantine => ("block", true),
                acp_core::enrollment::Disposition::AcceptRisk { expires_ms } => ("accept-risk", now < expires_ms),
            };
            serde_json::json!({
                "endpoint": d.endpoint, "provider": provider, "kind": d.kind,
                "disposition": dispo, "operator": d.operator, "reason": d.reason,
                "active": active, "verified": d.verify(),
            })
        })
        .collect();
    Json(serde_json::json!({"configured": true, "endpoints": out})).into_response()
}

/// POST /endpoints/register: record a signed disposition for an AI endpoint. Body:
/// {endpoint, disposition: govern|block|accept-risk, reason}. The provider is classified server-side,
/// and the record is stored in the control-plane DB when --store is set, else the enrollment file.
async fn endpoints_register(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) {
        return r;
    }
    let endpoint = body.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if endpoint.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "endpoint is required"})).into_response();
    }
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let now = now_ms();
    let (disposition, dispo_str, expires): (acp_core::enrollment::Disposition, &str, i64) =
        match body.get("disposition").and_then(|v| v.as_str()).unwrap_or("govern") {
            "govern" | "enroll" => (acp_core::enrollment::Disposition::Enroll, "govern", 0),
            "block" | "quarantine" => (acp_core::enrollment::Disposition::Quarantine, "block", 0),
            "accept-risk" => {
                let e = now + 30 * 24 * 3600 * 1000;
                (acp_core::enrollment::Disposition::AcceptRisk { expires_ms: e }, "accept-risk", e as i64)
            }
            other => return Json(serde_json::json!({"ok": false, "error": format!("unknown disposition '{other}'")})).into_response(),
        };
    let (kind, provider) = ai_kind_str(&endpoint);

    if let Some(store) = &st.store {
        let signer = enroll_signer(&st.cp_key);
        let mut log = acp_core::enrollment::EnrollmentLog::new();
        let d = log.record(&signer, &endpoint, &kind, disposition, "console", &reason, now).clone();
        return match store
            .upsert_endpoint(&endpoint, &kind, &provider, dispo_str, "console", &reason, d.decided_ms as i64, expires, &d.pubkey_hex, &d.sig_hex)
            .await
        {
            Ok(()) => Json(serde_json::json!({"ok": true, "endpoint": endpoint, "provider": provider, "kind": kind})).into_response(),
            Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
        };
    }

    let path = match &st.enrollment {
        Some(p) => p.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no store configured (--store or --enrollment)"})).into_response(),
    };
    let mut log = load_enrollment(&path);
    let signer = enroll_signer(&path);
    log.record(&signer, &endpoint, &kind, disposition, "console", &reason, now);
    match serde_json::to_string_pretty(&log) {
        Ok(s) => {
            if std::fs::write(&path, s).is_err() {
                return Json(serde_json::json!({"ok": false, "error": "cannot write enrollment store"})).into_response();
            }
        }
        Err(_) => return Json(serde_json::json!({"ok": false, "error": "serialise enrollment"})).into_response(),
    }
    Json(serde_json::json!({"ok": true, "endpoint": endpoint, "provider": provider, "kind": kind})).into_response()
}

/// Random hex, for generated ids and one-time agent tokens.
fn rand_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    let _ = getrandom::getrandom(&mut b);
    hex::encode(b)
}

/// POST /agents/verify: the enforcement path verifies an agent by id + token against the store, so a
/// DB-registered agent is honoured without a registry file. Returns the display identity when valid.
/// Ungated: it only confirms a token the caller already holds.
async fn agent_verify(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let token_sha = acp_core::canonical::sha256_hex_bytes(token.as_bytes());
    match store.verify_agent_identity(id, &token_sha).await {
        Ok(Some((agent, app_id, app))) => Json(serde_json::json!({"ok": true, "verified": true, "agent": agent, "app_id": app_id, "app": app})).into_response(),
        Ok(None) => Json(serde_json::json!({"ok": true, "verified": false})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /apps: register an application in the control-plane store. Body: {name, owner}.
async fn app_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = format!("app-{}", rand_hex(6));
    match store.add_app(&id, &name, &owner, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "name": name})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /agents: register an agent. Body: {app_id, name}. Returns a one-time token (stored hashed).
async fn agent_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let app_id = body.get("app_id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if app_id.is_empty() || name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "app_id and name are required"})).into_response(); }
    let id = format!("agt-{}", rand_hex(6));
    let token = rand_hex(24);
    let token_sha = acp_core::canonical::sha256_hex_bytes(token.as_bytes());
    match store.add_agent(&id, &app_id, &name, &token_sha, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "token": token, "note": "store this token now; it is not shown again"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /agents/:id/deactivate: revoke an agent.
async fn agent_deactivate(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    match store.deactivate_agent(&id).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

const GRC_KINDS: &[&str] = &["assessment", "conformity", "risk", "model-card", "use-case", "attestation", "aibom"];

fn grc_doc(id: &str, kind: &str, subject: &str, title: &str, status: &str, body: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "kind": kind, "subject": subject, "title": title, "status": status, "body": body})
}

/// GET /grc: list all governance records (the console groups them by kind). Each is re-verified
/// against its embedded public key, so the "signed" state shown is checked, not asserted.
async fn grc_list(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"records": []})).into_response() };
    match store.list_grc(None).await {
        Ok(recs) => {
            let out: Vec<serde_json::Value> = recs.iter().map(|r| {
                let doc = grc_doc(&r.id, &r.kind, &r.subject, &r.title, &r.status, &r.body);
                let verified = hex::decode(&r.pubkey_hex).ok().zip(hex::decode(&r.sig_hex).ok())
                    .map(|(pk, sig)| acp_core::sign::verify_ed25519(&pk, &acp_core::canonical::canonical_bytes(&doc), &sig))
                    .unwrap_or(false);
                serde_json::json!({
                    "id": r.id, "kind": r.kind, "subject": r.subject, "title": r.title,
                    "status": r.status, "body": r.body, "operator": r.operator,
                    "created_ms": r.created_ms, "verified": verified,
                })
            }).collect();
            Json(serde_json::json!({"records": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"records": [], "error": e})).into_response(),
    }
}

/// POST /grc: create a signed governance record. Body: {kind, subject, title, status, body}.
async fn grc_create(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !GRC_KINDS.contains(&kind.as_str()) {
        return Json(serde_json::json!({"ok": false, "error": format!("unknown kind '{kind}'; expected one of {GRC_KINDS:?}")})).into_response();
    }
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("open").to_string();
    // body field may be a string or an object; store a string.
    let doc_body = match body.get("body") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
        None => String::new(),
    };
    let id = format!("grc-{}", rand_hex(6));
    let now = now_ms();
    let doc = grc_doc(&id, &kind, &subject, &title, &status, &doc_body);
    let signer = enroll_signer(&st.cp_key);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, &kind, &subject, &title, &status, &doc_body, "console", now as i64, &pubkey_hex, &sig_hex).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "kind": kind})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /grc/:id/status: advance a record's status (e.g. use-case lifecycle, risk treatment).
async fn grc_status(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if status.is_empty() { return Json(serde_json::json!({"ok": false, "error": "status is required"})).into_response(); }
    match store.update_grc_status(&id, &status).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "status": status})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
fn deploy_signer(store_dir: &str) -> acp_core::sign::Ed25519Signer {
    let key_path = format!("{store_dir}/deploy.key");
    let _ = std::fs::create_dir_all(store_dir);
    match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            acp_core::sign::Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            s
        }
    }
}

/// The rules of the current deployed policy, with app/agent ids resolved to registered names, so the
/// console can show which rule governs which app and agent. Read-only projection of the signed file.
async fn policy_store_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let src = match st.policy_store.as_ref().map(|p| acp_policy::store::current_source(p)) {
        Some(Ok(s)) => s,
        _ => return Json(serde_json::json!({"rules": [], "count": 0})),
    };
    let pol = match acp_policy::dsl::parse_str(&src) {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({"rules": [], "count": 0, "error": e.to_string()})),
    };
    let reg = st.registry.as_ref().and_then(|p| acp_registry::Registry::load(p).ok());
    let app_name = |m: &Option<String>| -> Option<String> {
        let id = m.as_deref()?;
        reg.as_ref()
            .and_then(|r| r.apps().into_iter().find(|a| a.id == id).map(|a| a.name.clone()))
            .or_else(|| Some(id.to_string()))
    };
    let agent_name = |m: &Option<String>| -> Option<String> {
        let id = m.as_deref()?;
        reg.as_ref()
            .and_then(|r| r.agents().into_iter().find(|a| a.id == id).map(|a| a.name.clone()))
            .or_else(|| Some(id.to_string()))
    };
    let _ = &app_name; // app is display-only now; kept for team resolution elsewhere.
    use acp_policy::dsl::ObligationKind;
    let rules: Vec<_> = pol
        .rules
        .iter()
        .map(|r| {
            let verdict = serde_json::to_value(&r.verdict)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "allow".to_string());
            let obligations: Vec<String> = r
                .obligations
                .iter()
                .map(|o| match o.kind {
                    ObligationKind::Confirm => "confirm".to_string(),
                    ObligationKind::Redact => format!("redact({})", o.fields.join(",")),
                    ObligationKind::RateLimit => {
                        format!("rate_limit({}/{}ms)", o.max.unwrap_or(0), o.window_ms.unwrap_or(0))
                    }
                })
                .collect();
            serde_json::json!({
                "id": r.id,
                "agent": r.when.agent,
                "agent_label": agent_name(&r.when.agent),
                "principal": r.when.principal,
                "resource": r.when.resource,
                "operation": r.when.operation,
                "tool": r.when.tool,
                "verdict": verdict,
                "obligations": obligations,
                "approvers": r.approvers,
                "reason": r.reason,
            })
        })
        .collect();
    let default = serde_json::to_value(&pol.default)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "allow".to_string());
    Json(serde_json::json!({"rules": rules, "count": pol.rules.len(), "default": default}))
}

/// Deploy a policy from the console: validate, version, sign, and write it to the store the proxy
/// watches. A policy that does not compile is rejected before anything is written; the proxy
/// hot-reloads the new version only after verifying the signature.
async fn policy_store_deploy(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) {
        return r;
    }
    let store = match &st.policy_store {
        Some(s) => s.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no policy store configured"})).into_response(),
    };
    let src = body.get("policy").and_then(|v| v.as_str()).unwrap_or("");
    let author = body
        .get("author")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("console");
    if src.trim().is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "policy source is empty"})).into_response();
    }
    let signer = deploy_signer(&store);
    match acp_policy::store::deploy(src, &store, &signer, author) {
        Ok(d) => Json(serde_json::json!({"ok": true, "version": d.version, "hash": d.hash})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// Current break-glass status (what the proxy would be applying).
async fn break_glass_status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    use acp_core::breakglass::GrantFile;
    match &st.break_glass_file {
        Some(f) => match std::fs::read(f).ok().and_then(|b| serde_json::from_slice::<GrantFile>(&b).ok()) {
            Some(g) => Json(serde_json::json!({
                "active": true, "mode": g.mode, "scope": g.scope, "reason": g.reason, "actor": g.actor, "signed": !g.sig.is_empty()
            })),
            None => Json(serde_json::json!({"active": false, "configured": true})),
        },
        None => Json(serde_json::json!({"active": false, "configured": false})),
    }
}

/// Engage break-glass: write a (signed, if a key is configured) scoped grant to the file the proxy
/// watches. This is a controlled action; the proxy applies it on its next decision.
async fn break_glass_engage(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::BreakGlass) {
        return r;
    }
    use acp_core::breakglass::{GrantFile, Mode, Scope};
    let file = match &st.break_glass_file {
        Some(f) => f.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no break-glass file configured"})).into_response(),
    };
    let mode = match body.get("mode").and_then(|v| v.as_str()).and_then(Mode::parse) {
        Some(m) => m,
        None => return Json(serde_json::json!({"ok": false, "error": "invalid mode (lockdown_all|disable_enforce|emergency_bypass)"})).into_response(),
    };
    let scope = Scope::parse(body.get("scope").and_then(|v| v.as_str()).unwrap_or("global"));
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if reason.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "reason is required"})).into_response();
    }
    let actor = body.get("actor").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("console").to_string();
    let ttl_ms = body
        .get("ttl_ms")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
        .filter(|n| *n > 0)
        .unwrap_or(3_600_000);
    let mut grant = GrantFile::new_scoped(mode, scope, &reason, &actor, now_ms(), ttl_ms);
    if let Some(seed) = &st.break_glass_seed {
        grant.sign(&acp_core::sign::Ed25519Signer::from_seed(seed));
    }
    let json = serde_json::to_string_pretty(&grant).unwrap();
    if std::fs::write(&file, json).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "cannot write grant file"})).into_response();
    }
    Json(serde_json::json!({"ok": true, "mode": grant.mode, "scope": grant.scope, "signed": !grant.sig.is_empty()})).into_response()
}

/// Clear break-glass: remove the grant file (the proxy reverts to normal on its next decision).
async fn break_glass_clear(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::BreakGlass) {
        return r;
    }
    if let Some(f) = &st.break_glass_file {
        let _ = std::fs::remove_file(f);
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

/// DEV ONLY: issue a mock bearer token for a role, so the console can authenticate without real
/// Entra during local use. Present only when --dev-auth is set.
async fn dev_token(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> impl IntoResponse {
    match st.auth.as_ref().and_then(|a| a.dev.as_ref()) {
        Some(mock) => {
            let role = q.get("role").map(String::as_str).unwrap_or("PolicyAdmin");
            let tok = mock.issue("dev-oid", "dev@local", "common", &[role], now_ms(), 3600);
            Json(serde_json::json!({"token": tok, "role": role}))
        }
        None => Json(serde_json::json!({"error": "dev auth not enabled"})),
    }
}

/// Serve the axum app over mutual TLS: present the server cert and REQUIRE a client cert signed by
/// the ACP CA, so only enrolled components can reach the control API.
async fn serve_mtls(addr: &str, app: Router, ca: &str, cert: &str, key: &str) {
    acp_mtls::ensure_provider();
    let ca = std::fs::read(ca).expect("read tls-ca");
    let cert = std::fs::read(cert).expect("read tls-cert");
    let key = std::fs::read(key).expect("read tls-key");
    let cfg = acp_mtls::server_config(&ca, &cert, &key).expect("mtls server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t, // handshake fails here for a client with no/bad cert (mutual auth)
                Err(_) => return,
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// B1: an enrolled proxy posts a heartbeat (and, implicitly, that it is serving governed traffic).
async fn heartbeat(State(st): State<Arc<AppState>>, Path(proxy): Path<String>) -> impl IntoResponse {
    // A heartbeat asserts liveness only. Decision-stall detection (traffic expected but no
    // decisions) is driven separately by the evidence stream, so a freshly-enrolled proxy that has
    // not yet gated a call is not falsely flagged.
    st.liveness.lock().unwrap().heartbeat(&proxy, now_ms());
    Json(serde_json::json!({"ok": true, "proxy": proxy}))
}

/// B3: a proxy reports a governance event (e.g. fail_open, deny) for spike detection.
async fn record_event(State(st): State<Arc<AppState>>, Path(kind): Path<String>) -> impl IntoResponse {
    const WINDOW_MS: u64 = 60_000;
    const THRESHOLD: usize = 10; // >10 of one kind per minute trips
    let mut map = st.spikes.lock().unwrap();
    map.entry(kind.clone())
        .or_insert_with(|| acp_core::anomaly::SpikeDetector::new(WINDOW_MS, THRESHOLD))
        .record(now_ms());
    Json(serde_json::json!({"ok": true, "kind": kind}))
}

/// B3: which event kinds are currently spiking (over threshold in the window). A fail-open surge
/// or a deny surge pages here.
async fn alerts(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let now = now_ms();
    let mut map = st.spikes.lock().unwrap();
    let mut tripped: Vec<String> = Vec::new();
    for (k, d) in map.iter_mut() {
        if d.tripped(now) {
            tripped.push(k.clone());
        }
    }
    tripped.sort();
    Json(serde_json::json!({"tripped": tripped, "healthy": tripped.is_empty()}))
}

/// B1: report proxies that have gone silent (no heartbeat within the window). A gap here is the
/// dead-man's-switch firing: an enrolled proxy that was killed or silenced.
async fn liveness(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    const WINDOW_MS: u64 = 30_000;
    let gaps = st.liveness.lock().unwrap().scan(now_ms(), WINDOW_MS);
    let gaps: Vec<String> = gaps.iter().map(|g| format!("{g:?}")).collect();
    Json(serde_json::json!({"window_ms": WINDOW_MS, "gaps": gaps, "healthy": gaps.is_empty()}))
}

/// Resolve when the process is asked to stop, so the server can drain rather than drop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining in-flight requests");
}
