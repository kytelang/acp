//! acp-server: the control-plane HTTP service (v1.1 seed, single-tenant).
//!
//! Serves the web approval inbox (M4.3), the current policy endpoint (M2.2), a read-only
//! evidence-verify endpoint, and a basic governance report. HTML is rendered with `maud`, which
//! auto-escapes, so attacker-controlled content in the inbox cannot inject markup (M4.5).
//! Multi-tenant Postgres, per-tenant keys, and SSO are the next layer (v1.1.1-1.1.3 / H1).

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
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
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8787".to_string();
    let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
    let mut meta_ledger: Option<String> = None;
    let mut registry: Option<String> = None;
    let mut policy_store: Option<String> = None;
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
            other => {
                eprintln!("acp-server: unknown option '{other}'");
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
                eprintln!("acp-server: could not load policy {p}");
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
                let _ = std::fs::write(&key_path, s.seed());
                Box::new(s)
            }
        };
        match acp_ledger::Ledger::open(&path, signer) {
            Ok(l) => Some(std::sync::Mutex::new(l)),
            Err(e) => {
                eprintln!("acp-server: could not open meta-ledger {path}: {e}");
                None
            }
        }
    });

    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
        liveness: std::sync::Mutex::new(acp_core::liveness::GapDetector::new()),
        spikes: std::sync::Mutex::new(std::collections::HashMap::new()),
        meta,
        registry,
        policy_store,
    });
    let app = Router::new()
        .route("/", get(inbox))
        .route("/healthz", get(|| async { "ok" }))
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
        .route("/approvals/pending", get(approvals_pending))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("acp-server: listening on http://{addr}");
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
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.apps().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"owner":a.owner})).collect();
            Json(serde_json::json!({"apps": list}))
        }
        _ => Json(serde_json::json!({"apps": []})),
    }
}

/// Registered agents (read-only).
async fn agents(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.agents().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"app_id":a.app_id,"active":a.active})).collect();
            Json(serde_json::json!({"agents": list}))
        }
        _ => Json(serde_json::json!({"agents": []})),
    }
}

/// Current deployed signed policy (version/hash/author) from the policy store.
async fn policy_store_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.policy_store.as_ref().map(|p| acp_policy::store::current_info(p)) {
        Some(Ok(v)) => Json(v),
        _ => Json(serde_json::json!({"version": 0})),
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
    eprintln!("acp-server: shutdown signal received, draining in-flight requests");
}
