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
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8787".to_string();
    let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or(addr),
            "--approvals" => approvals = it.next().cloned(),
            "--policy" => policy_path = it.next().cloned(),
            "--ledger" => ledger = it.next().cloned(),
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

    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
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
