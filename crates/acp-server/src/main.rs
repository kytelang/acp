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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    eprintln!("acp-server: listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
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

async fn report(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st
        .ledger
        .as_ref()
        .and_then(|l| acp_ledger::export_file(l).ok())
    {
        Some(pack) => {
            let recs = pack["records"].as_array().cloned().unwrap_or_default();
            let decisions = recs.iter().filter(|r| r["kind"] == "decision").count();
            let outcomes = recs.iter().filter(|r| r["kind"] == "outcome").count();
            Json(serde_json::json!({"records": recs.len(), "decisions": decisions, "outcomes": outcomes})).into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}
