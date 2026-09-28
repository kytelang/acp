//! Control-plane HTTP handlers: approvals.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use std::sync::Arc;
use maud::{html, DOCTYPE};

pub(crate) async fn inbox(State(st): State<Arc<AppState>>) -> Html<String> {
    let items = match &st.approvals {
        Some(p) => acp_core::approvals::ApprovalStore::open(p)
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

pub(crate) async fn approve(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::Approve) { Ok(p) => p, Err(r) => return r };
    resolve(&st, &id, true, &actor_of(&principal));
    Redirect::to("/").into_response()
}

pub(crate) async fn deny(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::Approve) { Ok(p) => p, Err(r) => return r };
    resolve(&st, &id, false, &actor_of(&principal));
    Redirect::to("/").into_response()
}

pub(crate) fn resolve(st: &AppState, id: &str, ok: bool, actor: &str) {
    if let Some(p) = &st.approvals {
        if let Ok(store) = acp_core::approvals::ApprovalStore::open(p) {
            let _ = store.resolve(id, ok, actor, "web");
        }
    }
}

/// F1: a PEP registers a step-up hold raised in the field, so it appears in the console Approvals
/// inbox and can be resolved centrally. Gated by the shared report token (PEP identity). Idempotent.
pub(crate) async fn approval_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let path = match &st.approvals { Some(p) => p.clone(), None => return Json(serde_json::json!({"ok": false, "error": "no approvals store"})).into_response() };
    let store = match acp_core::approvals::ApprovalStore::open(&path) { Ok(s) => s, Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = g("id");
    if id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "id is required"})).into_response(); }
    let presented = body.get("presented").cloned().unwrap_or_else(|| serde_json::json!({}));
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(15 * 60 * 1000);
    match store.request(&id, &g("session"), &g("principal"), &g("tool"), &g("arg_hash"), &presented, ttl_ms) {
        Ok(created) => Json(serde_json::json!({"ok": true, "id": id, "created": created})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// F1: the resolution state of a hold, so a PEP can poll for the console operator's decision.
pub(crate) async fn approval_status(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let path = match &st.approvals { Some(p) => p.clone(), None => return Json(serde_json::json!({"state": "unknown"})).into_response() };
    let store = match acp_core::approvals::ApprovalStore::open(&path) { Ok(s) => s, Err(_) => return Json(serde_json::json!({"state": "unknown"})).into_response() };
    match store.get(&id) {
        Ok(Some(v)) => Json(serde_json::json!({"state": v.state, "approver": v.approver})).into_response(),
        Ok(None) => Json(serde_json::json!({"state": "unknown"})).into_response(),
        Err(e) => Json(serde_json::json!({"state": "error", "error": e})).into_response(),
    }
}

/// Pending approvals as JSON (for the console).
pub(crate) async fn approvals_pending(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let items = match &st.approvals {
        Some(p) => acp_core::approvals::ApprovalStore::open(p).and_then(|s| s.list_pending()).unwrap_or_default(),
        None => vec![],
    };
    let list: Vec<_> = items.iter().map(|a| serde_json::json!({"id": a.id, "tool": a.tool})).collect();
    Json(serde_json::json!({"pending": list}))
}
