//! Control-plane HTTP handlers: tickets.
use crate::state::AppState;
use crate::common::*;
use crate::handlers::approvals::resolve;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// T3: inbound ticketing callback. A ticket system (Jira/ServiceNow) posts a resolution here to close
/// the loop: resolve an approval hold, or advance a GRC record's status. HMAC-verified with the
/// webhook secret over the raw body (x-acp-signature: t=..,v1=..); rejected if the secret is unset or
/// the signature is bad. Body: {action: "approve"|"deny"|"grc-status", id, status?}.
pub(crate) async fn ticket_callback(State(st): State<Arc<AppState>>, headers: HeaderMap, raw: axum::body::Bytes) -> Response {
    let secret = match &st.webhook_secret {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::FORBIDDEN, Json(serde_json::json!({"ok": false, "error": "ticket callbacks require --webhook-secret"}))).into_response(),
    };
    let sig = headers.get("x-acp-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    let body_str = String::from_utf8_lossy(&raw).to_string();
    if !acp_core::webhook::verify_webhook(secret.as_bytes(), sig, &body_str, (now_ms() / 1000) as u64, 300) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false, "error": "signature verification failed"}))).into_response();
    }
    let body: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|_| serde_json::json!({}));
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "id is required"})).into_response(); }
    let status = body.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tenant = tenant_of(&headers, &None);
    match apply_ticket_resolution(&st, &action, &id, status.as_deref(), &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "action": action})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// Named Jira adapter: accept a Jira `issue_updated` webhook, map it via acp_core::ticket::jira to the
/// generic ticket vocabulary, and apply it. Verified with the same HMAC (x-acp-signature over the raw
/// body, keyed by --webhook-secret) as /tickets/callback: point a Jira Automation / a thin relay that
/// signs the forwarded payload at this endpoint. A webhook that does not concern ACP (no acp label) or
/// is not a terminal transition is accepted as a no-op.
pub(crate) async fn ticket_jira(State(st): State<Arc<AppState>>, headers: HeaderMap, raw: axum::body::Bytes) -> Response {
    let secret = match &st.webhook_secret {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::FORBIDDEN, Json(serde_json::json!({"ok": false, "error": "Jira callbacks require --webhook-secret"}))).into_response(),
    };
    let sig = headers.get("x-acp-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    let body_str = String::from_utf8_lossy(&raw).to_string();
    if !acp_core::webhook::verify_webhook(secret.as_bytes(), sig, &body_str, (now_ms() / 1000) as u64, 300) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false, "error": "signature verification failed"}))).into_response();
    }
    let payload: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|_| serde_json::json!({}));
    let resolution = match acp_core::ticket::jira::map_jira_webhook(&payload) {
        Some(r) => r,
        None => return Json(serde_json::json!({"ok": true, "applied": false, "note": "no ACP label or non-terminal transition"})).into_response(),
    };
    let tenant = tenant_of(&headers, &None);
    match apply_ticket_resolution(&st, &resolution.action, &resolution.id, resolution.status.as_deref(), &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "applied": true, "id": resolution.id, "action": resolution.action})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// M2/T3: apply one ticket resolution (idempotent): resolve an approval hold, or advance + re-sign a GRC
/// record's status. Shared by the inbound callback and the poll loop.
pub(crate) async fn apply_ticket_resolution(st: &Arc<AppState>, action: &str, id: &str, status: Option<&str>, tenant: &str) -> Result<(), String> {
    match action {
        "approve" | "deny" => { resolve(st, id, action == "approve", "ticket-system"); Ok(()) }
        "grc-status" => {
            let store = st.store.as_ref().ok_or_else(|| "no --store configured".to_string())?;
            let status = status.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).ok_or_else(|| "status is required".to_string())?;
            let rec = match store.get_grc(id).await? {
                Some(r) if r.tenant == tenant => r,
                _ => return Err("no such record".to_string()),
            };
            let doc = grc_doc(&rec.id, &rec.kind, &rec.subject, &rec.title, &status, &rec.body);
            let signer = tenant_signer(&st.cp_key, tenant);
            let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
            let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
            let sig_hex = hex::encode(sig);
            store.update_grc_signed(id, &status, &rec.body, &status, &pubkey_hex, &sig_hex).await
        }
        _ => Err("unknown action (approve|deny|grc-status)".to_string()),
    }
}
