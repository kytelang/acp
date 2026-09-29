//! Control-plane HTTP handlers: endpoints.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

pub(crate) fn ai_kind_str(ep: &str) -> (String, String) {
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
pub(crate) async fn endpoints_list(State(st): State<Arc<AppState>>) -> impl IntoResponse {
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
pub(crate) async fn endpoints_register(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
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
        let d = log.record(&signer, &endpoint, &kind, disposition, &operator, &reason, now).clone();
        return match store
            .upsert_endpoint(&endpoint, &kind, &provider, dispo_str, &operator, &reason, d.decided_ms as i64, expires, &d.pubkey_hex, &d.sig_hex)
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
    log.record(&signer, &endpoint, &kind, disposition, &operator, &reason, now);
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

/// POST /endpoints/delete (EditPolicy). Body: {endpoint}. The endpoint host is the key.
pub(crate) async fn endpoint_delete(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let endpoint = body.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if endpoint.is_empty() { return Json(serde_json::json!({"ok": false, "error": "endpoint is required"})).into_response(); }
    match store.delete_endpoint(&endpoint).await { Ok(()) => Json(serde_json::json!({"ok": true})).into_response(), Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response() }
}
