//! Control-plane HTTP handlers: breakglass.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// Current break-glass status (what the proxy would be applying).
pub(crate) async fn break_glass_status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
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
pub(crate) async fn break_glass_engage(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::BreakGlass) {
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
pub(crate) async fn break_glass_clear(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::BreakGlass) {
        return r;
    }
    if let Some(f) = &st.break_glass_file {
        let _ = std::fs::remove_file(f);
    }
    Json(serde_json::json!({"ok": true})).into_response()
}
