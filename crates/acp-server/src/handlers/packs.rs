//! Control-plane HTTP handlers: packs.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;

/// A4: the built-in signed control packs (EU AI Act, NIST AI RMF, ISO 42001), signed with the
/// control-plane key so an operator can load them via POST /packs. Derived from the control library.
pub(crate) async fn packs_available(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let signer = enroll_signer(&st.cp_key);
    let signed: Vec<serde_json::Value> = acp_core::pack::builtin_packs(now_ms())
        .iter().map(|p| serde_json::to_value(p.sign(&signer)).unwrap_or_default()).collect();
    Json(serde_json::json!({"packs": signed}))
}

/// A4: load a signed control pack. The signature is verified before storing; a tampered pack (body
/// no longer matches the signature) is rejected with a clear error. Idempotent by pack id.
pub(crate) async fn pack_load(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let signed: acp_core::pack::SignedPack = match serde_json::from_value(body.clone()) {
        Ok(s) => s,
        Err(e) => return Json(serde_json::json!({"ok": false, "error": format!("not a signed pack: {e}")})).into_response(),
    };
    if !acp_core::pack::verify(&signed) {
        return Json(serde_json::json!({"ok": false, "error": "pack signature verification FAILED (tampered or wrong key); rejected"})).into_response();
    }
    let p = &signed.pack;
    let id = p.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "pack has no id"})).into_response(); }
    let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Store the EXACT signed document so re-verification on read reproduces the signed bytes.
    let doc_json = p.to_string();
    match store.add_pack(&id, &version, &doc_json, &signed.pubkey_hex, &signed.sig_hex, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "version": version})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// A4: list loaded control packs, each re-verified against its embedded key (verified: true/false).
pub(crate) async fn packs_list(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"packs": []})).into_response() };
    match store.list_packs().await {
        Ok(rows) => {
            let out: Vec<serde_json::Value> = rows.iter().map(|r| {
                let doc: serde_json::Value = serde_json::from_str(&r.doc_json).unwrap_or_else(|_| serde_json::json!({}));
                let frameworks = doc.get("frameworks").cloned().unwrap_or_else(|| serde_json::json!([]));
                let count = doc.get("controls").and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0);
                // Re-verify the stored signature against the exact signed document.
                let verified = hex::decode(&r.pubkey_hex).ok().zip(hex::decode(&r.sig_hex).ok())
                    .map(|(pk, sig)| acp_core::sign::verify_ed25519(&pk, &acp_core::canonical::canonical_bytes(&doc), &sig))
                    .unwrap_or(false);
                serde_json::json!({"id": r.id, "version": r.version, "frameworks": frameworks, "controls": count, "verified": verified})
            }).collect();
            Json(serde_json::json!({"packs": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"packs": [], "error": e})).into_response(),
    }
}

/// A4: the merged control library from loaded packs (falls back to the built-in library when none are
/// loaded). This is the library the assessment engine (A1) draws on. Optional ?framework= filter.
pub(crate) async fn controls_list(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> Response {
    let fw = q.get("framework").map(String::as_str);
    // Prefer loaded packs; fall back to the built-in library.
    let mut controls: Vec<serde_json::Value> = Vec::new();
    if let Some(store) = &st.store {
        if let Ok(rows) = store.list_packs().await {
            for r in &rows {
                if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&r.doc_json) {
                    if let Some(arr) = doc.get("controls").and_then(|c| c.as_array()) {
                        controls.extend(arr.clone());
                    }
                }
            }
        }
    }
    if controls.is_empty() {
        controls = acp_core::controls::library().iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect();
    }
    if let Some(fw) = fw {
        controls.retain(|c| c.get("framework").and_then(|v| v.as_str()) == Some(fw));
    }
    Json(serde_json::json!({"controls": controls})).into_response()
}

/// B5: the built-in sample threat pack, signed with the control-plane key so an operator can load it.
pub(crate) async fn threat_pack_available(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let signer = enroll_signer(&st.cp_key);
    let pack = acp_core::threatfeed::builtin_threat_pack(now_ms(), now_ms());
    Json(serde_json::to_value(pack.sign(&signer)).unwrap_or_default())
}

/// B5: load a signed threat pack. The signature is verified before storing; a tampered pack is
/// rejected. On success the firewall_config feed version is bumped and the signatures stored, so every
/// acp-agent applies them on its next firewall fetch.
pub(crate) async fn threat_pack_load(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let signed: acp_core::threatfeed::SignedThreatPack = match serde_json::from_value(body.clone()) {
        Ok(s) => s,
        Err(e) => return Json(serde_json::json!({"ok": false, "error": format!("not a signed threat pack: {e}")})).into_response(),
    };
    if !acp_core::threatfeed::verify(&signed) {
        return Json(serde_json::json!({"ok": false, "error": "threat pack signature verification FAILED (tampered or wrong key); rejected"})).into_response();
    }
    let version = signed.pack.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
    let sigs = signed.pack.get("signatures").cloned().unwrap_or_else(|| serde_json::json!([]));
    let sigs_json = sigs.to_string();
    let tenant = tenant_of(&headers, &None);
    match store.set_firewall_threat(&tenant, version, &sigs_json, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "feed_version": version, "signatures": sigs.as_array().map(|a| a.len()).unwrap_or(0)})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
