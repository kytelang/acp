//! Control-plane HTTP handlers: firewall.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// GET /firewall/config: the central content-firewall configuration (toggles, denied topics, and the
/// ML model content), so a workstation PEP fetches everything from the control plane instead of
/// carrying local files. Ungated (same trust as the governed rule set). Returns a safe default when
/// no config has been set yet.
pub(crate) async fn firewall_config_get(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let default = serde_json::json!({"enabled": false, "block_secrets": false, "deny_topics": [], "model": "", "scan_url": "", "block_on_scanner_error": false, "block_toxicity": false, "updated_ms": 0});
    let store = match &st.store { Some(s) => s, None => return Json(default).into_response() };
    match store.get_firewall_config(&tenant).await {
        Ok(Some(c)) => {
            let mut topics: Vec<serde_json::Value> = serde_json::from_str::<Vec<serde_json::Value>>(&c.deny_topics).unwrap_or_default();
            let threat: Vec<serde_json::Value> = serde_json::from_str::<Vec<serde_json::Value>>(&c.threat_signatures).unwrap_or_default();
            // B5: merge threat-feed signatures into the served deny_topics so every PEP applies them on
            // its next fetch, without any PEP change. threat_signatures is also returned for display.
            topics.extend(threat.iter().cloned());
            Json(serde_json::json!({"enabled": c.enabled, "block_secrets": c.block_secrets, "deny_topics": topics, "model": c.model, "scan_url": c.scan_url, "block_on_scanner_error": c.block_on_scanner_error, "block_toxicity": c.block_toxicity, "feed_version": c.feed_version, "threat_signatures": threat, "updated_ms": c.updated_ms})).into_response()
        }
        Ok(None) => Json(default).into_response(),
        Err(e) => Json(serde_json::json!({"error": e})).into_response(),
    }
}

/// POST /firewall/config: set the central content-firewall configuration from the console
/// (RBAC-gated on EditPolicy). Body: {enabled, block_secrets, deny_topics:[...], model:"<json or empty>"}.
pub(crate) async fn firewall_config_set(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let block_secrets = body.get("block_secrets").and_then(|v| v.as_bool()).unwrap_or(false);
    let deny_topics_json = match body.get("deny_topics") {
        Some(v) if v.is_array() => v.to_string(),
        _ => "[]".to_string(),
    };
    // model may be a JSON string of the model content, or an object we serialise.
    let model = match body.get("model") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    let scan_url = body.get("scan_url").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let block_on_scanner_error = body.get("block_on_scanner_error").and_then(|v| v.as_bool()).unwrap_or(false);
    let block_toxicity = body.get("block_toxicity").and_then(|v| v.as_bool()).unwrap_or(false);
    let tenant = tenant_of(&headers, &None);
    match store.set_firewall_config(&tenant, enabled, block_secrets, &deny_topics_json, &model, &scan_url, block_on_scanner_error, block_toxicity, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// GET /intercept/rules: the interception rule registry derived from the stored endpoint
/// dispositions, so acp-intercept can pull its governed set from the control plane instead of a
/// static file. Latest disposition per endpoint wins; expired accept-risk exceptions are dropped;
/// destinations that match no rule hit the default (flag-and-pass: recorded as shadow AI, then
/// passed). Ungated: it returns the same governed set as GET /endpoints, no secrets.
pub(crate) async fn intercept_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    use acp_core::enrollment::{Disposition, EndpointDisposition, EnrollmentLog};
    let now = now_ms();
    let mut dispositions: Vec<EndpointDisposition> = Vec::new();
    if let Some(store) = &st.store {
        match store.list_endpoints().await {
            Ok(eps) => {
                for e in eps {
                    let disposition = match e.disposition.as_str() {
                        "block" | "quarantine" => Disposition::Quarantine,
                        "accept-risk" => Disposition::AcceptRisk { expires_ms: e.expires_ms as u64 },
                        _ => Disposition::Enroll,
                    };
                    dispositions.push(EndpointDisposition {
                        endpoint: e.endpoint,
                        kind: e.kind,
                        disposition,
                        operator: e.operator,
                        reason: e.reason,
                        decided_ms: e.decided_ms as u64,
                        pubkey_hex: e.pubkey_hex,
                        sig_hex: e.sig_hex,
                    });
                }
            }
            Err(e) => return Json(serde_json::json!({"error": e})).into_response(),
        }
    } else if let Some(path) = &st.enrollment {
        dispositions = load_enrollment(path).dispositions;
    }
    dispositions.retain(|d| match d.disposition {
        Disposition::AcceptRisk { expires_ms } => now < expires_ms,
        _ => true,
    });
    let log = EnrollmentLog { dispositions };
    let mut registry = acp_core::interception::registry_from_enrollment(
        &log,
        acp_core::interception::DefaultAction::FlagAndPass,
    );
    // Merge operator-authored rules ahead of the enrolment-derived ones (first match wins).
    if let Some(store) = &st.store {
        if let Ok(rules) = store.list_firewall_rules().await {
            let mut authored: Vec<acp_core::interception::EndpointRule> = Vec::new();
            for r in rules {
                let match_v: serde_json::Value = serde_json::from_str(&r.match_json).unwrap_or_else(|_| serde_json::json!({}));
                let classify_v = if r.classify.is_empty() { serde_json::Value::Null } else { serde_json::json!(r.classify) };
                let rule_v = serde_json::json!({"id": r.id, "match": match_v, "classify": classify_v, "action": r.action});
                if let Ok(rule) = serde_json::from_value::<acp_core::interception::EndpointRule>(rule_v) {
                    authored.push(rule);
                }
            }
            if !authored.is_empty() {
                authored.extend(registry.endpoints);
                registry.endpoints = authored;
            }
        }
    }
    Json(registry).into_response()
}

pub(crate) const FW_ACTIONS: &[&str] = &["inspect-prompt", "govern-tool-call", "dlp-only", "block", "pass"];

/// GET /firewall/rules: operator-authored interception rules (for the console Firewall rules screen).
pub(crate) async fn firewall_rules_list(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"rules": []})).into_response() };
    match store.list_firewall_rules().await {
        Ok(rules) => {
            let out: Vec<serde_json::Value> = rules.iter().map(|r| {
                let m: serde_json::Value = serde_json::from_str(&r.match_json).unwrap_or_else(|_| serde_json::json!({}));
                serde_json::json!({"id": r.id, "match": m, "classify": r.classify, "action": r.action})
            }).collect();
            Json(serde_json::json!({"rules": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"rules": [], "error": e})).into_response(),
    }
}

/// POST /firewall/rules: add an operator rule (RBAC-gated on EditPolicy). Body: a match predicate set
/// (host_contains|host_suffix|host_exact|sni|path_contains|path_prefix|port) + action + optional classify.
pub(crate) async fn firewall_rules_add(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let mut m = serde_json::Map::new();
    for k in ["host_contains", "host_suffix", "host_exact", "sni", "path_contains", "path_prefix"] {
        if let Some(v) = body.get(k).and_then(|x| x.as_str()) { if !v.trim().is_empty() { m.insert(k.to_string(), serde_json::json!(v.trim())); } }
    }
    if let Some(p) = body.get("port").and_then(|x| x.as_u64()) { m.insert("port".to_string(), serde_json::json!(p)); }
    if m.is_empty() { return Json(serde_json::json!({"ok": false, "error": "at least one match predicate is required"})).into_response(); }
    let action = body.get("action").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if !FW_ACTIONS.contains(&action.as_str()) {
        return Json(serde_json::json!({"ok": false, "error": format!("unknown action '{action}'; expected one of {FW_ACTIONS:?}")})).into_response();
    }
    let classify = body.get("classify").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let id = format!("fwr-{}", rand_hex(6));
    let match_json = serde_json::Value::Object(m).to_string();
    match store.add_firewall_rule(&id, &match_json, &classify, &action, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /firewall/rules/:id/delete: remove an operator rule (RBAC-gated on EditPolicy).
pub(crate) async fn firewall_rules_delete(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    match store.delete_firewall_rule(&id).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
