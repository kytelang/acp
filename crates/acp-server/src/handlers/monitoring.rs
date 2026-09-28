//! Control-plane HTTP handlers: monitoring.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// C1: report this replica's HA leadership view (is it the leader, who holds the lease, the fencing
/// token). The console and ops can see which node is active without guessing.
pub(crate) async fn leader_status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let (is_leader, holder, token) = st.lease.lock().unwrap().clone();
    Json(serde_json::json!({"node": st.node_id, "leader": is_leader, "holder": holder, "token": token}))
}

/// G1: load the per-tenant oversight thresholds from control_state, or the defaults.
pub(crate) async fn load_oversight_config(st: &Arc<AppState>, tenant: &str) -> acp_core::oversight::OversightConfig {
    if let Some(store) = &st.store {
        if let Ok(Some(v)) = store.get_state(&format!("oversight:config:{tenant}")).await {
            if let Ok(cfg) = serde_json::from_str(&v) { return cfg; }
        }
    }
    acp_core::oversight::OversightConfig::default()
}

/// Read the resolved decisions from the approvals store (sync rusqlite), newest first.
pub(crate) fn oversight_decisions(st: &Arc<AppState>) -> Vec<acp_core::oversight::Decision> {
    match &st.approvals {
        Some(p) => match acp_core::approvals::ApprovalStore::open(p) {
            Ok(store) => store.list_resolved(5000).unwrap_or_default(),
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    }
}

/// G1: GET /oversight - the oversight-quality profile of every approver (EU AI Act Art. 14). Read-only.
pub(crate) async fn oversight_get(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &principal);
    let cfg = load_oversight_config(&st, &tenant).await;
    let profiles = acp_core::oversight::analyze(&oversight_decisions(&st), &cfg);
    let flagged = profiles.iter().filter(|p| p.flagged).count();
    Json(serde_json::json!({"config": cfg, "approvers": profiles, "flagged": flagged})).into_response()
}

/// G1: POST /oversight/config - update the thresholds; the change is written to the meta-audit log.
pub(crate) async fn oversight_config_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &principal);
    let before = load_oversight_config(&st, &tenant).await;
    // Start from the current config; override only the fields present in the body.
    let mut cfg = before.clone();
    // Accept numbers or numeric strings (the console sends datastar string signals).
    let as_f = |b: &serde_json::Value, k: &str| b.get(k).and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    let as_u = |b: &serde_json::Value, k: &str| b.get(k).and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
    if let Some(v) = as_u(&body, "min_decisions") { cfg.min_decisions = v as u32; }
    if let Some(v) = as_f(&body, "approve_rate") { cfg.approve_rate = v; }
    if let Some(v) = as_u(&body, "fast_ms") { cfg.fast_ms = v; }
    if let Some(v) = as_f(&body, "fast_fraction") { cfg.fast_fraction = v; }
    if let Some(v) = as_u(&body, "bulk_window_ms") { cfg.bulk_window_ms = v; }
    if let Some(v) = as_u(&body, "bulk_count") { cfg.bulk_count = v as u32; }
    let cfg_json = serde_json::to_string(&cfg).unwrap_or_default();
    if let Err(e) = store.put_state(&format!("oversight:config:{tenant}"), &cfg_json, now_ms() as i64).await {
        return Json(serde_json::json!({"ok": false, "error": e})).into_response();
    }
    // Audit the config change in the meta-audit log (a governance-configuration change).
    if let Some(meta) = st.meta.as_ref() {
        let actor_s = actor_of(&principal);
        if let Ok(ev) = acp_core::metaaudit::MetaEvent::new(acp_core::metaaudit::MetaKind::RbacChange, actor_s.as_str(), "oversight thresholds updated", now_ms()) {
            let ev = ev.transition(Some(&serde_json::to_string(&before).unwrap_or_default()), Some(&cfg_json));
            let mut l = meta.lock().unwrap();
            let id = format!("meta-{}", l.size() + 1);
            let _ = l.append(&id, "meta", &ev.to_record(), None);
        }
    }
    Json(serde_json::json!({"ok": true, "config": cfg})).into_response()
}

/// G1: POST /oversight/scan - analyse and write a signed governance finding per flagged approver.
pub(crate) async fn oversight_scan(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &principal);
    let cfg = load_oversight_config(&st, &tenant).await;
    let profiles = acp_core::oversight::analyze(&oversight_decisions(&st), &cfg);
    let mut written = Vec::new();
    for p in profiles.iter().filter(|p| p.flagged) {
        let doc_body = serde_json::to_string(p).unwrap_or_default();
        let subject = "human-oversight";
        let title = format!("Oversight weakness: {}", p.approver);
        let status = "flagged";
        let id = format!("grc-{}", rand_hex(6));
        let doc = grc_doc(&id, "attestation", subject, &title, status, &doc_body);
        let signer = tenant_signer(&st.cp_key, &tenant);
        let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
        let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
        let sig_hex = hex::encode(sig);
        if store.add_grc(&id, "attestation", subject, &title, status, &doc_body, &operator, now_ms() as i64, &pubkey_hex, &sig_hex, "[]", "{}", "", 0, status, &tenant).await.is_ok() {
            written.push(serde_json::json!({"id": id, "approver": p.approver, "reasons": p.reasons}));
        }
    }
    Json(serde_json::json!({"ok": true, "flagged": written.len(), "findings": written})).into_response()
}

/// B1: an enrolled proxy posts a heartbeat (and, implicitly, that it is serving governed traffic).
pub(crate) async fn heartbeat(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(proxy): Path<String>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let ts = now_ms();
    st.liveness.lock().unwrap().heartbeat(&proxy, ts);
    // C1: persist one row per proxy so the dead-man's-switch survives a restart and replicas do not
    // clobber each other's view.
    if let Some(store) = &st.store {
        let _ = store.put_state(&format!("liveness:{proxy}"), &ts.to_string(), ts as i64).await;
    }
    Json(serde_json::json!({"ok": true, "proxy": proxy})).into_response()
}

/// F3: a PEP reports classifier hit-rate counts per class (counts only, never raw values).
pub(crate) async fn monitor_drift_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let class = body.get("class").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if class.is_empty() { return Json(serde_json::json!({"ok": false, "error": "class is required"})).into_response(); }
    let hits = body.get("hits").and_then(|v| v.as_i64()).unwrap_or(0);
    let total = body.get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    match store.report_drift(&class, hits, total, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// F3: per-class live hit-rate + baseline, with a drifted flag from `acp_core::drift`.
pub(crate) async fn monitor_drift_get(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"classes": []})).into_response() };
    let rows = match store.list_drift().await { Ok(r) => r, Err(e) => return Json(serde_json::json!({"classes": [], "error": e})).into_response() };
    let mut mon = acp_core::drift::DriftMonitor::new(0.15);
    for (class, _h, _t, base) in &rows { mon.set_baseline(class, *base); }
    // Feed the accumulated counts back in as observations so drifts() can judge live vs baseline.
    for (class, h, t, _b) in &rows {
        for i in 0..*t { mon.observe(class, i < *h); }
    }
    let drifted: std::collections::HashSet<String> = mon.drifts(5).into_iter().map(|d| d.class).collect();
    let out: Vec<serde_json::Value> = rows.iter().map(|(class, h, t, base)| {
        let rate = if *t > 0 { *h as f64 / *t as f64 } else { 0.0 };
        serde_json::json!({"class": class, "hits": h, "total": t, "rate": rate, "baseline": base, "drifted": drifted.contains(class)})
    }).collect();
    Json(serde_json::json!({"classes": out})).into_response()
}

/// F3: a PEP reports a data-class -> tool lineage edge (counts only).
pub(crate) async fn monitor_lineage_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let dc = body.get("data_class").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let tool = body.get("tool").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if dc.is_empty() || tool.is_empty() { return Json(serde_json::json!({"ok": false, "error": "data_class and tool are required"})).into_response(); }
    let count = body.get("count").and_then(|v| v.as_i64()).unwrap_or(1);
    match store.report_lineage(&dc, &tool, count, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

pub(crate) async fn monitor_lineage_get(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"edges": []})).into_response() };
    match store.list_lineage().await {
        Ok(edges) => Json(serde_json::json!({"edges": edges.iter().map(|(d,t,c)| serde_json::json!({"data_class": d, "tool": t, "count": c})).collect::<Vec<_>>()})).into_response(),
        Err(e) => Json(serde_json::json!({"edges": [], "error": e})).into_response(),
    }
}

/// B3: which event kinds are currently spiking (over threshold in the window). A fail-open surge
/// or a deny surge pages here.
pub(crate) async fn alerts(State(st): State<Arc<AppState>>) -> impl IntoResponse {
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
pub(crate) async fn liveness(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    const WINDOW_MS: u64 = 30_000;
    let gaps = st.liveness.lock().unwrap().scan(now_ms(), WINDOW_MS);
    let gaps: Vec<String> = gaps.iter().map(|g| format!("{g:?}")).collect();
    Json(serde_json::json!({"window_ms": WINDOW_MS, "gaps": gaps, "healthy": gaps.is_empty()}))
}
