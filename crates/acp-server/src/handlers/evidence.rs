//! Control-plane HTTP handlers: evidence.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

pub(crate) async fn verify(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.ledger {
        Some(l) => match acp_core::ledger::verify_file(l) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => Json(serde_json::json!({"ok": false, "detail": e})).into_response(),
        },
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}

/// H0.7: record a self-governance change (policy/key/RBAC/approver/break-glass) to the tamper-
/// evident meta-audit log. Body: {kind, actor, reason, before?, after?}.
pub(crate) async fn record_meta(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { Ok(p) => p, Err(r) => return r };
    let Some(meta) = st.meta.as_ref() else {
        return Json(serde_json::json!({"ok": false, "detail": "meta-audit not configured"})).into_response();
    };
    let kind = match body.get("kind").and_then(|v| v.as_str()) {
        Some("policy_change") => acp_core::metaaudit::MetaKind::PolicyChange,
        Some("key_rotation") => acp_core::metaaudit::MetaKind::KeyRotation,
        Some("rbac_change") => acp_core::metaaudit::MetaKind::RbacChange,
        Some("approver_group_change") => acp_core::metaaudit::MetaKind::ApproverGroupChange,
        Some("break_glass_engage") => acp_core::metaaudit::MetaKind::BreakGlassEngage,
        Some("break_glass_revert") => acp_core::metaaudit::MetaKind::BreakGlassRevert,
        _ => return Json(serde_json::json!({"ok": false, "detail": "unknown kind"})).into_response(),
    };
    let actor_s = actor_of(&principal);
    let actor = actor_s.as_str();
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let ev = match acp_core::metaaudit::MetaEvent::new(kind, actor, reason, now_ms()) {
        Ok(e) => e.transition(
            body.get("before").and_then(|v| v.as_str()),
            body.get("after").and_then(|v| v.as_str()),
        ),
        Err(e) => return Json(serde_json::json!({"ok": false, "detail": e})).into_response(),
    };
    let mut l = meta.lock().unwrap();
    let id = format!("meta-{}", l.size() + 1);
    let _ = l.append(&id, "meta", &ev.to_record(), None);
    Json(serde_json::json!({"ok": true, "id": id, "size": l.size()})).into_response()
}

/// H0.7: the meta-audit log status, verifiable like any evidence.
pub(crate) async fn meta_audit(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.meta.as_ref() {
        Some(meta) => {
            let l = meta.lock().unwrap();
            Json(serde_json::json!({"configured": true, "size": l.size(), "verified": l.verify().is_ok()}))
        }
        None => Json(serde_json::json!({"configured": false})),
    }
}

/// Recent governed decisions (tool, verdict, agent, hlc) for the console evidence view.
pub(crate) async fn evidence_recent(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A5: the raw decision detail (per-action tool/resource/principal) requires SeeArgs
    // (SecurityOfficer). Aggregate dashboards use ungated summary routes instead.
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::SeeArgs) { return r; }
    let recs = match st.ledger.as_ref().and_then(|p| acp_core::ledger::export_file(p).ok()) {
        Some(pack) => pack.get("records").and_then(|r| r.as_array()).cloned().unwrap_or_default(),
        None => vec![],
    };
    let mut out: Vec<serde_json::Value> = Vec::new();
    for r in recs.iter().rev() {
        let canon = r.get("canonical").and_then(|c| c.as_str()).unwrap_or("");
        let bytes = match hex::decode(canon) { Ok(b) => b, Err(_) => continue };
        let rec: serde_json::Value = match serde_json::from_slice(&bytes) { Ok(v) => v, Err(_) => continue };
        if rec.get("type").and_then(|t| t.as_str()) != Some("decision") { continue; }
        out.push(serde_json::json!({
            "seq": r.get("seq"),
            "tool": rec.pointer("/action/tool"),
            "resource": rec.pointer("/action/resource"),
            "operation": rec.pointer("/action/operation"),
            "verdict": rec.pointer("/decision/verdict"),
            "agent": rec.get("agent_id"),
            "principal": rec.pointer("/principal/id"),
            "principal_verified": rec.pointer("/principal/verified"),
            "hlc": rec.get("hlc"),
        }));
        if out.len() >= 25 { break; }
    }
    Json(serde_json::json!({"evidence": out})).into_response()
}

/// B3/E1: a PEP reports a governance event (deny, step_up, fail_open, ...) for spike detection and
/// the console violation feed. The body carries the redacted decision shape; the path is the kind.
pub(crate) async fn record_event(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(kind): Path<String>, body: Option<Json<serde_json::Value>>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    const WINDOW_MS: u64 = 60_000;
    const THRESHOLD: usize = 10; // >10 of one kind per minute trips
    let now = now_ms();
    {
        let mut map = st.spikes.lock().unwrap();
        map.entry(kind.clone())
            .or_insert_with(|| acp_core::anomaly::SpikeDetector::new(WINDOW_MS, THRESHOLD))
            .record(now);
    }
    // C1: persist one append-only row per spike event so alert state survives a restart; old keys are
    // pruned by the lease loop.
    if let Some(store) = &st.store {
        let _ = store.put_state(&format!("spike:{kind}:{now}"), "1", now as i64).await;
    }
    // Store a bounded, enriched copy for the console feed. The body never carries raw arguments.
    let mut ev = body.map(|Json(v)| v).unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = ev.as_object_mut() {
        obj.entry("kind".to_string()).or_insert(serde_json::json!(kind));
        obj.entry("ts_ms".to_string()).or_insert(serde_json::json!(now_ms()));
    }
    {
        let mut buf = st.events.lock().unwrap();
        buf.push_front(ev.clone());
        buf.truncate(500);
    }
    // Persist for the durable breach-and-violation report (best-effort).
    if let Some(store) = &st.store {
        let g = |k: &str| ev.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let id = format!("vio-{}", rand_hex(8));
        let _ = store.add_violation_event(&id, &kind, &g("proxy"), &g("agent"), &g("tool"), &g("verdict"), &g("rule_id"), &g("impact"), &g("outcome"), now_ms() as i64).await;
    }
    // G4: notify stakeholders of the violation (fields are JSON values, never interpolated).
    fire_webhook(&st, "violation", serde_json::json!({
        "kind": kind,
        "pep": ev.get("proxy").and_then(|v| v.as_str()).unwrap_or(""),
        "agent": ev.get("agent").and_then(|v| v.as_str()).unwrap_or(""),
        "tool": ev.get("tool").and_then(|v| v.as_str()).unwrap_or(""),
        "verdict": ev.get("verdict").and_then(|v| v.as_str()).unwrap_or(""),
    }));
    Json(serde_json::json!({"ok": true, "kind": kind})).into_response()
}

/// E1/E3: the most recent governance events reported by the PEPs, newest first, for the console
/// Violations feed. Read-only projection of the in-memory ring (bounded, best-effort).
pub(crate) async fn events_recent(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let buf = st.events.lock().unwrap();
    let out: Vec<serde_json::Value> = buf.iter().take(200).cloned().collect();
    Json(serde_json::json!({"events": out, "count": out.len()}))
}

/// E2: ingest PEP-reported decision records into the central, re-verifiable evidence store. The PEP is
/// authenticated by the shared report token; the control plane signs each record with its cp-key so
/// the central store is itself verifiable with the cp public key. Deduped by decision_id (idempotent).
pub(crate) async fn evidence_ingest(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let pep = body.get("pep").and_then(|v| v.as_str()).unwrap_or("pep").to_string();
    let recs: Vec<serde_json::Value> = match body.get("records").and_then(|v| v.as_array()) {
        Some(a) => a.clone(),
        None => vec![body.clone()],
    };
    let signer = enroll_signer(&st.cp_key);
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let now = now_ms();
    let mut count = 0usize;
    for r in recs {
        let did = r.get("decision_id").and_then(|v| v.as_str()).unwrap_or("");
        if did.is_empty() { continue; }
        let kind = r.get("kind").and_then(|v| v.as_str()).unwrap_or("decision");
        let verdict = r.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        let record = r.get("record").cloned().unwrap_or_else(|| serde_json::json!({}));
        let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&record));
        let sig_hex = hex::encode(sig);
        if let Ok(true) = store.add_ingested(did, &pep, kind, verdict, &record.to_string(), "control-plane", now as i64, &pubkey_hex, &sig_hex).await {
            count += 1;
        }
    }
    Json(serde_json::json!({"ok": true, "ingested": count})).into_response()
}

/// E2: the central fleet-evidence view, newest first, each re-verified against its embedded public key
/// (so the console shows a checked "verified" state, not an asserted one).
pub(crate) async fn evidence_ingested(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"records": []})).into_response() };
    match store.list_ingested(200).await {
        Ok(recs) => {
            let out: Vec<serde_json::Value> = recs.iter().map(|r| {
                let verified = serde_json::from_str::<serde_json::Value>(&r.record).ok()
                    .and_then(|doc| hex::decode(&r.pubkey_hex).ok().zip(hex::decode(&r.sig_hex).ok())
                        .map(|(pk, sig)| acp_core::sign::verify_ed25519(&pk, &acp_core::canonical::canonical_bytes(&doc), &sig)))
                    .unwrap_or(false);
                serde_json::json!({
                    "decision_id": r.decision_id, "pep": r.pep, "kind": r.kind, "verdict": r.verdict,
                    "record": r.record, "created_ms": r.created_ms, "verified": verified,
                })
            }).collect();
            Json(serde_json::json!({"records": out, "count": out.len()})).into_response()
        }
        Err(e) => Json(serde_json::json!({"records": [], "error": e})).into_response(),
    }
}
