//! Control-plane HTTP handlers: assurance.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// G19: GET /trust -> a signed, public summary of the controls in force, verifiable with the pubkey.
pub(crate) async fn trust_summary(State(st): State<Arc<AppState>>) -> Response {
    let packs = match &st.store { Some(s) => s.list_packs().await.map(|p| p.len()).unwrap_or(0), None => 0 };
    let body = serde_json::json!({
        "product": "Varman (ACP)",
        "generated_ms": now_ms(),
        "controls": {
            "resource_boundary_authorization": st.policy.is_some(),
            "rbac": st.auth.is_some(),
            "tamper_evident_evidence": st.ledger.is_some(),
            "content_firewall": true,
            "high_availability": st.node_id.len() > 0,
            "control_packs_loaded": packs,
        },
        "verify": "acp verify-pack against the published evidence pack, public key only",
    });
    let signer = enroll_signer(&st.cp_key);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&body));
    Json(serde_json::json!({"summary": body, "pubkey_hex": hex::encode(acp_core::sign::Signer::public_key(&signer)), "sig_hex": hex::encode(sig)})).into_response()
}

/// G18: GET /audit/pack?from=<ms>&to=<ms> -> a signed evidence pack for a window, downloadable and
/// verifiable with the public key alone. Auditor scope (Export).
pub(crate) async fn audit_pack(State(st): State<Arc<AppState>>, headers: HeaderMap, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let from: i64 = q.get("from").and_then(|v| v.parse().ok()).unwrap_or(0);
    let to: i64 = q.get("to").and_then(|v| v.parse().ok()).unwrap_or(i64::MAX);
    let recs = store.list_ingested(10000).await.unwrap_or_default();
    let window: Vec<serde_json::Value> = recs.iter().filter(|r| r.created_ms >= from && r.created_ms <= to)
        .map(|r| serde_json::json!({"decision_id": r.decision_id, "verdict": r.verdict, "record": r.record, "created_ms": r.created_ms})).collect();
    let body = serde_json::json!({"pack": "audit-window", "from_ms": from, "to_ms": to, "count": window.len(), "records": window});
    let signer = enroll_signer(&st.cp_key);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&body));
    Json(serde_json::json!({"body": body, "pubkey_hex": hex::encode(acp_core::sign::Signer::public_key(&signer)), "sig_hex": hex::encode(sig)})).into_response()
}

/// G9: POST /memory/write {content, store_id?} -> scan content the agent wants to persist; block/flag
/// planted instructions, and record the write for later incident tracing. Gated by the report token.
pub(crate) async fn memory_write(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let policy = acp_core::content::ContentPolicy::default();
    let cv = acp_core::content::scan_with_ml(&policy, content, None);
    let kinds: Vec<String> = cv.findings.iter().map(|f| f.kind.clone()).collect();
    // Record the write (blocked or allowed) in the fleet-evidence store for traceability.
    if let Some(store) = &st.store {
        let did = format!("mem-{}", rand_hex(8));
        let rec = serde_json::json!({"type": "memory-write", "blocked": cv.block, "kinds": kinds, "store_id": body.get("store_id").cloned().unwrap_or(serde_json::Value::Null), "ts_ms": now_ms()});
        let signer = enroll_signer(&st.cp_key);
        let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&rec));
        let _ = store.add_ingested(&did, "memory", "memory-write", if cv.block {"deny"} else {"allow"}, &rec.to_string(), "control-plane", now_ms() as i64, &hex::encode(acp_core::sign::Signer::public_key(&signer)), &hex::encode(sig)).await;
    }
    Json(serde_json::json!({"ok": true, "blocked": cv.block, "findings": kinds})).into_response()
}

/// G7: POST /retrieval/check {principal, groups, docs:[{doc_id,allow_principals,allow_groups}]} -> which
/// docs the principal may read and which are filtered (permission-aware retrieval).
pub(crate) async fn retrieval_check(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = body.get("principal").and_then(|v| v.as_str()).unwrap_or("");
    let groups: Vec<String> = body.get("groups").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    // Inline docs, else load the document-ACL export from the configured connector source (file or URL).
    let mut docs: Vec<acp_core::retrieval::DocAcl> = body.get("docs").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
    if docs.is_empty() {
        if let Some(src) = &st.retrieval_source {
            let raw = if src.starts_with("http") {
                reqwest::Client::new().get(src).send().await.ok().map(|r| async move { r.text().await.unwrap_or_default() })
            } else { None };
            let text = if let Some(fut) = raw { fut.await } else { std::fs::read_to_string(src).unwrap_or_default() };
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) { docs = acp_core::retrieval::from_export(&v); }
        }
    }
    let (visible, filtered) = acp_core::retrieval::filter(principal, &groups, &docs);
    Json(serde_json::json!({"ok": true, "visible": visible.iter().map(|d| d.doc_id.clone()).collect::<Vec<_>>(), "filtered": filtered})).into_response()
}

/// G8: POST /delegation/verify {chain:[{actor,scopes}], scope?} -> the effective scopes of a delegation
/// chain (and whether it permits a given scope), enforcing monotonic narrowing.
pub(crate) async fn delegation_verify(State(_st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
    let hops: Vec<acp_core::registry::chain::Hop> = body.get("chain").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|h| {
        let actor = h.get("actor")?.as_str()?.to_string();
        let scopes: Vec<String> = h.get("scopes").and_then(|s| s.as_array()).map(|x| x.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        Some(acp_core::registry::chain::Hop { actor, scopes: scopes.into_iter().collect() })
    }).collect()).unwrap_or_default();
    match acp_core::registry::chain::effective_scopes(&hops) {
        Ok(eff) => {
            let permits = body.get("scope").and_then(|v| v.as_str()).map(|sc| eff.contains(sc));
            Json(serde_json::json!({"ok": true, "effective_scopes": eff.into_iter().collect::<Vec<_>>(), "permits": permits})).into_response()
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": format!("{e:?}")})).into_response(),
    }
}

/// G11: POST /credential/stamp {content_b64, model, disclosure} -> a signed content credential.
pub(crate) async fn credential_stamp(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let content_b64 = body.get("content_b64").and_then(|v| v.as_str()).unwrap_or("");
    use base64::Engine;
    let content = base64::engine::general_purpose::STANDARD.decode(content_b64).unwrap_or_default();
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let disclosure = body.get("disclosure").and_then(|v| v.as_str()).unwrap_or("This content was generated by AI.");
    let signer = enroll_signer(&st.cp_key);
    let cred = acp_core::credential::stamp(&content, model, disclosure, now_ms(), &signer);
    Json(serde_json::json!({"ok": true, "credential": cred})).into_response()
}

/// G17: POST /redteam/target {url, min_catch?} -> run the injection attack corpus against a customer's
/// own agent endpoint and record the outcome as signed evidence. Each attack is POSTed as {input}; the
/// target is "caught" if it refuses (non-2xx) or returns {blocked:true} / an error. Best-effort: the
/// target contract is the customer's; adapt the marker as needed.
pub(crate) async fn redteam_target(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { Ok(p) => p, Err(r) => return r };
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let url = match body.get("url").and_then(|v| v.as_str()) { Some(u) if !u.is_empty() => u.to_string(), _ => return Json(serde_json::json!({"ok": false, "error": "url is required"})).into_response() };
    let min_catch = body.get("min_catch").and_then(|v| v.as_f64()).unwrap_or(0.9);
    let corpus = acp_core::redteam::corpus();
    let attacks: Vec<&acp_core::redteam::Case> = corpus.iter().filter(|s| s.is_attack).collect();
    let client = reqwest::Client::new();
    let (mut caught, mut total) = (0u32, 0u32);
    for a in &attacks {
        total += 1;
        let resp = client.post(&url).json(&serde_json::json!({"input": a.text})).send().await;
        let blocked = match resp {
            Ok(r) => {
                if !r.status().is_success() { true }
                else { r.json::<serde_json::Value>().await.ok().map(|v| v.get("blocked").and_then(|b| b.as_bool()).unwrap_or(false) || v.get("error").is_some()).unwrap_or(false) }
            }
            Err(_) => false,
        };
        if blocked { caught += 1; }
    }
    let catch_rate = if total > 0 { caught as f64 / total as f64 } else { 0.0 };
    let passed = catch_rate >= min_catch;
    let status = if passed { "passed" } else { "failed" };
    let doc_body = serde_json::json!({"kind": "red-team-target", "target": url, "attacks": total, "caught": caught, "catch_rate": catch_rate, "min_catch": min_catch}).to_string();
    let operator = actor_of(&principal);
    let tenant = tenant_of(&headers, &principal);
    let gid = format!("grc-{}", rand_hex(6));
    let doc = grc_doc(&gid, "attestation", "customer-agent", "Red-team target run", status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let _ = store.add_grc(&gid, "attestation", "customer-agent", "Red-team target run", status, &doc_body, &operator, now_ms() as i64, &hex::encode(acp_core::sign::Signer::public_key(&signer)), &hex::encode(sig), "[]", "{}", "", 0, status, &tenant).await;
    Json(serde_json::json!({"ok": true, "id": gid, "attacks": total, "caught": caught, "catch_rate": catch_rate, "passed": passed})).into_response()
}

/// B4: run the red-team corpus against the current content-firewall configuration, then store the
/// result as a signed GRC attestation record (so runs accumulate as a time series). A run below
/// --min-catch is stored with status "failed" so it is visibly flagged. A scheduled runner (cron)
/// simply calls this endpoint on an interval.
pub(crate) async fn redteam_run(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditFirewall) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let min_catch = body.get("min_catch").and_then(|v| v.as_f64()).unwrap_or(0.9) as f32;
    // Build the content policy from the current firewall config (+ threat signatures + ML).
    let tenant = tenant_of(&headers, &principal);
    let cfg = store.get_firewall_config(&tenant).await.ok().flatten();
    let (policy, ml) = match &cfg {
        Some(c) => {
            let mut topics: Vec<String> = serde_json::from_str(&c.deny_topics).unwrap_or_default();
            let threat: Vec<String> = serde_json::from_str(&c.threat_signatures).unwrap_or_default();
            topics.extend(threat);
            let pol = acp_core::content::ContentPolicy { block_injection: true, block_secrets: c.block_secrets, redact_pii: true, denied_topics: topics, block_toxicity: c.block_toxicity };
            let ml = if !c.model.is_empty() { acp_core::content::LinearScorer::from_json(&c.model).ok() } else { None };
            (pol, ml)
        }
        None => (acp_core::content::ContentPolicy::default(), None),
    };
    let report = acp_core::redteam::run(&policy, ml.as_ref(), &acp_core::redteam::corpus());
    let passed = report.catch_rate >= min_catch;
    let status = if passed { "passed" } else { "failed" };
    let doc_body = serde_json::json!({
        "kind": "red-team",
        "catch_rate": report.catch_rate,
        "attacks": report.attacks,
        "caught": report.caught,
        "fpr": report.fpr,
        "false_positives": report.false_positives,
        "min_catch": min_catch,
        "missed": report.missed.len(),
    }).to_string();
    let id = format!("grc-{}", rand_hex(6));
    let now = now_ms();
    let tenant = tenant_of(&headers, &principal);
    let doc = grc_doc(&id, "attestation", "content-firewall", "Red-team run", status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, "attestation", "content-firewall", "Red-team run", status, &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, "[]", "{}", "", 0, status, &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "status": status, "catch_rate": report.catch_rate, "attacks": report.attacks, "caught": report.caught, "fpr": report.fpr, "passed": passed})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// B4: the recent red-team runs (attestation GRC records for content-firewall), newest first, with
/// their metrics parsed out and each record's signature re-verified.
pub(crate) async fn redteam_runs(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"runs": []})).into_response() };
    match store.list_grc(&tenant, Some("attestation")).await {
        Ok(recs) => {
            let mut out: Vec<serde_json::Value> = Vec::new();
            for r in recs.iter().rev() {
                if r.subject != "content-firewall" { continue; }
                let doc = grc_doc(&r.id, &r.kind, &r.subject, &r.title, &r.status, &r.body);
                let verified = hex::decode(&r.pubkey_hex).ok().zip(hex::decode(&r.sig_hex).ok())
                    .map(|(pk, sig)| acp_core::sign::verify_ed25519(&pk, &acp_core::canonical::canonical_bytes(&doc), &sig))
                    .unwrap_or(false);
                let body: serde_json::Value = serde_json::from_str(&r.body).unwrap_or_else(|_| serde_json::json!({}));
                out.push(serde_json::json!({
                    "id": r.id, "status": r.status, "created_ms": r.created_ms, "verified": verified,
                    "catch_rate": body.get("catch_rate"), "attacks": body.get("attacks"), "caught": body.get("caught"),
                    "fpr": body.get("fpr"), "min_catch": body.get("min_catch"),
                }));
                if out.len() >= 20 { break; }
            }
            Json(serde_json::json!({"runs": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"runs": [], "error": e})).into_response(),
    }
}
