//! Control-plane HTTP handlers: grc.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

pub(crate) const GRC_KINDS: &[&str] = &["assessment", "conformity", "risk", "model-card", "use-case", "attestation", "aibom", "fria", "incident"];

/// G5: POST /incident/promote {subject, title, deadline_ms?} -> open a signed incident case (a GRC
/// record of kind "incident") with a reporting deadline (EU AI Act Art. 73).
pub(crate) async fn incident_promote(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Serious incident").to_string();
    let now = now_ms();
    // EU AI Act Art. 73: initial report deadline; default 15 days.
    let due = body.get("deadline_ms").and_then(|v| v.as_i64()).unwrap_or(now as i64 + 15 * 86_400_000);
    let doc_body = serde_json::json!({"kind": "incident", "opened_ms": now, "deadline_ms": due, "source": body.get("source").cloned().unwrap_or(serde_json::Value::Null)}).to_string();
    let operator = actor_of(&principal);
    let tenant = tenant_of(&headers, &principal);
    let gid = format!("grc-{}", rand_hex(6));
    let doc = grc_doc(&gid, "incident", &subject, &title, "detected", &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    match store.add_grc(&gid, "incident", &subject, &title, "detected", &doc_body, &operator, now as i64, &hex::encode(acp_core::sign::Signer::public_key(&signer)), &hex::encode(sig), "[]", "{}", "", due, "detected", &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": gid, "deadline_ms": due})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}


/// GET /grc: list all governance records (the console groups them by kind). Each is re-verified
/// against its embedded public key, so the "signed" state shown is checked, not asserted.
pub(crate) async fn grc_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"records": []})).into_response() };
    match store.list_grc(&tenant, None).await {
        Ok(recs) => {
            let mut out: Vec<serde_json::Value> = Vec::with_capacity(recs.len());
            for r in &recs {
                let doc = grc_doc(&r.id, &r.kind, &r.subject, &r.title, &r.status, &r.body);
                let verified = hex::decode(&r.pubkey_hex).ok().zip(hex::decode(&r.sig_hex).ok())
                    .map(|(pk, sig)| acp_core::sign::verify_ed25519(&pk, &acp_core::canonical::canonical_bytes(&doc), &sig))
                    .unwrap_or(false);
                // A2: linked_refs are advisory and unsigned. We never trust or mutate the
                // payload; we only check whether each referenced decision id exists in the
                // central ledger, reporting verified_refs/total_refs.
                let refs: Vec<serde_json::Value> = serde_json::from_str(&r.linked_refs).unwrap_or_default();
                let total_refs = refs.len();
                let mut verified_refs = 0usize;
                for rf in &refs {
                    let did = rf.get("id").and_then(|v| v.as_str())
                        .or_else(|| rf.as_str()).unwrap_or("");
                    if !did.is_empty() && store.ingested_exists(did).await.unwrap_or(false) {
                        verified_refs += 1;
                    }
                }
                // A1: surface checklist progress (k/m controls done) and the assessment tier if the
                // signed body carries them, plus the workflow metadata (assignee/due/stage).
                let parsed: serde_json::Value = serde_json::from_str(&r.body).unwrap_or_else(|_| serde_json::json!({}));
                // G3: for a model-card, resolve its model/use-case/risk references.
                let mut links = serde_json::Value::Null;
                if r.kind == "model-card" {
                    let mid = parsed.get("model_id").and_then(|v| v.as_str()).unwrap_or("");
                    let ucid = parsed.get("use_case_id").and_then(|v| v.as_str()).unwrap_or("");
                    let rid = parsed.get("risk_id").and_then(|v| v.as_str()).unwrap_or("");
                    let model_ok = !mid.is_empty() && store.get_model(mid).await.ok().flatten().map(|m| m.tenant == r.tenant).unwrap_or(false);
                    let uc_ok = !ucid.is_empty() && store.get_grc(ucid).await.ok().flatten().map(|g| g.kind == "use-case" && g.tenant == r.tenant).unwrap_or(false);
                    let risk_ok = !rid.is_empty() && store.get_grc(rid).await.ok().flatten().map(|g| g.kind == "risk" && g.tenant == r.tenant).unwrap_or(false);
                    links = serde_json::json!({"model": model_ok, "use_case": uc_ok, "risk": risk_ok, "model_id": mid, "use_case_id": ucid, "risk_id": rid});
                }
                let checklist = parsed.get("checklist").and_then(|v| v.as_array());
                let controls_total = checklist.map(|c| c.len()).unwrap_or(0);
                let controls_done = checklist.map(|c| c.iter().filter(|i| i.get("done").and_then(|v| v.as_bool()).unwrap_or(false)).count()).unwrap_or(0);
                let tier = parsed.get("tier").and_then(|v| v.as_str()).unwrap_or("").to_string();
                out.push(serde_json::json!({
                    "id": r.id, "kind": r.kind, "subject": r.subject, "title": r.title,
                    "status": r.status, "body": r.body, "operator": r.operator,
                    "created_ms": r.created_ms, "verified": verified,
                    "assignee": r.assignee, "due_ms": r.due_ms, "stage": r.stage,
                    "tier": tier, "controls_done": controls_done, "controls_total": controls_total,
                    "linked_refs": refs, "verified_refs": verified_refs, "total_refs": total_refs,
                    "links": links,
                }));
            }
            Json(serde_json::json!({"records": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"records": [], "error": e})).into_response(),
    }
}

/// POST /grc: create a signed governance record. Body: {kind, subject, title, status, body}.
pub(crate) async fn grc_create(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let kind = body.get("kind").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !GRC_KINDS.contains(&kind.as_str()) {
        return Json(serde_json::json!({"ok": false, "error": format!("unknown kind '{kind}'; expected one of {GRC_KINDS:?}")})).into_response();
    }
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("open").to_string();
    // body field may be a string or an object; store a string.
    let doc_body = match body.get("body") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => serde_json::to_string(v).unwrap_or_default(),
        None => String::new(),
    };
    // A2: optional advisory list of linked decision ids. Not part of the signed doc.
    let linked_refs = match body.get("linked_refs") {
        Some(v @ serde_json::Value::Array(_)) => serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string()),
        _ => "[]".to_string(),
    };
    let id = format!("grc-{}", rand_hex(6));
    let now = now_ms();
    let tenant = tenant_of(&headers, &principal);
    let doc = grc_doc(&id, &kind, &subject, &title, &status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, &kind, &subject, &title, &status, &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, &linked_refs, "{}", "", 0, &status, &tenant).await {
        Ok(()) => {
            fire_webhook(&st, "grc.created", serde_json::json!({"id": id, "kind": kind, "subject": subject, "title": title}));
            Json(serde_json::json!({"ok": true, "id": id, "kind": kind})).into_response()
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /grc/:id/status: advance a record's status (e.g. use-case lifecycle, risk treatment).
pub(crate) async fn grc_status(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if status.is_empty() { return Json(serde_json::json!({"ok": false, "error": "status is required"})).into_response(); }
    // A4: re-sign the record with the new status so the stored signature stays valid; otherwise the
    // record would read as tampered on the next verify-on-read in grc_list.
    let tenant = tenant_of(&headers, &None);
    let rec = match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => r,
        Ok(Some(_)) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Ok(None) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    };
    let doc = grc_doc(&rec.id, &rec.kind, &rec.subject, &rec.title, &status, &rec.body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.update_grc_signed(&id, &status, &rec.body, &status, &pubkey_hex, &sig_hex).await {
        Ok(()) => {
            fire_webhook(&st, "grc.status", serde_json::json!({"id": id, "kind": rec.kind, "subject": rec.subject, "status": status}));
            Json(serde_json::json!({"ok": true, "id": id, "status": status})).into_response()
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// A1: the built-in EU AI Act screening questionnaire. Served so the console can render a guided
/// "New assessment" wizard. Each entry is a yes/no question mapped to an assessment flag.
pub(crate) async fn grc_templates() -> impl IntoResponse {
    let q = |key: &str, label: &str| serde_json::json!({"key": key, "label": label});
    Json(serde_json::json!({
        "templates": [{
            "id": "eu-ai-act-screening",
            "kind": "assessment",
            "name": "EU AI Act risk screening",
            "questions": [
                q("prohibited_practice", "Is this a prohibited practice (social scoring, manipulative or exploitative AI, untargeted scraping)?"),
                q("safety_component", "Is the AI a safety component of a product, or an Annex III high-risk use?"),
                q("biometric_identification", "Does it perform biometric identification or categorisation?"),
                q("critical_infrastructure", "Is it used in critical infrastructure?"),
                q("employment_or_education", "Does it make employment or education decisions?"),
                q("essential_services", "Does it gate access to essential services (credit, benefits, insurance)?"),
                q("law_enforcement", "Is it used for law enforcement?"),
                q("interacts_with_humans", "Does it interact directly with people (chatbot)?"),
                q("generates_content", "Does it generate or manipulate content (gen-AI, deepfakes)?")
            ]
        }]
    }))
}

/// G3: create a model-card GRC record that references a model, a use-case and a risk by id. On read
/// (`grc_list`) the server resolves each reference and reports which links resolve.
pub(crate) async fn grc_model_card(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Model card").to_string();
    let doc_body = serde_json::json!({
        "kind": "model-card",
        "model_id": body.get("model_id").and_then(|v| v.as_str()).unwrap_or(""),
        "use_case_id": body.get("use_case_id").and_then(|v| v.as_str()).unwrap_or(""),
        "risk_id": body.get("risk_id").and_then(|v| v.as_str()).unwrap_or(""),
        "summary": body.get("summary").and_then(|v| v.as_str()).unwrap_or(""),
    }).to_string();
    let id = format!("grc-{}", rand_hex(6));
    let status = "open".to_string();
    let now = now_ms();
    let tenant = tenant_of(&headers, &principal);
    let doc = grc_doc(&id, "model-card", &subject, &title, &status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, "model-card", &subject, &title, &status, &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, "[]", "{}", "", 0, &status, &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// G2: create a structured risk-register record. Body carries likelihood/impact (low|medium|high),
/// treatment and owner; the server computes the score (likelihood x impact) and severity band via
/// `acp_core::riskregister::RiskItem` and stores them in the signed body. Console renders a risk table.
pub(crate) async fn grc_risk(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("Risk").to_string();
    let lvl = |k: &str| body.get(k).and_then(|v| v.as_str()).and_then(acp_core::riskregister::Level::parse);
    let likelihood = match lvl("likelihood") { Some(l) => l, None => return Json(serde_json::json!({"ok": false, "error": "likelihood must be low|medium|high"})).into_response() };
    let impact = match lvl("impact") { Some(l) => l, None => return Json(serde_json::json!({"ok": false, "error": "impact must be low|medium|high"})).into_response() };
    let treatment = body.get("treatment").and_then(|v| v.as_str()).and_then(acp_core::riskregister::Treatment::parse).unwrap_or(acp_core::riskregister::Treatment::Mitigate);
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or(&operator).to_string();
    let id = format!("grc-{}", rand_hex(6));
    let item = acp_core::riskregister::RiskItem {
        id: id.clone(), title: title.clone(), owner: owner.clone(), likelihood, impact, treatment,
        status: acp_core::riskregister::RiskStatus::Open, linked_controls: vec![], linked_decisions: vec![], notes: String::new(),
    };
    let score = item.score();
    let band = item.band();
    let doc_body = serde_json::json!({
        "kind": "risk",
        "likelihood": body.get("likelihood").and_then(|v| v.as_str()).unwrap_or(""),
        "impact": body.get("impact").and_then(|v| v.as_str()).unwrap_or(""),
        "treatment": body.get("treatment").and_then(|v| v.as_str()).unwrap_or("mitigate"),
        "owner": owner,
        "score": score,
        "band": band,
    }).to_string();
    let status = "open".to_string();
    let now = now_ms();
    let tenant = tenant_of(&headers, &principal);
    let doc = grc_doc(&id, "risk", &subject, &title, &status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, "risk", &subject, &title, &status, &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, "[]", "{}", "", 0, &status, &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "score": score, "band": band})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// A1: run the assessment engine over a screening questionnaire and persist a signed assessment
/// record. The signed body carries the computed EU AI Act tier, the reasons, and a control checklist
/// (each obligation with a `done` flag) derived from the control library. The raw answers, assignee,
/// due date and stage are stored as workflow metadata (not part of the signed document).
pub(crate) async fn grc_assess(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let subject = body.get("subject").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if subject.is_empty() { return Json(serde_json::json!({"ok": false, "error": "subject is required"})).into_response(); }
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("EU AI Act assessment").to_string();
    let answers = body.get("answers").cloned().unwrap_or_else(|| serde_json::json!({}));
    let flag = |k: &str| answers.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let screening = acp_core::assessment::Screening {
        prohibited_practice: flag("prohibited_practice"),
        safety_component: flag("safety_component"),
        biometric_identification: flag("biometric_identification"),
        critical_infrastructure: flag("critical_infrastructure"),
        employment_or_education: flag("employment_or_education"),
        essential_services: flag("essential_services"),
        law_enforcement: flag("law_enforcement"),
        interacts_with_humans: flag("interacts_with_humans"),
        generates_content: flag("generates_content"),
    };
    let now = now_ms();
    let assessment = acp_core::assessment::assess(&subject, &screening, now);
    let checklist: Vec<serde_json::Value> = assessment.obligations.iter().map(|o| serde_json::json!({
        "framework": o.framework, "control_id": o.control_id, "title": o.title, "done": false,
    })).collect();
    let doc_body = serde_json::json!({
        "tier": assessment.tier.as_str(),
        "reasons": assessment.reasons,
        "checklist": checklist,
    }).to_string();
    let assignee = body.get("assignee").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let due_ms = body.get("due_ms").and_then(|v| v.as_i64()).unwrap_or(0);
    let answers_json = answers.to_string();
    let status = "open".to_string();
    let stage = "draft".to_string();
    let id = format!("grc-{}", rand_hex(6));
    let tenant = tenant_of(&headers, &principal);
    let doc = grc_doc(&id, "assessment", &subject, &title, &status, &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&id, "assessment", &subject, &title, &status, &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, "[]", &answers_json, &assignee, due_ms, &stage, &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "tier": assessment.tier.as_str(), "controls": assessment.obligations.len()})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// #2: auto risk-tiering from an agent's tool bindings. Derives the EU AI Act screening from the
/// agent's business `domain` and registered `tools` (read from its registration metadata, overridable
/// in the body), runs the same tiering as the questionnaire, and files a signed `assessment` GRC record
/// pre-filled with the proposed tier and obligation checklist. An operator still reviews and advances
/// it, so auto-tiering can only propose, never silently approve. EditGrc scope.
pub(crate) async fn agent_auto_assess(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(agent_id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &principal);
    let agents = store.list_agents(&tenant).await.unwrap_or_default();
    let agent = match agents.iter().find(|a| a.id == agent_id) {
        Some(a) => a,
        None => return Json(serde_json::json!({"ok": false, "error": format!("unknown agent '{agent_id}'")})).into_response(),
    };
    // Registration metadata may be an object, or (defensively) a JSON string wrapping one.
    let meta: serde_json::Value = serde_json::from_str(&agent.metadata_json).unwrap_or(serde_json::Value::Null);
    let meta = match &meta { serde_json::Value::String(inner) => serde_json::from_str(inner).unwrap_or(serde_json::Value::Null), other => other.clone() };
    let pick_str = |k: &str| body.get(k).and_then(|v| v.as_str()).or_else(|| meta.get(k).and_then(|v| v.as_str())).unwrap_or("").to_string();
    let domain = pick_str("domain");
    let tools: Vec<String> = body.get("tools").and_then(|v| v.as_array())
        .or_else(|| meta.get("tools").and_then(|v| v.as_array()))
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if domain.is_empty() && tools.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "no domain or tools to assess; set them in the agent metadata or the request body"})).into_response();
    }
    let (screening, signals) = acp_core::assessment::screen_from_signals(&domain, &tools);
    let now = now_ms();
    let assessment = acp_core::assessment::assess(&agent.name, &screening, now);
    let checklist: Vec<serde_json::Value> = assessment.obligations.iter().map(|o| serde_json::json!({
        "framework": o.framework, "control_id": o.control_id, "title": o.title, "done": false,
    })).collect();
    let doc_body = serde_json::json!({
        "tier": assessment.tier.as_str(),
        "reasons": assessment.reasons,
        "checklist": checklist,
        "auto": {"source_agent": agent_id, "domain": domain, "tools": tools, "signals": signals},
    }).to_string();
    let answers_json = serde_json::to_string(&screening).unwrap_or_else(|_| "{}".to_string());
    let title = format!("Auto risk assessment: {}", agent.name);
    let gid = format!("grc-{}", rand_hex(6));
    let doc = grc_doc(&gid, "assessment", &agent.name, &title, "open", &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.add_grc(&gid, "assessment", &agent.name, &title, "open", &doc_body, &operator, now as i64, &pubkey_hex, &sig_hex, "[]", &answers_json, "", 0, "draft", &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": gid, "agent": agent_id, "tier": assessment.tier.as_str(), "controls": assessment.obligations.len(), "signals": assessment.reasons})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// A1: set the assignee and due date on a GRC record (workflow metadata, no re-sign needed).
pub(crate) async fn grc_assign(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let assignee = body.get("assignee").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let due_ms = body.get("due_ms").and_then(|v| v.as_i64()).unwrap_or(0);
    // T1: only assign within the caller's tenant.
    let tenant = tenant_of(&headers, &None);
    match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => {}
        _ => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
    }
    match store.set_grc_assignment(&id, &assignee, due_ms).await {
        Ok(()) => {
            fire_webhook(&st, "grc.assigned", serde_json::json!({"id": id, "assignee": assignee, "due_ms": due_ms}));
            Json(serde_json::json!({"ok": true, "id": id, "assignee": assignee, "due_ms": due_ms})).into_response()
        }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// T5: post a comment on a GRC record (author from the principal). Tenant-scoped: only the record's
/// tenant may comment; body is stored as-is and rendered as a value (never interpolated).
pub(crate) async fn grc_comments_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let author = actor_of(&principal);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &principal);
    match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => {}
        _ => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
    }
    let text = body.get("body").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if text.is_empty() { return Json(serde_json::json!({"ok": false, "error": "body is required"})).into_response(); }
    let cid = format!("cmt-{}", rand_hex(8));
    match store.add_comment(&cid, &id, &author, &text, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": cid})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// T5: list a GRC record's comments (tenant-scoped).
pub(crate) async fn grc_comments_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"comments": []})).into_response() };
    let tenant = tenant_of(&headers, &None);
    match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => {}
        _ => return Json(serde_json::json!({"comments": []})).into_response(),
    }
    match store.list_comments(&id).await {
        Ok(cs) => Json(serde_json::json!({"comments": cs.iter().map(|(cid,a,b,t)| serde_json::json!({"id":cid,"author":a,"body":b,"created_ms":t})).collect::<Vec<_>>()})).into_response(),
        Err(e) => Json(serde_json::json!({"comments": [], "error": e})).into_response(),
    }
}

/// G1/A2: append an advisory linked reference (another GRC id or a decision id) to a record. Unsigned
/// workflow metadata; used to link an assessment/attestation to a use-case for its lifecycle gates.
pub(crate) async fn grc_link(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let link_id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if link_id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "id is required"})).into_response(); }
    let link_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("ref").to_string();
    let tenant = tenant_of(&headers, &None);
    let rec = match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => r,
        Ok(Some(_)) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Ok(None) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    };
    let mut refs: Vec<serde_json::Value> = serde_json::from_str(&rec.linked_refs).unwrap_or_default();
    refs.push(serde_json::json!({"type": link_type, "id": link_id}));
    let refs_json = serde_json::to_string(&refs).unwrap_or_else(|_| "[]".to_string());
    match store.set_grc_linked_refs(&id, &refs_json).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "linked": link_id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// A1: toggle a control's done flag in a conformity/assessment checklist and re-sign the record, so
/// the checklist progress stays tamper-evident. The control_id must already be in the checklist.
pub(crate) async fn grc_control_toggle(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, control_id)): Path<(String, String)>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &None);
    let rec = match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => r,
        Ok(Some(_)) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Ok(None) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    };
    let want_done = body.get("done").and_then(|v| v.as_bool());
    let mut doc_body: serde_json::Value = serde_json::from_str(&rec.body).unwrap_or_else(|_| serde_json::json!({}));
    let mut found = false;
    if let Some(list) = doc_body.get_mut("checklist").and_then(|v| v.as_array_mut()) {
        for item in list.iter_mut() {
            if item.get("control_id").and_then(|v| v.as_str()) == Some(control_id.as_str()) {
                let cur = item.get("done").and_then(|v| v.as_bool()).unwrap_or(false);
                let next = want_done.unwrap_or(!cur);
                item["done"] = serde_json::Value::Bool(next);
                found = true;
            }
        }
    }
    if !found { return Json(serde_json::json!({"ok": false, "error": format!("control '{control_id}' not in checklist")})).into_response(); }
    let new_body = doc_body.to_string();
    let doc = grc_doc(&rec.id, &rec.kind, &rec.subject, &rec.title, &rec.status, &new_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
    let sig_hex = hex::encode(sig);
    match store.update_grc_signed(&id, &rec.status, &new_body, &rec.stage, &pubkey_hex, &sig_hex).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "control_id": control_id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// G1: advance a use-case GRC record through its gated lifecycle. The gate is enforced by
/// `acp_core::usecase`: `assessed` requires a linked assessment GRC record, `approved` requires a
/// linked attestation. Linked records are the record's `linked_refs` (by GRC id). Re-signs on success.
pub(crate) async fn grc_usecase_transition(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, stage)): Path<(String, String)>, Json(_body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let to = match acp_core::usecase::Stage::parse(&stage) {
        Some(s) => s,
        None => return Json(serde_json::json!({"ok": false, "error": format!("unknown stage '{stage}'")})).into_response(),
    };
    let tenant = tenant_of(&headers, &None);
    let rec = match store.get_grc(&id).await {
        Ok(Some(r)) if r.tenant == tenant => r,
        Ok(Some(_)) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Ok(None) => return Json(serde_json::json!({"ok": false, "error": "no such record"})).into_response(),
        Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    };
    if rec.kind != "use-case" {
        return Json(serde_json::json!({"ok": false, "error": "not a use-case record"})).into_response();
    }
    // Resolve the current stage (default proposed), and gate signals from the linked GRC records.
    let cur = acp_core::usecase::Stage::parse(if rec.stage.is_empty() { "proposed" } else { &rec.stage }).unwrap_or(acp_core::usecase::Stage::Proposed);
    let refs: Vec<serde_json::Value> = serde_json::from_str(&rec.linked_refs).unwrap_or_default();
    let (mut has_assessment, mut has_attestation) = (false, false);
    for rf in &refs {
        let rid = rf.get("id").and_then(|v| v.as_str()).or_else(|| rf.as_str()).unwrap_or("");
        if rid.is_empty() { continue; }
        if let Ok(Some(lr)) = store.get_grc(rid).await {
            match lr.kind.as_str() {
                "assessment" => has_assessment = true,
                "attestation" => has_attestation = true,
                _ => {}
            }
        }
    }
    let mut reg = acp_core::usecase::UseCaseRegistry::new();
    reg.upsert(acp_core::usecase::UseCase { id: id.clone(), name: rec.title.clone(), owner: rec.operator.clone(), stage: cur, tier: None, assessment_id: None, model_classes: vec![], created_ms: rec.created_ms as u64 });
    match reg.advance(&id, to, has_assessment, has_attestation) {
        acp_core::usecase::Transition::Refused(why) => Json(serde_json::json!({"ok": false, "error": why})).into_response(),
        acp_core::usecase::Transition::Ok => {
            // Persist the new stage (as both stage and status) and re-sign the record.
            let new_stage = stage.to_ascii_lowercase();
            let doc = grc_doc(&rec.id, &rec.kind, &rec.subject, &rec.title, &new_stage, &rec.body);
            let signer = tenant_signer(&st.cp_key, &tenant);
            let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
            let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
            let sig_hex = hex::encode(sig);
            match store.update_grc_signed(&id, &new_stage, &rec.body, &new_stage, &pubkey_hex, &sig_hex).await {
                Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "stage": new_stage})).into_response(),
                Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
            }
        }
    }
}
