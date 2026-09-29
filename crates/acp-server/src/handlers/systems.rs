//! Governance spine (audit P0: G1/G2/G3): the AI-system registry, roles per system, and the persisted
//! Statement of Applicability (SoA). Reporting can be scoped to a system and driven by its SoA and roles
//! rather than only by a computed profile, which is what an ISO 42001 audit expects.
use crate::state::AppState;
use crate::common::*;
use axum::{extract::{Path, State}, http::HeaderMap, response::{IntoResponse, Response}, Json};
use std::sync::Arc;

fn store_or<'a>(st: &'a Arc<AppState>) -> Result<&'a std::sync::Arc<crate::store::ControlStore>, Response> {
    match &st.store { Some(s) => Ok(s), None => Err(Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response()) }
}

/// GET /systems: the AI-system registry for the tenant.
pub(crate) async fn systems_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    match store.list_systems(&tenant).await {
        Ok(rows) => Json(serde_json::json!({"systems": rows})).into_response(),
        Err(e) => Json(serde_json::json!({"systems": [], "error": e})).into_response(),
    }
}

/// POST /systems: register a first-class AI system. Body: {name, purpose, owner, lifecycle_state,
/// risk_tier, sector, asset_type, jurisdictions:[..]}. EditGrc scope.
pub(crate) async fn system_create(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = g("name");
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    let jurisdictions = body.get("jurisdictions").cloned().unwrap_or_else(|| serde_json::json!([]));
    let id = format!("sys-{}", rand_hex(6));
    let lifecycle = { let l = g("lifecycle_state"); if l.is_empty() { "development".to_string() } else { l } };
    match store.add_system(&id, &name, &g("purpose"), &g("owner"), &lifecycle, &g("risk_tier"), &g("sector"), &g("asset_type"), &jurisdictions.to_string(), &tenant, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// GET /systems/:id: a system with its roles and a small governance-record summary.
pub(crate) async fn system_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let sys = match store.get_system(&id, &tenant).await { Ok(Some(s)) => s, Ok(None) => return Json(serde_json::json!({"error": "not found"})).into_response(), Err(e) => return Json(serde_json::json!({"error": e})).into_response() };
    let roles = store.list_roles(&id, &tenant).await.unwrap_or_default();
    // Records linked by subject == system name (until grc_records carries a system_id).
    let recs = store.list_grc(&tenant, None).await.unwrap_or_default();
    let linked: Vec<&crate::store::GrcRecord> = recs.iter().filter(|r| r.subject == sys.name).collect();
    let mut by_kind: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in &linked { *by_kind.entry(r.kind.clone()).or_insert(0) += 1; }
    Json(serde_json::json!({"system": sys, "roles": roles, "records_by_kind": by_kind, "records": linked.iter().map(|r| serde_json::json!({"id": r.id, "kind": r.kind, "title": r.title, "status": r.status})).collect::<Vec<_>>()})).into_response()
}

/// POST /systems/:id/roles: add a role the org plays for this system, per jurisdiction (G2). Body:
/// {role, jurisdiction, market_date}. EditGrc scope.
pub(crate) async fn role_add(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let role = g("role");
    if role.is_empty() { return Json(serde_json::json!({"ok": false, "error": "role is required"})).into_response(); }
    let rid = format!("role-{}", rand_hex(6));
    match store.add_role(&rid, &id, &role, &g("jurisdiction"), &g("market_date"), &tenant, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": rid})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// Build the subject profile for a system from its own fields plus its roles (G2 feeds applicability).
async fn system_profile(store: &crate::store::ControlStore, sys: &crate::store::AiSystem, tenant: &str) -> acp_core::conformance::SubjectProfile {
    let roles = store.list_roles(&sys.id, tenant).await.unwrap_or_default();
    let mut role_names: Vec<String> = roles.iter().map(|r| r.role.clone()).collect();
    role_names.sort(); role_names.dedup();
    if role_names.is_empty() { role_names = vec!["provider".into(), "deployer".into()]; }
    let jurisdiction = roles.iter().map(|r| r.jurisdiction.clone()).find(|j| !j.is_empty())
        .or_else(|| serde_json::from_str::<Vec<String>>(&sys.jurisdictions).ok().and_then(|v| v.into_iter().next()));
    acp_core::conformance::SubjectProfile {
        roles: role_names,
        risk_tier: Some(if sys.risk_tier.is_empty() { "high".to_string() } else { sys.risk_tier.clone() }),
        sector: (!sys.sector.is_empty()).then(|| sys.sector.clone()),
        jurisdiction,
        asset_type: (!sys.asset_type.is_empty()).then(|| sys.asset_type.clone()),
    }
}

/// GET /systems/:id/soa/:framework: the Statement of Applicability worksheet. Each control merges any
/// stored SoA entry with a proposed default (applicability from the engine), so an operator can edit.
pub(crate) async fn soa_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, framework)): Path<(String, String)>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let sys = match store.get_system(&id, &tenant).await { Ok(Some(s)) => s, Ok(None) => return Json(serde_json::json!({"error": "system not found"})).into_response(), Err(e) => return Json(serde_json::json!({"error": e})).into_response() };
    let profile = system_profile(store, &sys, &tenant).await;
    let stored: std::collections::HashMap<String, crate::store::SoaEntry> = store.list_soa(&id, &framework, &tenant).await.unwrap_or_default().into_iter().map(|e| (e.control_id.clone(), e)).collect();
    let rows: Vec<serde_json::Value> = acp_core::controls::for_framework(&framework).into_iter().map(|c| {
        let (applies, why) = acp_core::conformance::applies(&c, &profile);
        match stored.get(&c.id) {
            Some(e) => serde_json::json!({"control_id": c.id, "reference": c.reference, "title": c.title, "applicable": e.applicable, "justification": e.justification, "status": e.status, "stored": true}),
            None => serde_json::json!({"control_id": c.id, "reference": c.reference, "title": c.title, "applicable": applies, "justification": if applies { String::new() } else { why }, "status": "planned", "stored": false}),
        }
    }).collect();
    Json(serde_json::json!({"system_id": id, "framework": framework, "entries": rows})).into_response()
}

/// POST /systems/:id/soa/:framework: persist SoA entries. Body: {entries:[{control_id, applicable,
/// justification, status, evidence_refs?}]}. EditGrc scope.
pub(crate) async fn soa_set(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, framework)): Path<(String, String)>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { return r; }
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let entries = body.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut n = 0usize;
    for e in &entries {
        let cid = e.get("control_id").and_then(|v| v.as_str()).unwrap_or("").trim();
        if cid.is_empty() { continue; }
        let applicable = e.get("applicable").and_then(|v| v.as_bool()).unwrap_or(true);
        let justification = e.get("justification").and_then(|v| v.as_str()).unwrap_or("");
        let status = e.get("status").and_then(|v| v.as_str()).unwrap_or("planned");
        let evidence = e.get("evidence_refs").cloned().unwrap_or_else(|| serde_json::json!([]));
        if store.set_soa(&id, &framework, cid, applicable, justification, status, &evidence.to_string(), &tenant, now_ms() as i64).await.is_ok() { n += 1; }
    }
    Json(serde_json::json!({"ok": true, "saved": n})).into_response()
}

/// Map a SoA status string to a conformity state.
fn status_conformity(status: &str, applicable: bool) -> acp_core::conformance::Conformity {
    use acp_core::conformance::Conformity::*;
    if !applicable { return NotApplicable; }
    match status {
        "implemented" | "done" | "conformant" => Conformant,
        "partial" | "in-progress" => Partial,
        "gap" | "non-conformant" => NonConformant,
        "not-applicable" => NotApplicable,
        _ => NotAssessed, // planned / unset
    }
}

/// GET /systems/:id/report/:framework: the framework conformance report for one system, graded from its
/// persisted Statement of Applicability (falling back to the computed applicability where no SoA entry
/// exists yet). This is the audit-grade, system-anchored report.
pub(crate) async fn system_report(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, framework)): Path<(String, String)>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let sys = match store.get_system(&id, &tenant).await { Ok(Some(s)) => s, Ok(None) => return Json(serde_json::json!({"error": "system not found"})).into_response(), Err(e) => return Json(serde_json::json!({"error": e})).into_response() };
    let profile = system_profile(store, &sys, &tenant).await;
    let stored: std::collections::HashMap<String, crate::store::SoaEntry> = store.list_soa(&id, &framework, &tenant).await.unwrap_or_default().into_iter().map(|e| (e.control_id.clone(), e)).collect();
    use acp_core::conformance::{Conformity, ControlAssessment, summarise};
    let rows: Vec<ControlAssessment> = acp_core::controls::for_framework(&framework).into_iter().map(|c| {
        let (computed_applies, why) = acp_core::conformance::applies(&c, &profile);
        let (applicable, conformity, reason) = match stored.get(&c.id) {
            Some(e) => (e.applicable, status_conformity(&e.status, e.applicable), if e.applicable { String::new() } else { e.justification.clone() }),
            None => (computed_applies, if computed_applies { Conformity::NotAssessed } else { Conformity::NotApplicable }, why),
        };
        ControlAssessment {
            framework: c.framework, control_id: c.id, title: c.title, reference: c.reference,
            obligation_type: c.obligation_type, applicable, conformity, exclusion_reason: reason,
        }
    }).collect();
    let summary = summarise(&rows);
    let fw = acp_core::controls::framework(&framework);
    let control_rows: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "control_id": r.control_id, "title": r.title, "reference": r.reference, "obligation_type": r.obligation_type,
        "applicable": r.applicable, "conformity": r.conformity.as_str(), "exclusion_reason": r.exclusion_reason,
    })).collect();
    Json(serde_json::json!({
        "framework": framework,
        "framework_label": fw.as_ref().map(|f| f.label.clone()),
        "framework_version": fw.as_ref().map(|f| f.version.clone()),
        "framework_type": fw.as_ref().map(|f| f.framework_type.clone()),
        "system": {"id": sys.id, "name": sys.name, "owner": sys.owner, "risk_tier": sys.risk_tier},
        "subject_profile": profile,
        "generated_ms": now_ms(),
        "controls": control_rows,
        "conformity_summary": {
            "total": summary.total, "applicable": summary.applicable, "not_applicable": summary.not_applicable,
            "conformant": summary.conformant, "partial": summary.partial, "non_conformant": summary.non_conformant, "not_assessed": summary.not_assessed,
        },
    })).into_response()
}
