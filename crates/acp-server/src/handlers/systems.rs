//! Governance spine (audit P0: G1/G2/G3): the AI-system registry, roles per system, and the persisted
//! Statement of Applicability (SoA). Reporting can be scoped to a system and driven by its SoA and roles
//! rather than only by a computed profile, which is what an ISO 42001 audit expects.
use crate::state::AppState;
use crate::common::*;
use axum::{extract::{Path, State}, http::HeaderMap, response::{IntoResponse, Response}, Json};
use std::sync::Arc;

async fn audit(st: &Arc<AppState>, entity_id: &str, action: &str, actor: &str, detail: &str, tenant: &str) {
    if let Some(store) = &st.store {
        let _ = store.add_audit(&format!("aud-{}", rand_hex(6)), "system", entity_id, action, actor, detail, tenant, now_ms() as i64).await;
    }
}

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
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = g("name");
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    let jurisdictions = body.get("jurisdictions").cloned().unwrap_or_else(|| serde_json::json!([]));
    let id = format!("sys-{}", rand_hex(6));
    let lifecycle = { let l = g("lifecycle_state"); if l.is_empty() { "development".to_string() } else { l } };
    match store.add_system(&id, &name, &g("purpose"), &g("owner"), &lifecycle, &g("risk_tier"), &g("sector"), &g("asset_type"), &jurisdictions.to_string(), &tenant, now_ms() as i64).await {
        Ok(()) => { audit(&st, &id, "system-created", &actor_of(&principal), &name, &tenant).await; Json(serde_json::json!({"ok": true, "id": id})).into_response() }
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
    let by_fk = store.list_grc_for_system(&id, &tenant).await.unwrap_or_default();
    let all = store.list_grc(&tenant, None).await.unwrap_or_default();
    let by_name: Vec<crate::store::GrcRecord> = all.into_iter().filter(|r| r.subject == sys.name).collect();
    // Union FK-linked and subject-name-linked records, de-duplicated by id.
    let mut seen = std::collections::HashSet::new();
    let linked: Vec<&crate::store::GrcRecord> = by_fk.iter().chain(by_name.iter()).filter(|r| seen.insert(r.id.clone())).collect();
    let mut by_kind: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in &linked { *by_kind.entry(r.kind.clone()).or_insert(0) += 1; }
    Json(serde_json::json!({"system": sys, "roles": roles, "records_by_kind": by_kind, "records": linked.iter().map(|r| serde_json::json!({"id": r.id, "kind": r.kind, "title": r.title, "status": r.status})).collect::<Vec<_>>()})).into_response()
}

/// POST /systems/:id/roles: add a role the org plays for this system, per jurisdiction (G2). Body:
/// {role, jurisdiction, market_date}. EditGrc scope.
pub(crate) async fn role_add(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let role = g("role");
    if role.is_empty() { return Json(serde_json::json!({"ok": false, "error": "role is required"})).into_response(); }
    // Referential integrity (audit P1 E2): the system must exist.
    match store.get_system(&id, &tenant).await { Ok(Some(_)) => {}, Ok(None) => return Json(serde_json::json!({"ok": false, "error": format!("unknown system '{id}'")})).into_response(), Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() }
    let rid = format!("role-{}", rand_hex(6));
    match store.add_role(&rid, &id, &role, &g("jurisdiction"), &g("market_date"), &tenant, now_ms() as i64).await {
        Ok(()) => { audit(&st, &id, "role-added", &actor_of(&principal), &format!("{role} ({})", g("jurisdiction")), &tenant).await; Json(serde_json::json!({"ok": true, "id": rid})).into_response() }
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
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    // Referential integrity (audit P1 E2): the system must exist.
    match store.get_system(&id, &tenant).await { Ok(Some(_)) => {}, Ok(None) => return Json(serde_json::json!({"ok": false, "error": format!("unknown system '{id}'")})).into_response(), Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() }
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
    audit(&st, &id, "soa-updated", &actor_of(&principal), &format!("{framework}: {n} control(s)"), &tenant).await;
    Json(serde_json::json!({"ok": true, "saved": n})).into_response()
}

/// POST /systems/:id/evidence: attach a first-class evidence record to a control (audit P1). Body:
/// {framework, control_id, title, source, owner, produced_ms, valid_until_ms, artefact_ref, note}.
/// EditGrc scope.
pub(crate) async fn evidence_add(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let n = |k: &str| body.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    // Referential integrity (audit P1 E2): the system must exist.
    match store.get_system(&id, &tenant).await { Ok(Some(_)) => {}, Ok(None) => return Json(serde_json::json!({"ok": false, "error": format!("unknown system '{id}'")})).into_response(), Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() }
    let control_id = g("control_id");
    let framework = g("framework");
    if control_id.is_empty() || framework.is_empty() { return Json(serde_json::json!({"ok": false, "error": "framework and control_id are required"})).into_response(); }
    let eid = format!("ev-{}", rand_hex(6));
    match store.add_evidence(&eid, &id, &framework, &control_id, &g("title"), &g("source"), &g("owner"), n("produced_ms"), n("valid_until_ms"), &g("artefact_ref"), &g("note"), &tenant, now_ms() as i64).await {
        Ok(()) => { audit(&st, &id, "evidence-added", &actor_of(&principal), &format!("{framework}:{control_id}"), &tenant).await; Json(serde_json::json!({"ok": true, "id": eid})).into_response() }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// GET /systems/:id/evidence: the evidence register for a system.
pub(crate) async fn evidence_list(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let ev = store.list_evidence(&id, &tenant).await.unwrap_or_default();
    let now = now_ms() as i64;
    let rows: Vec<serde_json::Value> = ev.iter().map(|e| {
        let fresh = e.valid_until_ms == 0 || e.valid_until_ms > now;
        serde_json::json!({"id": e.id, "framework": e.framework, "control_id": e.control_id, "title": e.title, "source": e.source, "owner": e.owner, "produced_ms": e.produced_ms, "valid_until_ms": e.valid_until_ms, "fresh": fresh})
    }).collect();
    Json(serde_json::json!({"evidence": rows})).into_response()
}


/// POST /systems/:id/apply-pack: apply a policy pack to a system, seeding its Statement of Applicability
/// (audit-friendly, Credo-style). Body: {framework} for a built-in per-framework pack, or {pack_id} for a
/// stored (possibly cross-framework) pack. Non-destructive: controls that already have an SoA entry are
/// left untouched; the rest are seeded applicable + planned. EditGrc scope.
pub(crate) async fn apply_pack(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    if store.get_system(&id, &tenant).await.ok().flatten().is_none() {
        return Json(serde_json::json!({"ok": false, "error": format!("unknown system '{id}'")})).into_response();
    }
    // Resolve the (framework, control_id) set from either a built-in framework pack or a stored pack.
    let mut controls: Vec<(String, String)> = Vec::new();
    let mut pack_label = String::new();
    if let Some(fw) = body.get("framework").and_then(|v| v.as_str()) {
        pack_label = fw.to_string();
        for c in acp_core::controls::for_framework(fw) { controls.push((c.framework, c.id)); }
    } else if let Some(pid) = body.get("pack_id").and_then(|v| v.as_str()) {
        pack_label = pid.to_string();
        if let Ok(rows) = store.list_packs().await {
            if let Some(row) = rows.into_iter().find(|r| r.id == pid) {
                if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&row.doc_json) {
                    if let Some(arr) = doc.get("controls").and_then(|c| c.as_array()) {
                        for c in arr {
                            let fw = c.get("framework").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let cid = c.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if !fw.is_empty() && !cid.is_empty() { controls.push((fw, cid)); }
                        }
                    }
                }
            }
        }
    }
    if controls.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "provide a known 'framework' or 'pack_id' with controls"})).into_response();
    }
    // Non-destructive: skip controls that already have an SoA entry for this system.
    let existing: std::collections::HashSet<(String, String)> = store.list_all_soa(&id, &tenant).await.unwrap_or_default()
        .into_iter().map(|e| (e.framework, e.control_id)).collect();
    let now = now_ms() as i64;
    let (mut seeded, mut skipped) = (0usize, 0usize);
    for (fw, cid) in controls {
        if existing.contains(&(fw.clone(), cid.clone())) { skipped += 1; continue; }
        if store.set_soa(&id, &fw, &cid, true, "", "planned", "[]", &tenant, now).await.is_ok() { seeded += 1; }
    }
    audit(&st, &id, "pack-applied", &actor_of(&principal), &format!("{pack_label}: seeded {seeded}, skipped {skipped}"), &tenant).await;
    Json(serde_json::json!({"ok": true, "seeded": seeded, "skipped": skipped})).into_response()
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
/// persisted Statement of Applicability, with two audit-P1 rules applied: evidence FRESHNESS gates a
/// "conformant" grade (a control claimed implemented but lacking fresh evidence drops to partial), and
/// the control CROSSWALK propagates satisfaction (a control is satisfied via crosswalk when a mapped
/// control in another framework is itself satisfied with fresh evidence for this system).
pub(crate) async fn system_report(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, framework)): Path<(String, String)>, axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let sys = match store.get_system(&id, &tenant).await { Ok(Some(s)) => s, Ok(None) => return Json(serde_json::json!({"error": "system not found"})).into_response(), Err(e) => return Json(serde_json::json!({"error": e})).into_response() };
    let profile = system_profile(store, &sys, &tenant).await;
    // G8: "as at" a point in time. Evidence and SoA are filtered to what existed by then, so a historical
    // conformance state can be rendered. Defaults to now.
    let as_at: i64 = q.get("as_at").and_then(|s| s.parse().ok()).unwrap_or(now_ms() as i64);
    let now = as_at;

    // Evidence freshness per (framework, control): fresh if any evidence has no expiry or expires later.
    let mut fresh: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for e in store.list_evidence(&id, &tenant).await.unwrap_or_default() {
        if e.produced_ms > as_at { continue; } // did not exist as at the reporting date
        if e.valid_until_ms == 0 || e.valid_until_ms > now { fresh.insert((e.framework.clone(), e.control_id.clone())); }
    }
    // All SoA across frameworks for this system.
    let all_soa = store.list_all_soa(&id, &tenant).await.unwrap_or_default();
    let mut soa_map: std::collections::HashMap<(String, String), crate::store::SoaEntry> = std::collections::HashMap::new();
    for e in all_soa { if e.updated_ms <= as_at { soa_map.insert((e.framework.clone(), e.control_id.clone()), e); } }
    // A control is "satisfied" iff SoA marks it applicable + conformant-ish AND it has fresh evidence.
    let conformant_status = |s: &str| matches!(s, "implemented" | "done" | "conformant");
    let is_satisfied = |fw: &str, cid: &str| -> bool {
        match soa_map.get(&(fw.to_string(), cid.to_string())) {
            Some(e) => e.applicable && conformant_status(&e.status) && fresh.contains(&(fw.to_string(), cid.to_string())),
            None => false,
        }
    };
    // Symmetric crosswalk adjacency.
    let mut adj: std::collections::HashMap<(String, String), Vec<(String, String)>> = std::collections::HashMap::new();
    for (a, b) in acp_core::controls::crosswalk_edges() {
        adj.entry(a.clone()).or_default().push(b.clone());
        adj.entry(b).or_default().push(a);
    }

    use acp_core::conformance::{Conformity, ControlAssessment, summarise};
    let rows: Vec<ControlAssessment> = acp_core::controls::for_framework(&framework).into_iter().map(|c| {
        let key = (framework.clone(), c.id.clone());
        let (computed_applies, why) = acp_core::conformance::applies(&c, &profile);
        let soa = soa_map.get(&key);
        let applicable = soa.map(|e| e.applicable).unwrap_or(computed_applies);
        let mut exclusion = if applicable { String::new() } else { soa.map(|e| e.justification.clone()).unwrap_or(why) };
        let conformity = if !applicable {
            Conformity::NotApplicable
        } else if is_satisfied(&framework, &c.id) {
            Conformity::Conformant
        } else if let Some(entry) = soa {
            if conformant_status(&entry.status) {
                // claimed implemented but no fresh evidence -> freshness gate
                exclusion = "claimed implemented but no fresh evidence".to_string();
                Conformity::Partial
            } else {
                // crosswalk: satisfied elsewhere?
                match adj.get(&key).and_then(|ns| ns.iter().find(|(fw, cid)| is_satisfied(fw, cid))) {
                    Some((fw, cid)) => { exclusion = format!("satisfied via crosswalk: {fw}:{cid}"); Conformity::Conformant }
                    None => status_conformity(&entry.status, true),
                }
            }
        } else {
            match adj.get(&key).and_then(|ns| ns.iter().find(|(fw, cid)| is_satisfied(fw, cid))) {
                Some((fw, cid)) => { exclusion = format!("satisfied via crosswalk: {fw}:{cid}"); Conformity::Conformant }
                None => Conformity::NotAssessed,
            }
        };
        ControlAssessment {
            framework: c.framework, control_id: c.id, title: c.title, reference: c.reference,
            obligation_type: c.obligation_type, applicable, conformity, exclusion_reason: exclusion,
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
        "as_at": as_at,
        "controls": control_rows,
        "conformity_summary": {
            "total": summary.total, "applicable": summary.applicable, "not_applicable": summary.not_applicable,
            "conformant": summary.conformant, "partial": summary.partial, "non_conformant": summary.non_conformant, "not_assessed": summary.not_assessed,
        },
    })).into_response()
}

/// GET /systems/:id/audit: the change history for a system (audit P2 G7).
pub(crate) async fn system_audit(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let rows = store.list_audit(&id, &tenant, 500).await.unwrap_or_default();
    Json(serde_json::json!({"audit": rows})).into_response()
}

/// POST /systems/:id/delete (EditGrc): delete a system and cascade its roles/SoA/evidence/audit.
pub(crate) async fn system_delete(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    match store.delete_system(&id, &tenant).await { Ok(()) => { audit(&st, &id, "system-deleted", &actor_of(&principal), "", &tenant).await; Json(serde_json::json!({"ok": true})).into_response() }, Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response() }
}

/// POST /systems/:id/update (EditGrc). Body: same fields as create.
pub(crate) async fn system_update(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    let sys = match store.get_system(&id, &tenant).await { Ok(Some(s)) => s, Ok(None) => return Json(serde_json::json!({"ok": false, "error": "unknown system"})).into_response(), Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() };
    let g = |k: &str, d: &str| body.get(k).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).unwrap_or_else(|| d.to_string());
    let jurisdictions = body.get("jurisdictions").cloned().map(|v| v.to_string()).unwrap_or(sys.jurisdictions.clone());
    let lifecycle = g("lifecycle_state", &sys.lifecycle_state);
    match store.update_system(&id, &g("name", &sys.name), &g("purpose", &sys.purpose), &g("owner", &sys.owner), &lifecycle, &g("risk_tier", &sys.risk_tier), &g("sector", &sys.sector), &g("asset_type", &sys.asset_type), &jurisdictions, &tenant, now_ms() as i64).await {
        Ok(()) => { audit(&st, &id, "system-updated", &actor_of(&principal), &g("name", &sys.name), &tenant).await; Json(serde_json::json!({"ok": true})).into_response() }
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /systems/:id/roles/:rid/delete (EditGrc).
pub(crate) async fn role_delete(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, rid)): Path<(String, String)>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let tenant = tenant_of(&headers, &None);
    let store = match store_or(&st) { Ok(s) => s, Err(r) => return r };
    match store.delete_role(&rid, &tenant).await { Ok(()) => { audit(&st, &id, "role-removed", &actor_of(&principal), &rid, &tenant).await; Json(serde_json::json!({"ok": true})).into_response() }, Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response() }
}
