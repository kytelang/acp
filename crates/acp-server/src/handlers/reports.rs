//! Control-plane HTTP handlers: reports.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

pub(crate) async fn metrics(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let pack = st
        .ledger
        .as_ref()
        .and_then(|l| acp_core::ledger::export_file(l).ok());
    let recs = pack
        .as_ref()
        .and_then(|p| p["records"].as_array().cloned())
        .unwrap_or_default();
    let mut decisions = 0u64;
    let mut verdicts = std::collections::BTreeMap::<String, u64>::new();
    for r in &recs {
        if let Some(j) = r["canonical"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        {
            if j["type"] == "decision" {
                decisions += 1;
                *verdicts
                    .entry(
                        j["decision"]["verdict"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string(),
                    )
                    .or_default() += 1;
            }
        }
    }
    let mut out = String::new();
    out.push_str("# HELP acp_records_total Evidence records in the ledger.\n# TYPE acp_records_total counter\n");
    out.push_str(&format!("acp_records_total {}\n", recs.len()));
    out.push_str("# HELP acp_decisions_total Policy decisions recorded.\n# TYPE acp_decisions_total counter\n");
    out.push_str(&format!("acp_decisions_total {decisions}\n"));
    out.push_str("# HELP acp_decisions_by_verdict Decisions by verdict.\n# TYPE acp_decisions_by_verdict counter\n");
    for (v, n) in &verdicts {
        out.push_str(&format!(
            "acp_decisions_by_verdict{{verdict=\"{v}\"}} {n}\n"
        ));
    }
    // Governance-health gauges for alerting (Grafana/Prometheus). Best-effort: a gauge whose source is
    // not configured is simply omitted, never a scrape error.
    if let Some(store) = &st.store {
        if let Ok(v) = store.list_violations(100_000).await {
            out.push_str("# HELP acp_violations_total Policy denials and firewall blocks recorded.\n# TYPE acp_violations_total counter\n");
            out.push_str(&format!("acp_violations_total {}\n", v.len()));
        }
    }
    if let Some(path) = &st.approvals {
        if let Ok(astore) = acp_core::approvals::ApprovalStore::open(path) {
            if let Ok(p) = astore.list_pending() {
                out.push_str("# HELP acp_approvals_pending Approval holds awaiting a human decision.\n# TYPE acp_approvals_pending gauge\n");
                out.push_str(&format!("acp_approvals_pending {}\n", p.len()));
            }
            if st.approval_sla_ms > 0 {
                if let Ok(o) = astore.list_overdue(st.approval_sla_ms as u64, now_ms()) {
                    // Alert on this: a hold past the SLA is an unmet human-oversight obligation.
                    out.push_str("# HELP acp_approvals_overdue Approval holds pending past the configured SLA.\n# TYPE acp_approvals_overdue gauge\n");
                    out.push_str(&format!("acp_approvals_overdue {}\n", o.len()));
                }
            }
        }
    }
    ([("content-type", "text/plain; version=0.0.4")], out)
}

pub(crate) async fn report(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st
        .ledger
        .as_ref()
        .and_then(|l| acp_core::ledger::export_file(l).ok())
    {
        Some(pack) => {
            let recs = pack["records"].as_array().cloned().unwrap_or_default();
            let mut verdicts = std::collections::BTreeMap::<String, u64>::new();
            let mut outcomes = std::collections::BTreeMap::<String, u64>::new();
            let (mut decisions, mut with_rule) = (0u64, 0u64);
            for r in &recs {
                if let Some(json) = r["canonical"]
                    .as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                {
                    match json["type"].as_str() {
                        Some("decision") => {
                            decisions += 1;
                            let v = json["decision"]["verdict"]
                                .as_str()
                                .unwrap_or("?")
                                .to_string();
                            *verdicts.entry(v).or_default() += 1;
                            if json["decision"]["rule_id"].is_string() {
                                with_rule += 1;
                            }
                        }
                        Some("outcome") => {
                            let k = json["kind"].as_str().unwrap_or("?").to_string();
                            *outcomes.entry(k).or_default() += 1;
                        }
                        _ => {}
                    }
                }
            }
            let coverage = if decisions > 0 {
                with_rule as f64 / decisions as f64
            } else {
                0.0
            };
            Json(serde_json::json!({
                "records": recs.len(),
                "decisions": decisions,
                "billable_units": decisions,
                "verdicts": verdicts,
                "outcomes": outcomes,
                "policy_coverage": (coverage * 1000.0).round() / 1000.0
            }))
            .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}

/// F11: a single causally-ordered timeline (by HLC) over the evidence ledger, so an investigator
/// sees one ordered view even across proxies.
pub(crate) async fn timeline(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.ledger.as_ref() {
        Some(path) => match acp_core::ledger::ordered_by_hlc(path) {
            Ok(rows) => {
                let entries: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|(seq, hlc)| serde_json::json!({"seq": seq, "hlc": hlc}))
                    .collect();
                Json(serde_json::json!({"count": entries.len(), "timeline": entries}))
            }
            Err(e) => Json(serde_json::json!({"error": e})),
        },
        None => Json(serde_json::json!({"error": "no ledger configured"})),
    }
}

pub(crate) fn tally(map: &std::collections::HashMap<String, usize>) -> Vec<serde_json::Value> {
    let mut v: Vec<(String, usize)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().map(|(k, c)| serde_json::json!({"key": k, "count": c})).collect()
}

/// GET /report/violations: an aggregated breach-and-violation report (policy denies + step-ups and
/// A6: build the framework-level report for a regulator: for each control in the framework, its
/// status derived from GRC checklists, the linked-evidence verification counts, the breach summary,
/// and a coverage figure. Returns structured JSON.
/// G4: assemble the post-market monitoring report (EU AI Act Art. 72) purely from runtime data the
/// control plane already holds: violation/block events, classifier drift, and red-team outcomes. No
/// manual entry. Signed with the tenant key so a snapshot is verifiable evidence.
pub(crate) async fn post_market_report_value(st: &Arc<AppState>, tenant: &str) -> serde_json::Value {
    let store = match &st.store { Some(s) => s, None => return serde_json::json!({"error": "no --store configured"}) };
    let violations = store.list_violations(1000).await.unwrap_or_default();
    let blocks = violations.iter().filter(|v| v.verdict == "deny" || v.outcome == "block").count();
    let drift = store.list_drift().await.unwrap_or_default();
    let drift_summary: Vec<serde_json::Value> = drift.iter().map(|(class, hits, total, rate)| {
        serde_json::json!({"class": class, "hits": hits, "total": total, "hit_rate": rate})
    }).collect();
    // Latest red-team outcome from the signed GRC attestations.
    let mut redteam: Option<serde_json::Value> = None;
    if let Ok(recs) = store.list_grc(tenant, None).await {
        for r in recs.iter().filter(|r| r.kind == "attestation" && r.subject == "content-firewall") {
            if let Ok(b) = serde_json::from_str::<serde_json::Value>(&r.body) {
                redteam = Some(serde_json::json!({"status": r.status, "catch_rate": b.get("catch_rate")}));
                break;
            }
        }
    }
    serde_json::json!({
        "report": "post-market-monitoring",
        "framework": "eu-ai-act-art-72",
        "generated_ms": now_ms(),
        "tenant": tenant,
        "total_events": violations.len(),
        "blocks": blocks,
        "drift": drift_summary,
        "redteam": redteam,
        "method": "assembled from runtime violation/block, classifier drift and red-team evidence; no manual entry",
    })
}

pub(crate) async fn report_post_market(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let tenant = tenant_of(&headers, &None);
    Json(post_market_report_value(&st, &tenant).await).into_response()
}

pub(crate) async fn report_post_market_snapshot(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &None);
    let body = post_market_report_value(&st, &tenant).await;
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&body));
    let signed = serde_json::json!({"body": body, "pubkey_hex": hex::encode(acp_core::sign::Signer::public_key(&signer)), "sig_hex": hex::encode(sig)});
    let id = format!("pms-{}", rand_hex(6));
    match store.add_snapshot(&id, "post-market", &tenant, &signed.to_string(), now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

pub(crate) async fn report_post_market_history(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"snapshots": []})).into_response() };
    match store.list_snapshots("post-market", &tenant).await {
        Ok(rows) => Json(serde_json::json!({"snapshots": rows.iter().map(|(id, ts, _)| serde_json::json!({"id": id, "created_ms": ts})).collect::<Vec<_>>()})).into_response(),
        Err(e) => Json(serde_json::json!({"snapshots": [], "error": e})).into_response(),
    }
}

pub(crate) async fn framework_report_value(st: &Arc<AppState>, tenant: &str, name: &str) -> serde_json::Value {
    let store = match &st.store { Some(s) => s, None => return serde_json::json!({"error": "no --store configured"}) };
    // 1. Controls for the framework (loaded packs, else built-in).
    let mut controls: Vec<serde_json::Value> = Vec::new();
    if let Ok(rows) = store.list_packs().await {
        for r in &rows {
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&r.doc_json) {
                if let Some(arr) = doc.get("controls").and_then(|c| c.as_array()) { controls.extend(arr.clone()); }
            }
        }
    }
    if controls.is_empty() {
        controls = acp_core::controls::library().iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect();
    }
    controls.retain(|c| c.get("framework").and_then(|v| v.as_str()) == Some(name));
    // 2. GRC records -> which controls are satisfied, and linked-evidence counts.
    let mut satisfied: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut addressed: std::collections::HashSet<String> = std::collections::HashSet::new();
    let (mut ev_verified, mut ev_total) = (0usize, 0usize);
    if let Ok(recs) = store.list_grc(tenant, None).await {
        for r in &recs {
            if let Ok(body) = serde_json::from_str::<serde_json::Value>(&r.body) {
                if let Some(list) = body.get("checklist").and_then(|c| c.as_array()) {
                    for item in list {
                        if let Some(cid) = item.get("control_id").and_then(|v| v.as_str()) {
                            addressed.insert(cid.to_string());
                            if item.get("done").and_then(|v| v.as_bool()).unwrap_or(false) { satisfied.insert(cid.to_string()); }
                        }
                    }
                }
            }
            // linked-evidence verification for this record.
            let refs: Vec<serde_json::Value> = serde_json::from_str(&r.linked_refs).unwrap_or_default();
            ev_total += refs.len();
            for rf in &refs {
                let did = rf.get("id").and_then(|v| v.as_str()).or_else(|| rf.as_str()).unwrap_or("");
                if !did.is_empty() && store.ingested_exists(did).await.unwrap_or(false) { ev_verified += 1; }
            }
        }
    }
    let control_rows: Vec<serde_json::Value> = controls.iter().map(|c| {
        let cid = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let status = if satisfied.contains(cid) { "satisfied" } else if addressed.contains(cid) { "in-progress" } else { "not-addressed" };
        serde_json::json!({"control_id": cid, "title": c.get("title"), "status": status})
    }).collect();
    let total = controls.len();
    let sat = controls.iter().filter(|c| satisfied.contains(c.get("id").and_then(|v| v.as_str()).unwrap_or(""))).count();
    // 3. breach summary.
    let mut breach_total = 0usize;
    let mut by_verdict: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    if let Ok(rows) = store.list_violations(5000).await {
        breach_total = rows.len();
        for r in &rows { *by_verdict.entry(if r.verdict.is_empty() { r.kind.clone() } else { r.verdict.clone() }).or_insert(0) += 1; }
    }
    let coverage = if total > 0 { sat as f64 / total as f64 } else { 0.0 };
    serde_json::json!({
        "framework": name,
        "generated_ms": now_ms(),
        "controls": control_rows,
        "controls_summary": {"satisfied": sat, "total": total},
        "linked_evidence": {"verified": ev_verified, "total": ev_total},
        "breaches": {"total": breach_total, "by_verdict": by_verdict},
        "coverage": coverage,
    })
}

pub(crate) async fn report_framework(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    Json(framework_report_value(&st, &tenant, &name).await).into_response()
}

/// A6: the framework report as CSV (control_id, status) plus summary rows, for a same-origin download.
pub(crate) async fn report_framework_csv(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let v = framework_report_value(&st, &tenant, &name).await;
    let mut out = String::from("section,key,value
");
    if let Some(cs) = v.get("controls").and_then(|c| c.as_array()) {
        for c in cs {
            let cid = c.get("control_id").and_then(|x| x.as_str()).unwrap_or("");
            let status = c.get("status").and_then(|x| x.as_str()).unwrap_or("");
            out.push_str(&format!("control,{cid},{status}
"));
        }
    }
    let cov = v.get("coverage").and_then(|x| x.as_f64()).unwrap_or(0.0);
    let sat = v.pointer("/controls_summary/satisfied").and_then(|x| x.as_u64()).unwrap_or(0);
    let tot = v.pointer("/controls_summary/total").and_then(|x| x.as_u64()).unwrap_or(0);
    let evv = v.pointer("/linked_evidence/verified").and_then(|x| x.as_u64()).unwrap_or(0);
    let evt = v.pointer("/linked_evidence/total").and_then(|x| x.as_u64()).unwrap_or(0);
    let bt = v.pointer("/breaches/total").and_then(|x| x.as_u64()).unwrap_or(0);
    out.push_str(&format!("summary,controls_satisfied,{sat}/{tot}
"));
    out.push_str(&format!("summary,coverage,{cov:.3}
"));
    out.push_str(&format!("summary,linked_evidence_verified,{evv}/{evt}
"));
    out.push_str(&format!("summary,breaches_total,{bt}
"));
    ([(axum::http::header::CONTENT_TYPE, "text/csv"), (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"framework-report.csv\"")], out).into_response()
}

/// One-click regulator export (EU AI Act Art. 12 record-keeping): the framework conformance report as a
/// signed, self-verifying JSON-LD compliance pack. Every figure is drawn from the signed ledger and
/// GRC records, wrapped in a linked-data envelope and signed with the control-plane key, so a regulator
/// verifies it offline with the public key alone (the same {body, pubkey_hex, sig_hex} shape that
/// `acp verify-pack` checks). Auditor scope (Export).
pub(crate) async fn report_framework_pack(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    if st.store.is_none() { return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response(); }
    let tenant = tenant_of(&headers, &None);
    let report = framework_report_value(&st, &tenant, &name).await;
    let (label, article) = framework_label(&name);
    // JSON-LD envelope: a ComplianceReport that conformsTo the framework, carrying the report body.
    let body = serde_json::json!({
        "@context": {
            "@vocab": "https://schema.org/",
            "acp": "https://varman.ai/ns/compliance#",
            "conformsTo": "http://purl.org/dc/terms/conformsTo",
            "generatedAtTime": "http://www.w3.org/ns/prov#generatedAtTime"
        },
        "@type": "acp:ComplianceReport",
        "name": format!("{label} conformance report"),
        "conformsTo": label,
        "acp:article": article,
        "acp:tenant": tenant,
        "generatedAtTime": now_ms(),
        "acp:report": report,
    });
    let signer = enroll_signer(&st.cp_key);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&body));
    let pack = serde_json::json!({
        "body": body,
        "pubkey_hex": hex::encode(acp_core::sign::Signer::public_key(&signer)),
        "sig_hex": hex::encode(sig),
    });
    let fname = format!("{name}-compliance-pack.jsonld");
    (
        [
            (axum::http::header::CONTENT_TYPE, "application/ld+json".to_string()),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{fname}\"")),
        ],
        serde_json::to_string_pretty(&pack).unwrap_or_else(|_| pack.to_string()),
    ).into_response()
}

/// Human framework label + the record-keeping article it satisfies, for the export envelope.
pub(crate) fn framework_label(slug: &str) -> (&'static str, &'static str) {
    match slug {
        "eu-ai-act" => ("EU AI Act", "Art. 12 (record-keeping)"),
        "nist-ai-rmf" => ("NIST AI RMF", "Measure/Govern"),
        "iso-42001" => ("ISO/IEC 42001", "Clause 9 (performance evaluation)"),
        "soc-2" => ("SOC 2", "CC (common criteria)"),
        _ => ("Framework", "record-keeping"),
    }
}

/// T6: capture the current framework report as a signed-in-time snapshot (history). Gated on Export.
pub(crate) async fn report_framework_snapshot(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &None);
    let report = framework_report_value(&st, &tenant, &name).await;
    let id = format!("snap-{}", rand_hex(8));
    match store.add_snapshot(&id, &name, &tenant, &report.to_string(), now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "framework": name})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// T6: list framework-report snapshots newest-first (history), with a small summary per entry.
pub(crate) async fn report_framework_history(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"snapshots": []})).into_response() };
    let tenant = tenant_of(&headers, &None);
    match store.list_snapshots(&name, &tenant).await {
        Ok(rows) => {
            let out: Vec<serde_json::Value> = rows.iter().map(|(id, ts, body)| {
                let v: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|_| serde_json::json!({}));
                serde_json::json!({"id": id, "created_ms": ts, "coverage": v.get("coverage"), "controls_summary": v.get("controls_summary")})
            }).collect();
            Json(serde_json::json!({"snapshots": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"snapshots": [], "error": e})).into_response(),
    }
}

/// firewall blocks reported by every PEP), for the console Reports view. Persisted, so it spans more
/// than the live feed.
pub(crate) async fn report_violations(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"total": 0, "by_verdict": [], "by_rule": [], "by_agent": [], "by_pep": [], "recent": []})).into_response() };
    let rows = match store.list_violations(2000).await { Ok(r) => r, Err(e) => return Json(serde_json::json!({"error": e})).into_response() };
    let mut by_verdict = std::collections::HashMap::new();
    let mut by_rule = std::collections::HashMap::new();
    let mut by_agent = std::collections::HashMap::new();
    let mut by_pep = std::collections::HashMap::new();
    for r in &rows {
        *by_verdict.entry(if r.verdict.is_empty() { r.kind.clone() } else { r.verdict.clone() }).or_insert(0) += 1;
        *by_rule.entry(if r.rule_id.is_empty() { "(none)".to_string() } else { r.rule_id.clone() }).or_insert(0) += 1;
        *by_agent.entry(if r.agent.is_empty() { "(unknown)".to_string() } else { r.agent.clone() }).or_insert(0) += 1;
        *by_pep.entry(if r.pep.is_empty() { "(unknown)".to_string() } else { r.pep.clone() }).or_insert(0) += 1;
    }
    let recent: Vec<serde_json::Value> = rows.iter().take(200).map(|r| serde_json::json!({
        "ts_ms": r.ts_ms, "pep": r.pep, "agent": r.agent, "tool": r.tool, "verdict": r.verdict,
        "rule_id": r.rule_id, "impact": r.impact, "outcome": r.outcome,
    })).collect();
    Json(serde_json::json!({
        "generated_ms": now_ms(), "total": rows.len(),
        "by_verdict": tally(&by_verdict), "by_rule": tally(&by_rule),
        "by_agent": tally(&by_agent), "by_pep": tally(&by_pep), "recent": recent,
    })).into_response()
}

/// GET /report/violations.csv: the violation records as a CSV download.
pub(crate) async fn report_violations_csv(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A5: exporting the violation ledger requires the Export capability (Auditor).
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let store = match &st.store { Some(s) => s, None => return (StatusCode::OK, "no store\n").into_response() };
    let rows = match store.list_violations(10000).await { Ok(r) => r, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response() };
    let esc = |x: &str| format!("\"{}\"", x.replace('"', "\"\""));
    let mut out = String::from("ts_ms,pep,agent,tool,verdict,rule_id,impact,outcome\n");
    for r in &rows {
        out.push_str(&format!("{},{},{},{},{},{},{},{}\n", r.ts_ms, esc(&r.pep), esc(&r.agent), esc(&r.tool), esc(&r.verdict), esc(&r.rule_id), esc(&r.impact), esc(&r.outcome)));
    }
    ([(axum::http::header::CONTENT_TYPE, "text/csv"), (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"violations.csv\"")], out).into_response()
}
