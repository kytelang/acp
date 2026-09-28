//! Control-plane HTTP handlers: models.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// B3: run the model/artifact admission scanner (if configured) and produce a scan status and, on a
/// clean pass, a signed CycloneDX AI-BOM. Returns (scan_status, aibom_json, refused). With no scanner
/// configured the model is stored "unscanned" and not refused. On a bad verdict, the model is refused
/// when --model-scan-block is set, else flagged (stored with the finding recorded in the AI-BOM).
pub(crate) async fn admission_scan(st: &Arc<AppState>, name: &str, provider: &str, version: &str) -> (String, String, bool) {
    let url = match &st.model_scanner_url { Some(u) => u.clone(), None => return ("unscanned".to_string(), String::new(), false) };
    let client = reqwest::Client::new();
    let req = serde_json::json!({"name": name, "provider": provider, "version": version});
    let verdict = match client.post(&url).json(&req).send().await {
        Ok(resp) => resp.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    };
    let (scan, _issues): (acp_core::supplychain::ScanVerdict, Vec<String>) = match &verdict {
        Some(v) => {
            let vs = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("");
            let issues: Vec<String> = v.get("issues").and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|i| i.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            match vs {
                "clean" => (acp_core::supplychain::ScanVerdict::Clean, issues),
                "" => (acp_core::supplychain::ScanVerdict::Unscanned, issues),
                _ => (acp_core::supplychain::ScanVerdict::Findings { issues: if issues.is_empty() { vec![vs.to_string()] } else { issues.clone() } }, issues),
            }
        }
        None => {
            // Scanner unreachable: fail closed only when blocking is on.
            return ("scanner-error".to_string(), String::new(), st.model_scan_block);
        }
    };
    // Provenance digest so the AI-BOM admission is not denied for lack of a digest.
    let digest = acp_core::canonical::sha256_hex_bytes(format!("{name}:{provider}:{version}").as_bytes());
    let artifact = acp_core::supplychain::Artifact {
        kind: "model-class".to_string(), name: name.to_string(), digest, source: provider.to_string(),
        publisher: provider.to_string(), signature: None,
    };
    let admission = acp_core::supplychain::admit(&artifact, &scan, true, true);
    let refused = !admission.admitted() && st.model_scan_block;
    let scan_status = match &scan {
        acp_core::supplychain::ScanVerdict::Clean => "clean".to_string(),
        acp_core::supplychain::ScanVerdict::Unscanned => "unscanned".to_string(),
        acp_core::supplychain::ScanVerdict::Findings { issues } => format!("findings: {}", issues.join(", ")),
    };
    if refused {
        return (scan_status, String::new(), true);
    }
    // Store a signed AI-BOM for the registered model (clean or flagged).
    let bom = acp_core::aibom::AiBom {
        generated_ms: now_ms(),
        entries: vec![acp_core::aibom::BomEntry::new(artifact, scan, admission, None, None)],
    };
    let signer = enroll_signer(&st.cp_key);
    let signed = bom.sign(&signer);
    let aibom_json = serde_json::to_string(&signed).unwrap_or_default();
    (scan_status, aibom_json, false)
}

/// A3: register a model in the registry (provider, version, card). B3 later wires an admission scan;
/// here the scan_status defaults to "unscanned".
pub(crate) async fn model_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterApp) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    let provider = body.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let version = body.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let card = body.get("card").map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());
    let id = format!("mdl-{}", rand_hex(6));
    // B3: run the admission scanner (if configured) before storing; refuse/flag per config.
    let (scan_status, aibom, refused) = admission_scan(&st, &name, &provider, &version).await;
    if refused {
        return Json(serde_json::json!({"ok": false, "error": format!("model refused by admission scan: {scan_status}"), "scan_status": scan_status})).into_response();
    }
    let tenant = tenant_of(&headers, &None);
    match store.add_model(&id, &name, &provider, &version, &card, &scan_status, &aibom, &tenant, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "name": name, "scan_status": scan_status})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

pub(crate) async fn models_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"models": []})).into_response() };
    match store.list_models(&tenant).await {
        Ok(ms) => {
            // R4: annotate each model with the MITRE ATLAS techniques mapped from its scan findings.
            let enriched: Vec<serde_json::Value> = ms.iter().map(|m| {
                let mut v = serde_json::to_value(m).unwrap_or_else(|_| serde_json::json!({}));
                let techs = atlas_from_scan_status(&m.scan_status);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("atlas".into(), serde_json::json!(techs.iter().map(|t| t.id.clone()).collect::<Vec<_>>()));
                    obj.insert("atlas_detail".into(), serde_json::to_value(&techs).unwrap_or(serde_json::json!([])));
                }
                v
            }).collect();
            Json(serde_json::json!({"models": enriched})).into_response()
        }
        Err(e) => Json(serde_json::json!({"models": [], "error": e})).into_response(),
    }
}

/// R4: derive ATLAS techniques from a stored scan_status string. The status is either "clean",
/// "unscanned", "scanner-error", or "findings: a, b, c". Only the findings list maps to techniques.
pub(crate) fn atlas_from_scan_status(scan_status: &str) -> Vec<acp_core::atlas::AtlasTechnique> {
    let rest = match scan_status.strip_prefix("findings:") {
        Some(r) => r.trim(),
        None => return Vec::new(),
    };
    let issues: Vec<String> = rest.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    acp_core::atlas::techniques_for_issues(&issues)
}

pub(crate) async fn model_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"error": "no --store configured"})).into_response() };
    match store.get_model(&id).await {
        Ok(Some(m)) if m.tenant == tenant => Json(serde_json::json!(m)).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no such model"}))).into_response(),
        Err(e) => Json(serde_json::json!({"error": e})).into_response(),
    }
}

/// G15: POST /models/:id/fairness {rows:[{group,predicted_positive,actual_positive}]} -> fairness report,
/// stored as a signed GRC record linked to the model.
pub(crate) async fn model_fairness(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_core::auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let rows_val = match body.get("rows") {
        Some(serde_json::Value::String(s)) => serde_json::from_str::<serde_json::Value>(s).unwrap_or(serde_json::Value::Null),
        Some(v) => v.clone(),
        None => serde_json::Value::Null,
    };
    let rows: Vec<acp_core::fairness::EvalRow> = rows_val.as_array().map(|a| a.iter().filter_map(|r| {
        Some(acp_core::fairness::EvalRow { group: r.get("group")?.as_str()?.to_string(),
            predicted_positive: r.get("predicted_positive").and_then(|v| v.as_bool()).unwrap_or(false),
            actual_positive: r.get("actual_positive").and_then(|v| v.as_bool()).unwrap_or(false) })
    }).collect()).unwrap_or_default();
    if rows.is_empty() { return Json(serde_json::json!({"ok": false, "error": "rows required"})).into_response(); }
    let report = acp_core::fairness::evaluate(&rows);
    let doc_body = serde_json::to_string(&report).unwrap_or_default();
    let operator = actor_of(&principal);
    let tenant = tenant_of(&headers, &principal);
    let gid = format!("grc-{}", rand_hex(6));
    let title = format!("Fairness test: {id}");
    let doc = grc_doc(&gid, "attestation", &id, &title, "tested", &doc_body);
    let signer = tenant_signer(&st.cp_key, &tenant);
    let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
    let refs = serde_json::json!([id]).to_string();
    match store.add_grc(&gid, "attestation", &id, &title, "tested", &doc_body, &operator, now_ms() as i64, &hex::encode(acp_core::sign::Signer::public_key(&signer)), &hex::encode(sig), &refs, "{}", "", 0, "tested", &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": gid, "report": report})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
