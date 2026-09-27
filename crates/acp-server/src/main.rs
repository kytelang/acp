//! acp-server: the control-plane HTTP service (v1.1 seed, single-tenant).
//!
//! Serves the web approval inbox (M4.3), the current policy endpoint (M2.2), a read-only
//! evidence-verify endpoint, and a basic governance report. HTML is rendered with `maud`, which
//! auto-escapes, so attacker-controlled content in the inbox cannot inject markup (M4.5).
//! Multi-tenant Postgres, per-tenant keys, and SSO are the next layer (v1.1.1-1.1.3 / H1).

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap as StdHashMap;
use maud::{html, DOCTYPE};
use std::sync::Arc;

struct AppState {
    approvals: Option<String>,
    policy: Option<(String, String)>, // (hash, yaml body)
    ledger: Option<String>,
    // B1: server-side liveness of enrolled proxies (dead-man's-switch).
    liveness: std::sync::Mutex<acp_core::liveness::GapDetector>,
    // B3: fail-open/deny spike detectors, one per event kind.
    spikes: std::sync::Mutex<std::collections::HashMap<String, acp_core::anomaly::SpikeDetector>>,
    // H0.7: tamper-evident self-governance meta-audit log (None if not configured).
    meta: Option<std::sync::Mutex<acp_ledger::Ledger>>,
    registry: Option<String>,
    policy_store: Option<String>,
    enrollment: Option<String>,
    store: Option<std::sync::Arc<acp_cpstore::ControlStore>>,
    cp_key: String,
    break_glass_file: Option<String>,
    break_glass_seed: Option<[u8; 32]>,
    auth: Option<Auth>,
    // E1: shared bearer token PEPs present when reporting heartbeats/events. None = open (dev).
    report_token: Option<String>,
    // E1/E3: bounded ring of recent governance events reported by PEPs, for the console feed.
    events: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    // A5: user->role-group directory surfaced over SCIM (id, email, groups). Loaded from
    // --scim-users JSON, or a demo default in the mocked-IdP dev setup.
    scim_users: Vec<(String, String, Vec<String>)>,
    // C1 (HA): this replica's node id, and the current leadership view (is_leader, holder, token).
    node_id: String,
    lease_ttl_ms: i64,
    // B3: optional model/artifact admission scanner. When set, model registration calls it and
    // refuses (block) or flags (default) on a bad verdict, storing a signed AI-BOM on a clean pass.
    model_scanner_url: Option<String>,
    model_scan_block: bool,
    // G4: optional outbound event webhook (HMAC-signed) for stakeholder notifications.
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    // G5: optional feed URLs the control plane polls for signed control packs / threat packs.
    packs_feed_url: Option<String>,
    threat_feed_url: Option<String>,
    // M2: optional ticket-resolution feed the control plane polls (pull complement to /tickets/callback).
    ticket_poll_url: Option<String>,
    // M3: periodic framework-report snapshotting + delivery.
    snapshot_interval_ms: i64,
    snapshot_frameworks: Vec<String>,
    // M4: approval SLA escalation.
    approval_sla_ms: i64,
    escalated: std::sync::Mutex<std::collections::HashSet<String>>,
    lease: std::sync::Mutex<(bool, String, i64)>,
}

/// Optional control-plane RBAC. When present, mutating endpoints require a verified bearer token
/// with the right capability. `dev` is an in-memory mock issuer for local use (issues test tokens);
/// production sets jwks+cfg from the org IdP and leaves dev None.
struct Auth {
    jwks: std::sync::Arc<std::sync::RwLock<acp_auth::Jwks>>,
    cfg: acp_auth::EntraConfig,
    dev: Option<acp_auth::MockEntra>,
}

/// A4: the built-in signed control packs (EU AI Act, NIST AI RMF, ISO 42001), signed with the
/// control-plane key so an operator can load them via POST /packs. Derived from the control library.
async fn packs_available(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let signer = enroll_signer(&st.cp_key);
    let signed: Vec<serde_json::Value> = acp_core::pack::builtin_packs(now_ms())
        .iter().map(|p| serde_json::to_value(p.sign(&signer)).unwrap_or_default()).collect();
    Json(serde_json::json!({"packs": signed}))
}

/// A4: load a signed control pack. The signature is verified before storing; a tampered pack (body
/// no longer matches the signature) is rejected with a clear error. Idempotent by pack id.
async fn pack_load(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { return r; }
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
async fn packs_list(State(st): State<Arc<AppState>>) -> Response {
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
async fn controls_list(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> Response {
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

/// B3: run the model/artifact admission scanner (if configured) and produce a scan status and, on a
/// clean pass, a signed CycloneDX AI-BOM. Returns (scan_status, aibom_json, refused). With no scanner
/// configured the model is stored "unscanned" and not refused. On a bad verdict, the model is refused
/// when --model-scan-block is set, else flagged (stored with the finding recorded in the AI-BOM).
async fn admission_scan(st: &Arc<AppState>, name: &str, provider: &str, version: &str) -> (String, String, bool) {
    let url = match &st.model_scanner_url { Some(u) => u.clone(), None => return ("unscanned".to_string(), String::new(), false) };
    let client = reqwest::Client::new();
    let req = serde_json::json!({"name": name, "provider": provider, "version": version});
    let verdict = match client.post(&url).json(&req).send().await {
        Ok(resp) => resp.json::<serde_json::Value>().await.ok(),
        Err(_) => None,
    };
    let (scan, issues): (acp_core::supplychain::ScanVerdict, Vec<String>) = match &verdict {
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
async fn model_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterApp) { return r; }
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
async fn models_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
fn atlas_from_scan_status(scan_status: &str) -> Vec<acp_core::atlas::AtlasTechnique> {
    let rest = match scan_status.strip_prefix("findings:") {
        Some(r) => r.trim(),
        None => return Vec::new(),
    };
    let issues: Vec<String> = rest.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    acp_core::atlas::techniques_for_issues(&issues)
}
async fn model_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"error": "no --store configured"})).into_response() };
    match store.get_model(&id).await {
        Ok(Some(m)) if m.tenant == tenant => Json(serde_json::json!(m)).into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no such model"}))).into_response(),
        Err(e) => Json(serde_json::json!({"error": e})).into_response(),
    }
}
async fn vendor_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterApp) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    // G6: if a structured questionnaire is supplied, compute a deterministic risk score + band and store
    // both alongside the answers. Otherwise fall back to a free-form risk object.
    let (risk_json, score, band) = if let Some(q) = body.get("questionnaire") {
        let data_residency = q.get("data_residency").and_then(|v| v.as_str()).unwrap_or("");
        let sub_processors = q.get("sub_processors").and_then(|v| v.as_u64()).unwrap_or(0);
        let certifications = q.get("certifications").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let incidents = q.get("incidents").and_then(|v| v.as_u64()).unwrap_or(0);
        let mut score: u64 = 0;
        // Residency outside a trusted region adds risk.
        if !matches!(data_residency, "eu" | "us" | "uk") { score += 2; }
        // More than three sub-processors adds one point each.
        if sub_processors > 3 { score += sub_processors - 3; }
        // No certifications is a red flag.
        if certifications == 0 { score += 2; }
        // Each past incident adds two points.
        score += incidents * 2;
        let band = match score { 0..=1 => "low", 2..=3 => "medium", 4..=6 => "high", _ => "critical" };
        let rj = serde_json::json!({"questionnaire": q, "score": score, "band": band}).to_string();
        (rj, score, band.to_string())
    } else {
        (body.get("risk").map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string()), 0, "n/a".to_string())
    };
    let id = format!("vnd-{}", rand_hex(6));
    let tenant = tenant_of(&headers, &None);
    let interval = body.get("review_interval_ms").and_then(|v| v.as_i64()).unwrap_or(90 * 24 * 60 * 60 * 1000);
    let review_due = now_ms() as i64 + interval;
    match store.add_vendor(&id, &name, &risk_json, &tenant, review_due, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "name": name, "score": score, "band": band, "review_due_ms": review_due})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
/// M5: mark a vendor re-reviewed, pushing its next review date out by the interval (default 90d).
async fn vendor_review(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterApp) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let tenant = tenant_of(&headers, &None);
    let interval = body.get("review_interval_ms").and_then(|v| v.as_i64()).unwrap_or(90 * 24 * 60 * 60 * 1000);
    let review_due = now_ms() as i64 + interval;
    match store.set_vendor_review(&id, &tenant, review_due).await {
        Ok(true) => Json(serde_json::json!({"ok": true, "id": id, "review_due_ms": review_due})).into_response(),
        Ok(false) => Json(serde_json::json!({"ok": false, "error": "no such vendor"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

async fn vendors_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let tenant = tenant_of(&headers, &None);
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"vendors": []})).into_response() };
    match store.list_vendors(&tenant).await {
        Ok(vs) => {
            let now = now_ms() as i64;
            let out: Vec<serde_json::Value> = vs.iter().map(|v| serde_json::json!({
                "id": v.id, "name": v.name, "risk_json": v.risk_json, "review_due_ms": v.review_due_ms,
                "overdue": v.review_due_ms > 0 && now > v.review_due_ms,
            })).collect();
            Json(serde_json::json!({"vendors": out})).into_response()
        }
        Err(e) => Json(serde_json::json!({"vendors": [], "error": e})).into_response(),
    }
}

/// M1: list the tenants that have data, for the console tenant switcher.
async fn tenants_list(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"tenants": ["default"]})).into_response() };
    match store.list_tenants().await {
        Ok(mut ts) => { if ts.is_empty() { ts.push("default".to_string()); } Json(serde_json::json!({"tenants": ts})).into_response() }
        Err(e) => Json(serde_json::json!({"tenants": ["default"], "error": e})).into_response(),
    }
}

/// C1: report this replica's HA leadership view (is it the leader, who holds the lease, the fencing
/// token). The console and ops can see which node is active without guessing.
async fn leader_status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let (is_leader, holder, token) = st.lease.lock().unwrap().clone();
    Json(serde_json::json!({"node": st.node_id, "leader": is_leader, "holder": holder, "token": token}))
}

/// C1: restore persisted liveness heartbeats and spike-event timestamps from the shared store into
/// the in-memory detectors, so a restart does not lose the dead-man's-switch or the alert state.
async fn restore_control_state(st: &Arc<AppState>, store: &acp_cpstore::ControlStore) {
    // Liveness: one row per proxy ("liveness:{proxy}" -> ts), so replicas never clobber each other.
    if let Ok(rows) = store.list_state_prefix("liveness:").await {
        let mut live = st.liveness.lock().unwrap();
        for (k, v) in rows {
            if let (Some(proxy), Ok(ts)) = (k.strip_prefix("liveness:"), v.parse::<u64>()) {
                live.heartbeat(proxy, ts);
            }
        }
    }
    // Spikes: one row per event ("spike:{kind}:{ts}"), append-only, replayed within the window.
    let cutoff = now_ms() - 300_000;
    if let Ok(rows) = store.list_state_prefix("spike:").await {
        let mut spikes = st.spikes.lock().unwrap();
        for (k, _) in rows {
            let mut it = k.splitn(3, ':'); // "spike", kind, ts
            let _ = it.next();
            if let (Some(kind), Some(ts)) = (it.next(), it.next().and_then(|t| t.parse::<u64>().ok())) {
                if ts >= cutoff {
                    spikes.entry(kind.to_string()).or_insert_with(|| acp_core::anomaly::SpikeDetector::new(60_000, 10)).record(ts);
                }
            }
        }
    }
    tracing::info!("restored control state (liveness + spike) from shared store");
}

/// G4: fire a structured, HMAC-signed event to the configured webhook (best-effort, non-blocking).
/// User-controlled fields (tool name, subject, ...) are placed only as JSON values, never interpolated
/// into markup, so a crafted value cannot forge the notification.
fn fire_webhook(st: &Arc<AppState>, event_type: &str, fields: serde_json::Value) {
    let url = match &st.webhook_url { Some(u) => u.clone(), None => return };
    let secret = st.webhook_secret.clone().unwrap_or_default();
    let now = now_ms();
    let payload = serde_json::json!({"type": event_type, "ts_ms": now, "event": fields});
    let body = payload.to_string();
    let header = acp_core::webhook::sign_webhook(secret.as_bytes(), (now / 1000) as u64, &body);
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let _ = client.post(&url)
            .header("content-type", "application/json")
            .header("x-acp-signature", header)
            .body(body)
            .send().await;
    });
}

/// A5: load the SCIM user directory (id, email, role groups) from a JSON file, or return a demo
/// mapping so the SCIM endpoints are exercisable under the mocked IdP. The file is a JSON array of
/// {id, email, groups:[role,...]}.
fn load_scim_users(path: Option<&str>) -> Vec<(String, String, Vec<String>)> {
    if let Some(p) = path {
        if let Ok(body) = std::fs::read_to_string(p) {
            if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                return arr.iter().map(|u| (
                    u.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    u.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    u.get("groups").and_then(|v| v.as_array()).map(|g| g.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                )).collect();
            }
        }
    }
    // Demo directory: one operator per separation-of-duty role.
    vec![
        ("u-admin".into(), "policy.admin@example.com".into(), vec!["PolicyAdmin".into()]),
        ("u-onboard".into(), "app.registrar@example.com".into(), vec!["AppRegistrar".into()]),
        ("u-grc".into(), "grc.author@example.com".into(), vec!["GrcAuthor".into()]),
        ("u-fw".into(), "firewall.admin@example.com".into(), vec!["FirewallAdmin".into()]),
        ("u-approver".into(), "approver@example.com".into(), vec!["Approver".into()]),
        ("u-auditor".into(), "auditor@example.com".into(), vec!["Auditor".into()]),
        ("u-secops".into(), "security.officer@example.com".into(), vec!["SecurityOfficer".into()]),
        ("u-breakglass".into(), "breakglass@example.com".into(), vec!["BreakGlassOperator".into()]),
    ]
}

/// Load a JWKS from a URL (fetched) or a file path (read). Used for real Entra keys.
async fn load_jwks(source: &str) -> Result<acp_auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?
            .text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
}

/// Authorise a request for a capability. RBAC disabled (auth None) allows everything (local demo).
fn authorize(auth: &Option<Auth>, headers: &HeaderMap, cap: acp_auth::Capability) -> Result<Option<acp_auth::Principal>, Response> {
    let a = match auth { Some(a) => a, None => return Ok(None) };
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"missing bearer token"}))).into_response())?;
    let jwks = a.jwks.read().unwrap();
    let p = acp_auth::verify(token, &jwks, &a.cfg, now_ms())
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":format!("invalid token: {e:?}")}))).into_response())?;
    if !p.can(cap) {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"ok":false,"error":format!("principal lacks {cap:?}")}))).into_response());
    }
    Ok(Some(p))
}

/// The actor string to attribute a change to: the verified principal's username (or oid), else
/// "console" when RBAC is off (local/dev). Threaded into evidence and control-plane records so a
/// change is attributable to the authenticated admin, not a hardcoded literal (gap A9).
/// T1: resolve the tenant for a request: the `x-acp-tenant` header if present, else the authenticated
/// principal's Entra tenant (when it is a real tenant, not the dev "common"), else "default".
fn tenant_of(headers: &HeaderMap, principal: &Option<acp_auth::Principal>) -> String {
    if let Some(h) = headers.get("x-acp-tenant").and_then(|v| v.to_str().ok()) {
        let t = h.trim();
        if !t.is_empty() { return t.to_string(); }
    }
    if let Some(p) = principal {
        if !p.tenant.is_empty() && p.tenant != "common" { return p.tenant.clone(); }
    }
    "default".to_string()
}

fn actor_of(p: &Option<acp_auth::Principal>) -> String {
    match p {
        Some(pr) if !pr.username.is_empty() => pr.username.clone(),
        Some(pr) => pr.oid.clone(),
        None => "console".to_string(),
    }
}

#[tokio::main]
async fn main() {
    acp_obs::init("acp-server");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8787".to_string();
    let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
    let mut meta_ledger: Option<String> = None;
    let mut registry: Option<String> = None;
    let mut policy_store: Option<String> = None;
    let mut break_glass_file: Option<String> = None;
    let mut enrollment: Option<String> = None;
    let mut store_url: Option<String> = None;
    let mut cp_key = "acp-cp.key".to_string();
    let mut tls_ca: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut break_glass_seed: Option<[u8; 32]> = None;
    let mut oidc_jwks: Option<String> = None;
    let mut oidc_issuer: Option<String> = None;
    let mut oidc_audience: Option<String> = None;
    let mut dev_auth = false;
    let mut entra_tenant: Option<String> = None;
    let mut entra_audience: Option<String> = None;
    let mut report_token: Option<String> = std::env::var("ACP_REPORT_TOKEN").ok().filter(|s| !s.is_empty());
    let mut scim_users_path: Option<String> = None;
    let mut model_scanner_url: Option<String> = None;
    let mut model_scan_block = false;
    let mut webhook_url: Option<String> = None;
    let mut webhook_secret: Option<String> = None;
    let mut packs_feed_url: Option<String> = None;
    let mut threat_feed_url: Option<String> = None;
    let mut ticket_poll_url: Option<String> = None;
    let mut snapshot_interval_ms: i64 = 0;
    let mut snapshot_frameworks: Vec<String> = Vec::new();
    let mut approval_sla_ms: i64 = 0;
    let mut node_id: Option<String> = None;
    let mut lease_ttl_ms: i64 = 15_000;
    let mut entra_preflight = false;
    let mut entra_test_token: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or(addr),
            "--approvals" => approvals = it.next().cloned(),
            "--policy" => policy_path = it.next().cloned(),
            "--ledger" => ledger = it.next().cloned(),
            "--meta-ledger" => meta_ledger = it.next().cloned(),
            "--registry" => registry = it.next().cloned(),
            "--policy-store" => policy_store = it.next().cloned(),
            "--enrollment" => enrollment = it.next().cloned(),
            "--store" => store_url = it.next().cloned(),
            "--report-token" => report_token = it.next().cloned(),
            "--scim-users" => scim_users_path = it.next().cloned(),
            "--model-scanner-url" => model_scanner_url = it.next().cloned(),
            "--model-scan-block" => model_scan_block = true,
            "--webhook-url" => webhook_url = it.next().cloned(),
            "--webhook-secret" => webhook_secret = it.next().cloned(),
            "--packs-feed-url" => packs_feed_url = it.next().cloned(),
            "--threat-feed-url" => threat_feed_url = it.next().cloned(),
            "--ticket-poll-url" => ticket_poll_url = it.next().cloned(),
            "--snapshot-interval-ms" => snapshot_interval_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--snapshot-frameworks" => snapshot_frameworks = it.next().map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default(),
            "--approval-sla-ms" => approval_sla_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--node-id" => node_id = it.next().cloned(),
            "--lease-ttl-ms" => lease_ttl_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(15_000),
            "--cp-key" => { if let Some(v) = it.next() { cp_key = v.clone(); } }
            "--oidc-jwks" => oidc_jwks = it.next().cloned(),
            "--oidc-issuer" => oidc_issuer = it.next().cloned(),
            "--oidc-audience" => oidc_audience = it.next().cloned(),
            "--dev-auth" => dev_auth = true,
            "--entra-tenant" => entra_tenant = it.next().cloned(),
            "--entra-audience" => entra_audience = it.next().cloned(),
            "--entra-preflight" => entra_preflight = true,
            "--entra-test-token" => entra_test_token = it.next().cloned(),
            "--break-glass-file" => break_glass_file = it.next().cloned(),
            "--tls-ca" => tls_ca = it.next().cloned(),
            "--tls-cert" => tls_cert = it.next().cloned(),
            "--tls-key" => tls_key = it.next().cloned(),
            "--break-glass-key" => {
                if let Some(h) = it.next() {
                    match hex::decode(acp_core::secret::resolve(h)) {
                        Ok(b) if b.len() == 32 => {
                            let mut s = [0u8; 32];
                            s.copy_from_slice(&b);
                            break_glass_seed = Some(s);
                        }
                        _ => {
                            tracing::error!("--break-glass-key must be a 32-byte hex seed");
                            std::process::exit(2);
                        }
                    }
                }
            }
            other => {
                tracing::warn!("unknown option '{other}'");
                std::process::exit(2);
            }
        }
    }

    // R7: real-Entra cutover preflight. Verifies the identity setup without starting the full server:
    // fetch the JWKS from the derived Entra/OIDC endpoint, confirm it parses and has keys, and (if a
    // sample token is given) run the full verification and print each claim check and the effective
    // capabilities. Exits 0 on success, 1 on any failure. Gated only on a customer tenant + token.
    if entra_preflight {
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        let (issuer, audience, source) = match resolved {
            Some(t) => t,
            None => {
                eprintln!("preflight: need --entra-tenant + --entra-audience (or the --oidc-* flags)");
                std::process::exit(1);
            }
        };
        println!("entra preflight");
        println!("  issuer:   {issuer}");
        println!("  audience: {audience}");
        println!("  jwks:     {source}");
        let jwks = match load_jwks(&source).await {
            Ok(j) => { println!("  [ok] JWKS fetched: {} key(s)", j.key_count()); j }
            Err(e) => { println!("  [FAIL] JWKS load: {e}"); std::process::exit(1); }
        };
        if let Some(tok) = &entra_test_token {
            let cfg = acp_auth::EntraConfig { issuer, audience };
            match acp_auth::verify(tok, &jwks, &cfg, now_ms()) {
                Ok(p) => {
                    println!("  [ok] token verified");
                    println!("       oid={} user={} tid={}", p.oid, p.username, p.tenant);
                    println!("       roles: {}", if p.roles.is_empty() { "(none)".to_string() } else { p.roles.join(", ") });
                    let caps: Vec<String> = p.capabilities().into_iter().map(|c| format!("{c:?}")).collect();
                    println!("       capabilities: {}", if caps.is_empty() { "(none, fail-closed)".to_string() } else { caps.join(", ") });
                    if p.roles.is_empty() {
                        println!("  [warn] token carries no app roles; the principal can do nothing. Assign app roles in Entra.");
                    }
                }
                Err(e) => { println!("  [FAIL] token verification: {e:?}"); std::process::exit(1); }
            }
        } else {
            println!("  [note] no --entra-test-token given; JWKS reachability only. Pass a real token to verify iss/aud/nbf/exp/signature/roles end to end.");
        }
        println!("preflight OK");
        std::process::exit(0);
    }

    let policy = match policy_path {
        Some(p) => match std::fs::read_to_string(&p).ok().and_then(|src| {
            acp_policy::PolicyEngine::from_yaml(&src)
                .ok()
                .map(|e| (e.hash().to_string(), src))
        }) {
            Some(v) => Some(v),
            None => {
                tracing::error!("could not load policy {p}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    // H0.7: a tamper-evident meta-audit ledger for admin actions (policy/key/RBAC changes).
    let meta = meta_ledger.and_then(|path| {
        let key_path = format!("{path}.key");
        let signer: Box<dyn acp_core::sign::Signer + Send> = match std::fs::read(&key_path) {
            Ok(b) if b.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b);
                Box::new(acp_core::sign::Ed25519Signer::from_seed(&s))
            }
            _ => {
                let s = acp_core::sign::Ed25519Signer::generate();
                let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
                Box::new(s)
            }
        };
        // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE).
        let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_hsm::signer_from_env() {
            Some(Ok(hsm)) => { tracing::info!("meta-ledger signing with a PKCS#11 HSM"); hsm }
            Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
            None => signer,
        };
        match acp_ledger::Ledger::open(&path, signer) {
            Ok(l) => Some(std::sync::Mutex::new(l)),
            Err(e) => {
                tracing::error!("could not open meta-ledger {path}: {e}");
                None
            }
        }
    });

    if dev_auth && std::env::var("ACP_ALLOW_DEV_AUTH").ok().as_deref() != Some("1") {
        tracing::info!("--dev-auth requires ACP_ALLOW_DEV_AUTH=1 (never enable in production)");
        std::process::exit(2);
    }
    // Control-plane RBAC (opt-in). Three ways to enable, in priority order:
    //   --dev-auth                         : in-memory mock issuer (local use)
    //   --entra-tenant + --entra-audience  : real Entra; issuer + JWKS URL derived from the tenant
    //   --oidc-jwks(url|file) + --oidc-issuer + --oidc-audience : explicit
    // With none, RBAC is off and the local demo is unaffected.
    let auth: Option<Auth> = if dev_auth {
        let mock = acp_auth::MockEntra::new("common", "acp-app");
        tracing::info!("DEV auth enabled (mock issuer); GET /auth/dev-token?role=PolicyAdmin");
        Some(Auth {
            jwks: std::sync::Arc::new(std::sync::RwLock::new(mock.jwks())),
            cfg: mock.config(),
            dev: Some(mock),
        })
    } else {
        // Resolve (issuer, audience, jwks_source) from either the Entra convenience flags or the
        // explicit OIDC flags.
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        match resolved {
            Some((issuer, audience, source)) => match load_jwks(&source).await {
                Ok(jwks) => {
                    tracing::info!("OIDC RBAC enabled (issuer {issuer}, aud {audience})");
                    let jwks_arc = std::sync::Arc::new(std::sync::RwLock::new(jwks));
                    // Key rotation: refresh the JWKS hourly when it came from a URL.
                    if source.starts_with("http") {
                        let arc = jwks_arc.clone();
                        let url = source.clone();
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                                if let Ok(fresh) = load_jwks(&url).await {
                                    *arc.write().unwrap() = fresh;
                                }
                            }
                        });
                    }
                    Some(Auth {
                        jwks: jwks_arc,
                        cfg: acp_auth::EntraConfig { issuer, audience },
                        dev: None,
                    })
                }
                Err(e) => {
                    tracing::error!("could not load JWKS from {source}: {e}; refusing to start (auth was requested, failing closed)");
                    std::process::exit(1);
                }
            },
            None => None,
        }
    };
    // Config-driven control-plane store (identity, endpoints; GRC later). The backend is chosen by
    // the --store URL (sqlite / postgres / mysql). Fail closed if it was requested but cannot connect.
    let store = match store_url {
        Some(u) => match acp_cpstore::ControlStore::connect(&u).await {
            Ok(s) => {
                tracing::info!("control-plane store connected");
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::error!("cannot connect --store: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
        liveness: std::sync::Mutex::new(acp_core::liveness::GapDetector::new()),
        spikes: std::sync::Mutex::new(std::collections::HashMap::new()),
        meta,
        registry,
        policy_store,
        enrollment,
        store,
        cp_key,
        break_glass_file,
        break_glass_seed,
        auth,
        report_token,
        events: std::sync::Mutex::new(std::collections::VecDeque::new()),
        scim_users: load_scim_users(scim_users_path.as_deref()),
        node_id: node_id.unwrap_or_else(|| format!("node-{}", rand_hex(6))),
        lease_ttl_ms,
        model_scanner_url,
        model_scan_block,
        webhook_url,
        webhook_secret,
        packs_feed_url,
        threat_feed_url,
        ticket_poll_url,
        snapshot_interval_ms,
        snapshot_frameworks,
        approval_sla_ms,
        escalated: std::sync::Mutex::new(std::collections::HashSet::new()),
        lease: std::sync::Mutex::new((false, String::new(), 0)),
    });
    // C1 (HA): restore persisted liveness/spike state so the dead-man's-switch and alert state survive
    // a restart, then start the leader-lease loop (shared-store fencing prevents split-brain).
    if let Some(store) = state.store.clone() {
        restore_control_state(&state, &store).await;
        let st2 = state.clone();
        let node = st2.node_id.clone();
        let ttl = st2.lease_ttl_ms.max(3000);
        tracing::info!("HA leader lease active as node '{node}' (ttl {ttl}ms)");
        tokio::spawn(async move {
            let period = std::time::Duration::from_millis(((ttl / 3).max(1000)) as u64);
            loop {
                match store.try_acquire_leader(&node, now_ms() as i64, ttl).await {
                    Ok((is_leader, holder, token)) => { *st2.lease.lock().unwrap() = (is_leader, holder, token); }
                    Err(e) => tracing::warn!("leader lease error: {e}"),
                }
                // Prune spike-event keys older than the detection window so control_state stays bounded.
                let cutoff = now_ms() as i64 - 300_000;
                if let Ok(rows) = store.list_state_prefix("spike:").await {
                    for (k, _) in rows {
                        if let Some(ts) = k.rsplit(':').next().and_then(|t| t.parse::<i64>().ok()) {
                            if ts < cutoff { let _ = store.delete_state(&k).await; }
                        }
                    }
                }
                tokio::time::sleep(period).await;
            }
        });
    }
    // G5: poll optional signed-pack / threat-pack feeds and load verified content on an interval.
    if let (Some(store), Some(feed)) = (state.store.clone(), state.packs_feed_url.clone()) {
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if let Some(arr) = v.get("packs").and_then(|p| p.as_array()) {
                            for one in arr {
                                if let Ok(signed) = serde_json::from_value::<acp_core::pack::SignedPack>(one.clone()) {
                                    if acp_core::pack::verify(&signed) {
                                        let p = &signed.pack;
                                        let id = p.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let version = p.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        if !id.is_empty() {
                                            let _ = store.add_pack(&id, &version, &p.to_string(), &signed.pubkey_hex, &signed.sig_hex, now_ms() as i64).await;
                                        }
                                    } else {
                                        tracing::warn!("packs feed: rejected a pack (signature verification failed)");
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }
    if let (Some(store), Some(feed)) = (state.store.clone(), state.threat_feed_url.clone()) {
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if let Ok(signed) = serde_json::from_value::<acp_core::threatfeed::SignedThreatPack>(v.clone()) {
                            if acp_core::threatfeed::verify(&signed) {
                                let version = signed.pack.get("version").and_then(|x| x.as_i64()).unwrap_or(0);
                                let sigs = signed.pack.get("signatures").cloned().unwrap_or_else(|| serde_json::json!([])).to_string();
                                let _ = store.set_firewall_threat("default", version, &sigs, now_ms() as i64).await;
                            } else {
                                tracing::warn!("threat feed: rejected a pack (signature verification failed)");
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }
    // M2: poll a ticket-resolution feed and apply each resolution (idempotent), the pull complement to
    // the inbound /tickets/callback.
    if let Some(feed) = state.ticket_poll_url.clone() {
        let st2 = state.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        let items = v.get("resolutions").and_then(|r| r.as_array()).cloned()
                            .or_else(|| v.as_array().cloned()).unwrap_or_default();
                        for item in items {
                            let action = item.get("action").and_then(|x| x.as_str()).unwrap_or("");
                            let id = item.get("id").and_then(|x| x.as_str()).unwrap_or("");
                            let status = item.get("status").and_then(|x| x.as_str());
                            let tenant = item.get("tenant").and_then(|x| x.as_str()).unwrap_or("default");
                            if !action.is_empty() && !id.is_empty() {
                                let _ = apply_ticket_resolution(&st2, action, id, status, tenant).await;
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }
    // M3: periodic framework-report snapshots + delivery (fires a signed report.snapshot webhook).
    if state.snapshot_interval_ms > 0 && !state.snapshot_frameworks.is_empty() && state.store.is_some() {
        let st2 = state.clone();
        tokio::spawn(async move {
            let interval = std::time::Duration::from_millis(st2.snapshot_interval_ms.max(1000) as u64);
            loop {
                tokio::time::sleep(interval).await;
                if let Some(store) = &st2.store {
                    for name in &st2.snapshot_frameworks {
                        let report = framework_report_value(&st2, "default", name).await;
                        let id = format!("snap-{}", rand_hex(8));
                        if store.add_snapshot(&id, name, "default", &report.to_string(), now_ms() as i64).await.is_ok() {
                            fire_webhook(&st2, "report.snapshot", serde_json::json!({
                                "framework": name, "id": id,
                                "coverage": report.get("coverage"), "controls_summary": report.get("controls_summary"),
                            }));
                        }
                    }
                }
            }
        });
    }
    // M4: escalate approval holds that sit pending past the SLA (one approval.overdue webhook per hold).
    if state.approval_sla_ms > 0 && state.approvals.is_some() {
        let st2 = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let path = match &st2.approvals { Some(p) => p.clone(), None => continue };
                if let Ok(store) = acp_approvals::ApprovalStore::open(&path) {
                    if let Ok(ids) = store.list_overdue(st2.approval_sla_ms as u64, now_ms()) {
                        for id in ids {
                            let already = { st2.escalated.lock().unwrap().contains(&id) };
                            if already { continue; }
                            st2.escalated.lock().unwrap().insert(id.clone());
                            fire_webhook(&st2, "approval.overdue", serde_json::json!({"id": id, "sla_ms": st2.approval_sla_ms}));
                        }
                    }
                }
            }
        });
    }
    let app = Router::new()
        .route("/", get(inbox))
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route("/approvals/register", post(approval_register))
        .route("/approvals/:id/status", get(approval_status))
        .route("/approvals/:id/approve", post(approve))
        .route("/approvals/:id/deny", post(deny))
        .route("/policy/current", get(policy_current))
        .route("/verify", get(verify))
        .route("/report", get(report))
        .route("/metrics", get(metrics))
        .route("/heartbeat/:proxy", post(heartbeat))
        .route("/liveness", get(liveness))
        .route("/event/:kind", post(record_event))
        .route("/tickets/callback", post(ticket_callback))
        .route("/monitor/drift", get(monitor_drift_get).post(monitor_drift_post))
        .route("/monitor/lineage", get(monitor_lineage_get).post(monitor_lineage_post))
        .route("/alerts", get(alerts))
        .route("/events/recent", get(events_recent))
        .route("/report/violations", get(report_violations))
        .route("/report/framework/:name", get(report_framework))
        .route("/report/framework/:name/csv", get(report_framework_csv))
        .route("/report/framework/:name/snapshot", post(report_framework_snapshot))
        .route("/report/framework/:name/history", get(report_framework_history))
        .route("/report/violations.csv", get(report_violations_csv))
        .route("/evidence/ingest", post(evidence_ingest))
        .route("/evidence/ingested", get(evidence_ingested))
        .route("/admin/meta", post(record_meta))
        .route("/meta-audit", get(meta_audit))
        .route("/timeline", get(timeline))
        .route("/apps", get(apps))
        .route("/agents", get(agents))
        .route("/policy-store", get(policy_store_current))
        .route("/policy-store/rules", get(policy_store_rules))
        .route("/policy-store/deploy", post(policy_store_deploy))
        .route("/endpoints", get(endpoints_list))
        .route("/endpoints/register", post(endpoints_register))
        .route("/intercept/rules", get(intercept_rules))
        .route("/firewall/config", get(firewall_config_get).post(firewall_config_set))
        .route("/firewall/threat-pack", post(threat_pack_load))
        .route("/firewall/threat-pack/available", get(threat_pack_available))
        .route("/firewall/rules", get(firewall_rules_list).post(firewall_rules_add))
        .route("/firewall/rules/:id/delete", post(firewall_rules_delete))
        .route("/apps", post(app_register))
        .route("/agents", post(agent_register))
        .route("/agents/:id/deactivate", post(agent_deactivate))
        .route("/agents/verify", post(agent_verify))
        .route("/grc", get(grc_list).post(grc_create))
        .route("/grc/templates", get(grc_templates))
        .route("/redteam/run", post(redteam_run))
        .route("/redteam/runs", get(redteam_runs))
        .route("/grc/assess", post(grc_assess))
        .route("/grc/risk", post(grc_risk))
        .route("/grc/model-card", post(grc_model_card))
        .route("/grc/:id/status", post(grc_status))
        .route("/grc/:id/usecase/:stage", post(grc_usecase_transition))
        .route("/grc/:id/assign", post(grc_assign))
        .route("/grc/:id/link", post(grc_link))
        .route("/grc/:id/comments", get(grc_comments_get).post(grc_comments_post))
        .route("/grc/:id/control/:control_id", post(grc_control_toggle))
        .route("/approvals/pending", get(approvals_pending))
        .route("/evidence/recent", get(evidence_recent))
        .route("/break-glass", get(break_glass_status))
        .route("/break-glass/engage", post(break_glass_engage))
        .route("/break-glass/clear", post(break_glass_clear))
        .route("/packs", get(packs_list).post(pack_load))
        .route("/packs/available", get(packs_available))
        .route("/controls", get(controls_list))
        .route("/models", get(models_list).post(model_register))
        .route("/models/:id", get(model_get))
        .route("/vendors", get(vendors_list).post(vendor_register))
        .route("/vendors/:id/review", post(vendor_review))
        .route("/leader", get(leader_status))
        .route("/tenants", get(tenants_list))
        .route("/scim/v2/Users", get(scim_users))
        .route("/scim/v2/Groups", get(scim_groups))
        .route("/auth/dev-token", get(dev_token))
        .with_state(state);

    // mTLS between components: when TLS flags are given, require a client cert signed by the ACP CA.
    if let (Some(ca), Some(cert), Some(key)) = (&tls_ca, &tls_cert, &tls_key) {
        tracing::error!("listening on https://{addr} (mTLS, client cert required)");
        serve_mtls(&addr, app, ca, cert, key).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!("listening on http://{addr}");
    // X.7: drain in-flight requests on SIGTERM/Ctrl-C instead of dropping them. The evidence
    // ledger is durable per-append, so a clean drain loses no decision and double-executes none.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");
}

async fn inbox(State(st): State<Arc<AppState>>) -> Html<String> {
    let items = match &st.approvals {
        Some(p) => acp_approvals::ApprovalStore::open(p)
            .and_then(|s| s.list_pending())
            .unwrap_or_default(),
        None => vec![],
    };
    let page = html! {
        (DOCTYPE)
        html {
            head { title { "ACP approvals" }
                style { "body{font:15px system-ui;margin:2rem;max-width:760px} .card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:10px 0} button{margin-right:8px;padding:6px 12px} .meta{color:#666;font-size:.85em}" } }
            body {
                h1 { "Pending approvals" }
                @if items.is_empty() { p { "No pending approvals." } }
                @for a in &items {
                    div.card {
                        div { b { (a.tool) } }
                        // maud auto-escapes: attacker-controlled presented context cannot inject markup (M4.5)
                        div.meta { "presented: " (a.presented.to_string()) }
                        div.meta { "id: " (a.id) }
                        form method="post" action=(format!("/approvals/{}/approve", a.id)) style="display:inline" { button { "Approve" } }
                        form method="post" action=(format!("/approvals/{}/deny", a.id)) style="display:inline" { button { "Deny" } }
                    }
                }
            }
        }
    };
    Html(page.into_string())
}

async fn approve(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::Approve) { Ok(p) => p, Err(r) => return r };
    resolve(&st, &id, true, &actor_of(&principal));
    Redirect::to("/").into_response()
}
async fn deny(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::Approve) { Ok(p) => p, Err(r) => return r };
    resolve(&st, &id, false, &actor_of(&principal));
    Redirect::to("/").into_response()
}
fn resolve(st: &AppState, id: &str, ok: bool, actor: &str) {
    if let Some(p) = &st.approvals {
        if let Ok(store) = acp_approvals::ApprovalStore::open(p) {
            let _ = store.resolve(id, ok, actor, "web");
        }
    }
}

/// F1: a PEP registers a step-up hold raised in the field, so it appears in the console Approvals
/// inbox and can be resolved centrally. Gated by the shared report token (PEP identity). Idempotent.
async fn approval_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize_report(&st, &headers) { return r; }
    let path = match &st.approvals { Some(p) => p.clone(), None => return Json(serde_json::json!({"ok": false, "error": "no approvals store"})).into_response() };
    let store = match acp_approvals::ApprovalStore::open(&path) { Ok(s) => s, Err(e) => return Json(serde_json::json!({"ok": false, "error": e})).into_response() };
    let g = |k: &str| body.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = g("id");
    if id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "id is required"})).into_response(); }
    let presented = body.get("presented").cloned().unwrap_or_else(|| serde_json::json!({}));
    let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(15 * 60 * 1000);
    match store.request(&id, &g("session"), &g("principal"), &g("tool"), &g("arg_hash"), &presented, ttl_ms) {
        Ok(created) => Json(serde_json::json!({"ok": true, "id": id, "created": created})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// F1: the resolution state of a hold, so a PEP can poll for the console operator's decision.
async fn approval_status(State(st): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let path = match &st.approvals { Some(p) => p.clone(), None => return Json(serde_json::json!({"state": "unknown"})).into_response() };
    let store = match acp_approvals::ApprovalStore::open(&path) { Ok(s) => s, Err(_) => return Json(serde_json::json!({"state": "unknown"})).into_response() };
    match store.get(&id) {
        Ok(Some(v)) => Json(serde_json::json!({"state": v.state, "approver": v.approver})).into_response(),
        Ok(None) => Json(serde_json::json!({"state": "unknown"})).into_response(),
        Err(e) => Json(serde_json::json!({"state": "error", "error": e})).into_response(),
    }
}

async fn policy_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.policy {
        Some((hash, body)) => {
            Json(serde_json::json!({"hash": hash, "body": body, "max_staleness_s": 30}))
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no policy configured").into_response(),
    }
}

async fn verify(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.ledger {
        Some(l) => match acp_ledger::verify_file(l) {
            Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
            Err(e) => Json(serde_json::json!({"ok": false, "detail": e})).into_response(),
        },
        None => (axum::http::StatusCode::NOT_FOUND, "no ledger configured").into_response(),
    }
}

async fn metrics(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let pack = st
        .ledger
        .as_ref()
        .and_then(|l| acp_ledger::export_file(l).ok());
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
    ([("content-type", "text/plain; version=0.0.4")], out)
}

async fn report(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st
        .ledger
        .as_ref()
        .and_then(|l| acp_ledger::export_file(l).ok())
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
async fn timeline(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.ledger.as_ref() {
        Some(path) => match acp_ledger::ordered_by_hlc(path) {
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

/// H0.7: record a self-governance change (policy/key/RBAC/approver/break-glass) to the tamper-
/// evident meta-audit log. Body: {kind, actor, reason, before?, after?}.
async fn record_meta(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { Ok(p) => p, Err(r) => return r };
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
async fn meta_audit(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.meta.as_ref() {
        Some(meta) => {
            let l = meta.lock().unwrap();
            Json(serde_json::json!({"configured": true, "size": l.size(), "verified": l.verify().is_ok()}))
        }
        None => Json(serde_json::json!({"configured": false})),
    }
}

/// Recent governed decisions (tool, verdict, agent, hlc) for the console evidence view.
async fn evidence_recent(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A5: the raw decision detail (per-action tool/resource/principal) requires SeeArgs
    // (SecurityOfficer). Aggregate dashboards use ungated summary routes instead.
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::SeeArgs) { return r; }
    let recs = match st.ledger.as_ref().and_then(|p| acp_ledger::export_file(p).ok()) {
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

/// Pending approvals as JSON (for the console).
async fn approvals_pending(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let items = match &st.approvals {
        Some(p) => acp_approvals::ApprovalStore::open(p).and_then(|s| s.list_pending()).unwrap_or_default(),
        None => vec![],
    };
    let list: Vec<_> = items.iter().map(|a| serde_json::json!({"id": a.id, "tool": a.tool})).collect();
    Json(serde_json::json!({"pending": list}))
}

/// Registered apps (read-only view for the console).
async fn apps(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let tenant = tenant_of(&headers, &None);
    if let Some(store) = &st.store {
        match store.list_apps(&tenant).await {
            Ok(apps) => return Json(serde_json::json!({"apps": apps})).into_response(),
            Err(e) => return Json(serde_json::json!({"apps": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.apps().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"owner":a.owner})).collect();
            Json(serde_json::json!({"apps": list})).into_response()
        }
        _ => Json(serde_json::json!({"apps": []})).into_response(),
    }
}

/// Registered agents (read-only).
async fn agents(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let tenant = tenant_of(&headers, &None);
    if let Some(store) = &st.store {
        match store.list_agents(&tenant).await {
            Ok(agents) => return Json(serde_json::json!({"agents": agents})).into_response(),
            Err(e) => return Json(serde_json::json!({"agents": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.agents().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"app_id":a.app_id,"active":a.active})).collect();
            Json(serde_json::json!({"agents": list})).into_response()
        }
        _ => Json(serde_json::json!({"agents": []})).into_response(),
    }
}

/// Current deployed signed policy (version/hash/author) from the policy store.
async fn policy_store_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.policy_store.as_ref().map(|p| acp_policy::store::current_info(p)) {
        Some(Ok(v)) => Json(v),
        _ => Json(serde_json::json!({"version": 0})),
    }
}

/// Load-or-create the Ed25519 signer used to sign console-initiated deployments. Persisted next to
/// the store so the signed manifest stays verifiable across restarts. The proxy trusts the pubkey
/// embedded in current.json (tamper-evidence of the file against the signed hash).
/// Sign endpoint dispositions with a key kept next to the enrollment log (created 0600 if absent).
/// M1: derive a deterministic per-tenant Ed25519 signer from the control-plane key seed + tenant id,
/// so each tenant's records are signed with a distinct key (still verifiable via the embedded pubkey).
fn tenant_signer(path: &str, tenant: &str) -> acp_core::sign::Ed25519Signer {
    if tenant == "default" { return enroll_signer(path); }
    let base = enroll_signer(path).seed();
    let mut seed = [0u8; 32];
    let derived = acp_core::canonical::sha256_hex_bytes(&[&base[..], b":", tenant.as_bytes()].concat());
    let bytes = hex::decode(&derived).unwrap_or_default();
    seed.copy_from_slice(&bytes[..32]);
    acp_core::sign::Ed25519Signer::from_seed(&seed)
}

fn enroll_signer(path: &str) -> acp_core::sign::Ed25519Signer {
    let key_path = format!("{path}.key");
    match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            acp_core::sign::Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            s
        }
    }
}

fn load_enrollment(path: &str) -> acp_core::enrollment::EnrollmentLog {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn ai_kind_str(ep: &str) -> (String, String) {
    // (kind, provider) from the discovery classifier; falls back to a generic endpoint.
    match acp_core::discovery::classify_ai(ep) {
        Some(ai) => {
            let kind = match ai.kind {
                acp_core::discovery::AiKind::ModelApi => "model-api",
                acp_core::discovery::AiKind::Mcp => "mcp",
            };
            (kind.to_string(), ai.provider)
        }
        None => ("endpoint".to_string(), "unclassified".to_string()),
    }
}

/// GET /endpoints: the latest disposition per registered AI endpoint, with the provider classified
/// (OpenAI / Anthropic / xAI / Google / ...), for the console to list.
async fn endpoints_list(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    // Config-driven store first (identity/endpoints in a DB). Falls back to the enrollment file.
    if let Some(store) = &st.store {
        let now = now_ms();
        return match store.list_endpoints().await {
            Ok(eps) => {
                let out: Vec<serde_json::Value> = eps
                    .iter()
                    .map(|e| {
                        let active = e.expires_ms == 0 || now < e.expires_ms as u64;
                        serde_json::json!({
                            "endpoint": e.endpoint, "provider": e.provider, "kind": e.kind,
                            "disposition": e.disposition, "operator": e.operator, "reason": e.reason,
                            "active": active, "verified": true,
                        })
                    })
                    .collect();
                Json(serde_json::json!({"configured": true, "endpoints": out})).into_response()
            }
            Err(e) => Json(serde_json::json!({"configured": true, "endpoints": [], "error": e})).into_response(),
        };
    }
    let path = match &st.enrollment {
        Some(p) => p.clone(),
        None => return Json(serde_json::json!({"configured": false, "endpoints": []})).into_response(),
    };
    let log = load_enrollment(&path);
    let mut by_ep: std::collections::BTreeMap<&str, &acp_core::enrollment::EndpointDisposition> =
        std::collections::BTreeMap::new();
    for d in &log.dispositions {
        match by_ep.get(d.endpoint.as_str()) {
            Some(existing) if existing.decided_ms >= d.decided_ms => {}
            _ => {
                by_ep.insert(&d.endpoint, d);
            }
        }
    }
    let now = now_ms();
    let out: Vec<serde_json::Value> = by_ep
        .values()
        .map(|d| {
            let (_kind, provider) = ai_kind_str(&d.endpoint);
            let (dispo, active) = match d.disposition {
                acp_core::enrollment::Disposition::Enroll => ("govern", true),
                acp_core::enrollment::Disposition::Quarantine => ("block", true),
                acp_core::enrollment::Disposition::AcceptRisk { expires_ms } => ("accept-risk", now < expires_ms),
            };
            serde_json::json!({
                "endpoint": d.endpoint, "provider": provider, "kind": d.kind,
                "disposition": dispo, "operator": d.operator, "reason": d.reason,
                "active": active, "verified": d.verify(),
            })
        })
        .collect();
    Json(serde_json::json!({"configured": true, "endpoints": out})).into_response()
}

/// B5: the built-in sample threat pack, signed with the control-plane key so an operator can load it.
async fn threat_pack_available(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let signer = enroll_signer(&st.cp_key);
    let pack = acp_core::threatfeed::builtin_threat_pack(now_ms(), now_ms());
    Json(serde_json::to_value(pack.sign(&signer)).unwrap_or_default())
}

/// B5: load a signed threat pack. The signature is verified before storing; a tampered pack is
/// rejected. On success the firewall_config feed version is bumped and the signatures stored, so every
/// acp-agent applies them on its next firewall fetch.
async fn threat_pack_load(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditFirewall) { return r; }
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

/// GET /firewall/config: the central content-firewall configuration (toggles, denied topics, and the
/// ML model content), so a workstation PEP fetches everything from the control plane instead of
/// carrying local files. Ungated (same trust as the governed rule set). Returns a safe default when
/// no config has been set yet.
async fn firewall_config_get(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
async fn firewall_config_set(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditFirewall) { return r; }
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
async fn intercept_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
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

const FW_ACTIONS: &[&str] = &["inspect-prompt", "govern-tool-call", "dlp-only", "block", "pass"];

/// GET /firewall/rules: operator-authored interception rules (for the console Firewall rules screen).
async fn firewall_rules_list(State(st): State<Arc<AppState>>) -> Response {
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
async fn firewall_rules_add(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditFirewall) { return r; }
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
async fn firewall_rules_delete(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditFirewall) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    match store.delete_firewall_rule(&id).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /endpoints/register: record a signed disposition for an AI endpoint. Body:
/// {endpoint, disposition: govern|block|accept-risk, reason}. The provider is classified server-side,
/// and the record is stored in the control-plane DB when --store is set, else the enrollment file.
async fn endpoints_register(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) { Ok(p) => p, Err(r) => return r };
    let operator = actor_of(&principal);
    let endpoint = body.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if endpoint.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "endpoint is required"})).into_response();
    }
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let now = now_ms();
    let (disposition, dispo_str, expires): (acp_core::enrollment::Disposition, &str, i64) =
        match body.get("disposition").and_then(|v| v.as_str()).unwrap_or("govern") {
            "govern" | "enroll" => (acp_core::enrollment::Disposition::Enroll, "govern", 0),
            "block" | "quarantine" => (acp_core::enrollment::Disposition::Quarantine, "block", 0),
            "accept-risk" => {
                let e = now + 30 * 24 * 3600 * 1000;
                (acp_core::enrollment::Disposition::AcceptRisk { expires_ms: e }, "accept-risk", e as i64)
            }
            other => return Json(serde_json::json!({"ok": false, "error": format!("unknown disposition '{other}'")})).into_response(),
        };
    let (kind, provider) = ai_kind_str(&endpoint);

    if let Some(store) = &st.store {
        let signer = enroll_signer(&st.cp_key);
        let mut log = acp_core::enrollment::EnrollmentLog::new();
        let d = log.record(&signer, &endpoint, &kind, disposition, &operator, &reason, now).clone();
        return match store
            .upsert_endpoint(&endpoint, &kind, &provider, dispo_str, &operator, &reason, d.decided_ms as i64, expires, &d.pubkey_hex, &d.sig_hex)
            .await
        {
            Ok(()) => Json(serde_json::json!({"ok": true, "endpoint": endpoint, "provider": provider, "kind": kind})).into_response(),
            Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
        };
    }

    let path = match &st.enrollment {
        Some(p) => p.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no store configured (--store or --enrollment)"})).into_response(),
    };
    let mut log = load_enrollment(&path);
    let signer = enroll_signer(&path);
    log.record(&signer, &endpoint, &kind, disposition, &operator, &reason, now);
    match serde_json::to_string_pretty(&log) {
        Ok(s) => {
            if std::fs::write(&path, s).is_err() {
                return Json(serde_json::json!({"ok": false, "error": "cannot write enrollment store"})).into_response();
            }
        }
        Err(_) => return Json(serde_json::json!({"ok": false, "error": "serialise enrollment"})).into_response(),
    }
    Json(serde_json::json!({"ok": true, "endpoint": endpoint, "provider": provider, "kind": kind})).into_response()
}

/// Random hex, for generated ids and one-time agent tokens.
fn rand_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    let _ = getrandom::getrandom(&mut b);
    hex::encode(b)
}

/// POST /agents/verify: the enforcement path verifies an agent by id + token against the store, so a
/// DB-registered agent is honoured without a registry file. Returns the display identity when valid.
/// Ungated: it only confirms a token the caller already holds.
async fn agent_verify(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let token_sha = acp_core::canonical::sha256_hex_bytes(token.as_bytes());
    match store.verify_agent_identity(id, &token_sha).await {
        Ok(Some((agent, app_id, app))) => Json(serde_json::json!({"ok": true, "verified": true, "agent": agent, "app_id": app_id, "app": app})).into_response(),
        Ok(None) => Json(serde_json::json!({"ok": true, "verified": false})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /apps: register an application in the control-plane store. Body: {name, owner}.
async fn app_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterApp) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "name is required"})).into_response(); }
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let metadata = body.get("metadata").map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());
    let id = format!("app-{}", rand_hex(6));
    let tenant = tenant_of(&headers, &None);
    match store.add_app(&id, &name, &owner, &metadata, &tenant, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "name": name})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /agents: register an agent. Body: {app_id, name}. Returns a one-time token (stored hashed).
async fn agent_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let app_id = body.get("app_id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if app_id.is_empty() || name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "app_id and name are required"})).into_response(); }
    let owner = body.get("owner").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let metadata = body.get("metadata").map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());
    let id = format!("agt-{}", rand_hex(6));
    let token = rand_hex(24);
    let token_sha = acp_core::canonical::sha256_hex_bytes(token.as_bytes());
    let tenant = tenant_of(&headers, &None);
    match store.add_agent(&id, &app_id, &name, &token_sha, &owner, &metadata, &tenant, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "token": token, "note": "store this token now; it is not shown again"})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /agents/:id/deactivate: revoke an agent.
async fn agent_deactivate(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    match store.deactivate_agent(&id).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

const GRC_KINDS: &[&str] = &["assessment", "conformity", "risk", "model-card", "use-case", "attestation", "aibom"];

fn grc_doc(id: &str, kind: &str, subject: &str, title: &str, status: &str, body: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "kind": kind, "subject": subject, "title": title, "status": status, "body": body})
}

/// GET /grc: list all governance records (the console groups them by kind). Each is re-verified
/// against its embedded public key, so the "signed" state shown is checked, not asserted.
async fn grc_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
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
async fn grc_create(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
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
async fn grc_status(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { return r; }
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
/// B4: run the red-team corpus against the current content-firewall configuration, then store the
/// result as a signed GRC attestation record (so runs accumulate as a time series). A run below
/// --min-catch is stored with status "failed" so it is visibly flagged. A scheduled runner (cron)
/// simply calls this endpoint on an interval.
async fn redteam_run(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditFirewall) { Ok(p) => p, Err(r) => return r };
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
async fn redteam_runs(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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

/// A1: the built-in EU AI Act screening questionnaire. Served so the console can render a guided
/// "New assessment" wizard. Each entry is a yes/no question mapped to an assessment flag.
async fn grc_templates() -> impl IntoResponse {
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
async fn grc_model_card(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
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
async fn grc_risk(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
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
async fn grc_assess(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
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

/// A1: set the assignee and due date on a GRC record (workflow metadata, no re-sign needed).
async fn grc_assign(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { return r; }
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
async fn grc_comments_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    let principal = match authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { Ok(p) => p, Err(r) => return r };
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
async fn grc_comments_get(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
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
async fn grc_link(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { return r; }
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
async fn grc_control_toggle(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, control_id)): Path<(String, String)>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { return r; }
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
async fn grc_usecase_transition(State(st): State<Arc<AppState>>, headers: HeaderMap, Path((id, stage)): Path<(String, String)>, Json(_body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditGrc) { return r; }
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

fn deploy_signer(store_dir: &str) -> acp_core::sign::Ed25519Signer {
    let key_path = format!("{store_dir}/deploy.key");
    let _ = std::fs::create_dir_all(store_dir);
    match std::fs::read(&key_path) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            acp_core::sign::Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = acp_core::sign::Ed25519Signer::generate();
            let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
            s
        }
    }
}

/// The rules of the current deployed policy, with app/agent ids resolved to registered names, so the
/// console can show which rule governs which app and agent. Read-only projection of the signed file.
async fn policy_store_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let src = match st.policy_store.as_ref().map(|p| acp_policy::store::current_source(p)) {
        Some(Ok(s)) => s,
        _ => return Json(serde_json::json!({"rules": [], "count": 0})),
    };
    let pol = match acp_policy::dsl::parse_str(&src) {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({"rules": [], "count": 0, "error": e.to_string()})),
    };
    let reg = st.registry.as_ref().and_then(|p| acp_registry::Registry::load(p).ok());
    let app_name = |m: &Option<String>| -> Option<String> {
        let id = m.as_deref()?;
        reg.as_ref()
            .and_then(|r| r.apps().into_iter().find(|a| a.id == id).map(|a| a.name.clone()))
            .or_else(|| Some(id.to_string()))
    };
    let agent_name = |m: &Option<String>| -> Option<String> {
        let id = m.as_deref()?;
        reg.as_ref()
            .and_then(|r| r.agents().into_iter().find(|a| a.id == id).map(|a| a.name.clone()))
            .or_else(|| Some(id.to_string()))
    };
    let _ = &app_name; // app is display-only now; kept for team resolution elsewhere.
    use acp_policy::dsl::ObligationKind;
    let rules: Vec<_> = pol
        .rules
        .iter()
        .map(|r| {
            let verdict = serde_json::to_value(&r.verdict)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "allow".to_string());
            let obligations: Vec<String> = r
                .obligations
                .iter()
                .map(|o| match o.kind {
                    ObligationKind::Confirm => "confirm".to_string(),
                    ObligationKind::Redact => format!("redact({})", o.fields.join(",")),
                    ObligationKind::RateLimit => {
                        format!("rate_limit({}/{}ms)", o.max.unwrap_or(0), o.window_ms.unwrap_or(0))
                    }
                })
                .collect();
            serde_json::json!({
                "id": r.id,
                "agent": r.when.agent,
                "agent_label": agent_name(&r.when.agent),
                "principal": r.when.principal,
                "resource": r.when.resource,
                "operation": r.when.operation,
                "tool": r.when.tool,
                "verdict": verdict,
                "obligations": obligations,
                "approvers": r.approvers,
                "reason": r.reason,
            })
        })
        .collect();
    let default = serde_json::to_value(&pol.default)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "allow".to_string());
    Json(serde_json::json!({"rules": rules, "count": pol.rules.len(), "default": default}))
}

/// Deploy a policy from the console: validate, version, sign, and write it to the store the proxy
/// watches. A policy that does not compile is rejected before anything is written; the proxy
/// hot-reloads the new version only after verifying the signature.
async fn policy_store_deploy(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::EditPolicy) {
        return r;
    }
    let store = match &st.policy_store {
        Some(s) => s.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no policy store configured"})).into_response(),
    };
    let src = body.get("policy").and_then(|v| v.as_str()).unwrap_or("");
    let author = body
        .get("author")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("console");
    if src.trim().is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "policy source is empty"})).into_response();
    }
    let signer = deploy_signer(&store);
    match acp_policy::store::deploy(src, &store, &signer, author) {
        Ok(d) => Json(serde_json::json!({"ok": true, "version": d.version, "hash": d.hash})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// Current break-glass status (what the proxy would be applying).
async fn break_glass_status(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    use acp_core::breakglass::GrantFile;
    match &st.break_glass_file {
        Some(f) => match std::fs::read(f).ok().and_then(|b| serde_json::from_slice::<GrantFile>(&b).ok()) {
            Some(g) => Json(serde_json::json!({
                "active": true, "mode": g.mode, "scope": g.scope, "reason": g.reason, "actor": g.actor, "signed": !g.sig.is_empty()
            })),
            None => Json(serde_json::json!({"active": false, "configured": true})),
        },
        None => Json(serde_json::json!({"active": false, "configured": false})),
    }
}

/// Engage break-glass: write a (signed, if a key is configured) scoped grant to the file the proxy
/// watches. This is a controlled action; the proxy applies it on its next decision.
async fn break_glass_engage(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::BreakGlass) {
        return r;
    }
    use acp_core::breakglass::{GrantFile, Mode, Scope};
    let file = match &st.break_glass_file {
        Some(f) => f.clone(),
        None => return Json(serde_json::json!({"ok": false, "error": "no break-glass file configured"})).into_response(),
    };
    let mode = match body.get("mode").and_then(|v| v.as_str()).and_then(Mode::parse) {
        Some(m) => m,
        None => return Json(serde_json::json!({"ok": false, "error": "invalid mode (lockdown_all|disable_enforce|emergency_bypass)"})).into_response(),
    };
    let scope = Scope::parse(body.get("scope").and_then(|v| v.as_str()).unwrap_or("global"));
    let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if reason.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "reason is required"})).into_response();
    }
    let actor = body.get("actor").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("console").to_string();
    let ttl_ms = body
        .get("ttl_ms")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
        .filter(|n| *n > 0)
        .unwrap_or(3_600_000);
    let mut grant = GrantFile::new_scoped(mode, scope, &reason, &actor, now_ms(), ttl_ms);
    if let Some(seed) = &st.break_glass_seed {
        grant.sign(&acp_core::sign::Ed25519Signer::from_seed(seed));
    }
    let json = serde_json::to_string_pretty(&grant).unwrap();
    if std::fs::write(&file, json).is_err() {
        return Json(serde_json::json!({"ok": false, "error": "cannot write grant file"})).into_response();
    }
    Json(serde_json::json!({"ok": true, "mode": grant.mode, "scope": grant.scope, "signed": !grant.sig.is_empty()})).into_response()
}

/// Clear break-glass: remove the grant file (the proxy reverts to normal on its next decision).
async fn break_glass_clear(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::BreakGlass) {
        return r;
    }
    if let Some(f) = &st.break_glass_file {
        let _ = std::fs::remove_file(f);
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

/// DEV ONLY: issue a mock bearer token for a role, so the console can authenticate without real
/// Entra during local use. Present only when --dev-auth is set.
/// A5 (SCIM 2.0): the role groups ACP recognises, in SCIM ListResponse shape, so an IdP or an
/// operator can see the provisionable groups and the capabilities each grants. Gated on Export
/// (read-only administrative view). Groups are the ACP role catalogue (single source of truth).
async fn scim_groups(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::Export) { return r; }
    let resources: Vec<serde_json::Value> = acp_auth::role_catalogue().into_iter().map(|(name, caps)| {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": name, "displayName": name,
            "urn:acp:capabilities": caps,
        })
    }).collect();
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(), "itemsPerPage": resources.len(), "startIndex": 1,
        "Resources": resources,
    })).into_response()
}

/// A5 (SCIM 2.0): the users known to ACP with their role-group memberships, in SCIM ListResponse
/// shape. Gated on Export. The source is the control-plane user directory when configured; in the
/// mocked-IdP dev setup it reflects the dev principal so the shape and mapping are exercisable.
async fn scim_users(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::Export) { return r; }
    // Users are provisioned by the IdP; here we surface the operators the control plane knows about.
    // With the dev mock issuer, that is the dev principal carrying whatever role it was minted with.
    let users = st.scim_users.clone();
    let resources: Vec<serde_json::Value> = users.into_iter().map(|(id, email, groups)| {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": id, "userName": email, "active": true,
            "groups": groups.iter().map(|g| serde_json::json!({"value": g, "display": g})).collect::<Vec<_>>(),
        })
    }).collect();
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(), "itemsPerPage": resources.len(), "startIndex": 1,
        "Resources": resources,
    })).into_response()
}

async fn dev_token(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> impl IntoResponse {
    match st.auth.as_ref().and_then(|a| a.dev.as_ref()) {
        Some(mock) => {
            let role = q.get("role").map(String::as_str).unwrap_or("PolicyAdmin");
            let tok = mock.issue("dev-oid", "dev@local", "common", &[role], now_ms(), 3600);
            Json(serde_json::json!({"token": tok, "role": role}))
        }
        None => Json(serde_json::json!({"error": "dev auth not enabled"})),
    }
}

/// Serve the axum app over mutual TLS: present the server cert and REQUIRE a client cert signed by
/// the ACP CA, so only enrolled components can reach the control API.
async fn serve_mtls(addr: &str, app: Router, ca: &str, cert: &str, key: &str) {
    acp_mtls::ensure_provider();
    let ca = std::fs::read(ca).expect("read tls-ca");
    let cert = std::fs::read(cert).expect("read tls-cert");
    let key = std::fs::read(key).expect("read tls-key");
    let cfg = acp_mtls::server_config(&ca, &cert, &key).expect("mtls server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t, // handshake fails here for a client with no/bad cert (mutual auth)
                Err(_) => return,
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// E1: PEP reporting routes present a shared bearer token when the server is configured with one.
/// Fail-closed when a token is set; open (dev) when it is not, with the check a no-op.
fn authorize_report(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let want = match &st.report_token { Some(t) => t, None => return Ok(()) };
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    if got == Some(want.as_str()) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"invalid report token"}))).into_response())
    }
}

/// B1: an enrolled proxy posts a heartbeat (and, implicitly, that it is serving governed traffic).
async fn heartbeat(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(proxy): Path<String>) -> Response {
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

/// T3: inbound ticketing callback. A ticket system (Jira/ServiceNow) posts a resolution here to close
/// the loop: resolve an approval hold, or advance a GRC record's status. HMAC-verified with the
/// webhook secret over the raw body (x-acp-signature: t=..,v1=..); rejected if the secret is unset or
/// the signature is bad. Body: {action: "approve"|"deny"|"grc-status", id, status?}.
async fn ticket_callback(State(st): State<Arc<AppState>>, headers: HeaderMap, raw: axum::body::Bytes) -> Response {
    let secret = match &st.webhook_secret {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return (StatusCode::FORBIDDEN, Json(serde_json::json!({"ok": false, "error": "ticket callbacks require --webhook-secret"}))).into_response(),
    };
    let sig = headers.get("x-acp-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
    let body_str = String::from_utf8_lossy(&raw).to_string();
    if !acp_core::webhook::verify_webhook(secret.as_bytes(), sig, &body_str, (now_ms() / 1000) as u64, 300) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false, "error": "signature verification failed"}))).into_response();
    }
    let body: serde_json::Value = serde_json::from_slice(&raw).unwrap_or_else(|_| serde_json::json!({}));
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if id.is_empty() { return Json(serde_json::json!({"ok": false, "error": "id is required"})).into_response(); }
    let status = body.get("status").and_then(|v| v.as_str()).map(|s| s.to_string());
    let tenant = tenant_of(&headers, &None);
    match apply_ticket_resolution(&st, &action, &id, status.as_deref(), &tenant).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id, "action": action})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// M2/T3: apply one ticket resolution (idempotent): resolve an approval hold, or advance + re-sign a GRC
/// record's status. Shared by the inbound callback and the poll loop.
async fn apply_ticket_resolution(st: &Arc<AppState>, action: &str, id: &str, status: Option<&str>, tenant: &str) -> Result<(), String> {
    match action {
        "approve" | "deny" => { resolve(st, id, action == "approve", "ticket-system"); Ok(()) }
        "grc-status" => {
            let store = st.store.as_ref().ok_or_else(|| "no --store configured".to_string())?;
            let status = status.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).ok_or_else(|| "status is required".to_string())?;
            let rec = match store.get_grc(id).await? {
                Some(r) if r.tenant == tenant => r,
                _ => return Err("no such record".to_string()),
            };
            let doc = grc_doc(&rec.id, &rec.kind, &rec.subject, &rec.title, &status, &rec.body);
            let signer = tenant_signer(&st.cp_key, tenant);
            let sig = acp_core::sign::Signer::sign(&signer, &acp_core::canonical::canonical_bytes(&doc));
            let pubkey_hex = hex::encode(acp_core::sign::Signer::public_key(&signer));
            let sig_hex = hex::encode(sig);
            store.update_grc_signed(id, &status, &rec.body, &status, &pubkey_hex, &sig_hex).await
        }
        _ => Err("unknown action (approve|deny|grc-status)".to_string()),
    }
}

/// F3: a PEP reports classifier hit-rate counts per class (counts only, never raw values).
async fn monitor_drift_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
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
async fn monitor_drift_get(State(st): State<Arc<AppState>>) -> Response {
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
async fn monitor_lineage_post(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
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
async fn monitor_lineage_get(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"edges": []})).into_response() };
    match store.list_lineage().await {
        Ok(edges) => Json(serde_json::json!({"edges": edges.iter().map(|(d,t,c)| serde_json::json!({"data_class": d, "tool": t, "count": c})).collect::<Vec<_>>()})).into_response(),
        Err(e) => Json(serde_json::json!({"edges": [], "error": e})).into_response(),
    }
}

/// B3/E1: a PEP reports a governance event (deny, step_up, fail_open, ...) for spike detection and
/// the console violation feed. The body carries the redacted decision shape; the path is the kind.
async fn record_event(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(kind): Path<String>, body: Option<Json<serde_json::Value>>) -> Response {
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

fn tally(map: &std::collections::HashMap<String, usize>) -> Vec<serde_json::Value> {
    let mut v: Vec<(String, usize)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.into_iter().map(|(k, c)| serde_json::json!({"key": k, "count": c})).collect()
}

/// GET /report/violations: an aggregated breach-and-violation report (policy denies + step-ups and
/// A6: build the framework-level report for a regulator: for each control in the framework, its
/// status derived from GRC checklists, the linked-evidence verification counts, the breach summary,
/// and a coverage figure. Returns structured JSON.
async fn framework_report_value(st: &Arc<AppState>, tenant: &str, name: &str) -> serde_json::Value {
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
async fn report_framework(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    let tenant = tenant_of(&headers, &None);
    Json(framework_report_value(&st, &tenant, &name).await).into_response()
}
/// A6: the framework report as CSV (control_id, status) plus summary rows, for a same-origin download.
async fn report_framework_csv(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
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

/// T6: capture the current framework report as a signed-in-time snapshot (history). Gated on Export.
async fn report_framework_snapshot(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::Export) { return r; }
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
async fn report_framework_history(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(name): Path<String>) -> Response {
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
async fn report_violations(State(st): State<Arc<AppState>>) -> Response {
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
async fn report_violations_csv(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // A5: exporting the violation ledger requires the Export capability (Auditor).
    if let Err(r) = authorize(&st.auth, &headers, acp_auth::Capability::Export) { return r; }
    let store = match &st.store { Some(s) => s, None => return (StatusCode::OK, "no store\n").into_response() };
    let rows = match store.list_violations(10000).await { Ok(r) => r, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response() };
    let esc = |x: &str| format!("\"{}\"", x.replace('"', "\"\""));
    let mut out = String::from("ts_ms,pep,agent,tool,verdict,rule_id,impact,outcome\n");
    for r in &rows {
        out.push_str(&format!("{},{},{},{},{},{},{},{}\n", r.ts_ms, esc(&r.pep), esc(&r.agent), esc(&r.tool), esc(&r.verdict), esc(&r.rule_id), esc(&r.impact), esc(&r.outcome)));
    }
    ([(axum::http::header::CONTENT_TYPE, "text/csv"), (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"violations.csv\"")], out).into_response()
}

/// E1/E3: the most recent governance events reported by the PEPs, newest first, for the console
/// Violations feed. Read-only projection of the in-memory ring (bounded, best-effort).
async fn events_recent(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let buf = st.events.lock().unwrap();
    let out: Vec<serde_json::Value> = buf.iter().take(200).cloned().collect();
    Json(serde_json::json!({"events": out, "count": out.len()}))
}

/// E2: ingest PEP-reported decision records into the central, re-verifiable evidence store. The PEP is
/// authenticated by the shared report token; the control plane signs each record with its cp-key so
/// the central store is itself verifiable with the cp public key. Deduped by decision_id (idempotent).
async fn evidence_ingest(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
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
async fn evidence_ingested(State(st): State<Arc<AppState>>) -> Response {
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

/// B3: which event kinds are currently spiking (over threshold in the window). A fail-open surge
/// or a deny surge pages here.
async fn alerts(State(st): State<Arc<AppState>>) -> impl IntoResponse {
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
async fn liveness(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    const WINDOW_MS: u64 = 30_000;
    let gaps = st.liveness.lock().unwrap().scan(now_ms(), WINDOW_MS);
    let gaps: Vec<String> = gaps.iter().map(|g| format!("{g:?}")).collect();
    Json(serde_json::json!({"window_ms": WINDOW_MS, "gaps": gaps, "healthy": gaps.is_empty()}))
}

/// Resolve when the process is asked to stop, so the server can drain rather than drop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining in-flight requests");
}
