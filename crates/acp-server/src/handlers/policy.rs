//! Control-plane HTTP handlers: policy.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

pub(crate) async fn policy_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match &st.policy {
        Some((hash, body)) => {
            Json(serde_json::json!({"hash": hash, "body": body, "max_staleness_s": 30}))
                .into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "no policy configured").into_response(),
    }
}

/// Current deployed signed policy (version/hash/author) from the policy store.
pub(crate) async fn policy_store_current(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    match st.policy_store.as_ref().map(|p| acp_core::policy::store::current_info(p)) {
        Some(Ok(v)) => Json(v),
        _ => Json(serde_json::json!({"version": 0})),
    }
}

/// G2: GET /policy/suggest - propose the least-privilege policy synthesised from the fleet-evidence
/// the control plane has ingested, with a diff against the live policy and a would-block check. It
/// deploys nothing: the console shows the diff and the operator posts the proposal to
/// /policy-store/deploy (which signs and versions it) to accept.
pub(crate) async fn policy_suggest(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    // Distil observed actions from the ingested decision records.
    let recs = store.list_ingested(5000).await.unwrap_or_default();
    let mut observed: Vec<acp_core::policy::synth::ObservedAction> = Vec::new();
    for r in &recs {
        if r.kind != "decision" { continue; }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.record) {
            let tool = v["action"]["tool"].as_str().unwrap_or("").to_string();
            if tool.is_empty() { continue; }
            observed.push(acp_core::policy::synth::ObservedAction {
                tool,
                resource: v["action"]["resource"].as_str().unwrap_or("").to_string(),
                operation: v["action"]["operation"].as_str().unwrap_or("").to_string(),
                verdict: v["decision"]["verdict"].as_str().unwrap_or(&r.verdict).to_string(),
            });
        }
    }
    let proposed = acp_core::policy::synth::synthesize_least_privilege(&observed);
    let current = st.policy.as_ref().map(|(_, body)| body.clone()).unwrap_or_default();
    // Would-block: under the proposed policy, does any action that was observed-allowed get denied?
    let mut would_block: Vec<String> = Vec::new();
    if let Ok(engine) = acp_core::policy::PolicyEngine::from_yaml(&proposed) {
        let tax = acp_core::impact::ImpactTaxonomy::default();
        let rtax = acp_core::resource::ResourceTaxonomy::default();
        let mut seen = std::collections::BTreeSet::new();
        for a in observed.iter().filter(|a| a.verdict == "allow") {
            if !seen.insert(a.tool.clone()) { continue; }
            let ctx = acp_core::policy::context::build_context_identified_full(&a.tool, &serde_json::json!({}), "prod", "agent", "", "principal", &tax, &rtax);
            if engine.evaluate(ctx).verdict == acp_core::types::Verdict::Deny {
                would_block.push(a.tool.clone());
            }
        }
    }
    let proposed_rules = proposed.matches("\n  - id:").count();
    Json(serde_json::json!({
        "ok": true,
        "proposed": proposed,
        "current": current,
        "observed_decisions": recs.iter().filter(|r| r.kind == "decision").count(),
        "distinct_tools": observed.iter().map(|a| a.tool.clone()).collect::<std::collections::BTreeSet<_>>().len(),
        "proposed_rules": proposed_rules,
        "would_block": would_block,
    })).into_response()
}

/// G3: draft the model-v2 DSL from an English description via a configured OpenAI-compatible LLM. Returns
/// None if no LLM is configured or the call/parse fails (the caller then uses the deterministic drafter).
pub(crate) async fn author_llm_draft(st: &Arc<AppState>, text: &str) -> Option<String> {
    let url = st.author_llm_url.as_ref()?;
    let model = st.author_llm_model.clone().unwrap_or_else(|| "gpt-4o-mini".to_string());
    let sys = "You are a policy compiler for the Varman (ACP) model-v2 YAML DSL. Output ONLY a YAML policy document, no prose, no markdown fences. Shape: `version: 1`, `default: allow` (or deny), and `rules:` where each rule has `id`, a `when:` map keyed by any of tool/resource/operation/principal/agent/app (resource is one of database/filesystem/secrets/network/payments/model; operation is read/write/delete), and `verdict:` one of allow/deny/step_up. Translate the user's rule faithfully and minimally.";
    let mut req = reqwest::Client::new().post(url).json(&serde_json::json!({
        "model": model,
        "messages": [{"role": "system", "content": sys}, {"role": "user", "content": text}],
        "temperature": 0
    }));
    if let Some(k) = &st.author_llm_key { req = req.header("authorization", format!("Bearer {k}")); }
    let v: serde_json::Value = req.send().await.ok()?.json().await.ok()?;
    let content = v.get("choices")?.get(0)?.get("message")?.get("content")?.as_str()?.to_string();
    // Strip any accidental markdown fences.
    let cleaned = content.lines().filter(|l| !l.trim_start().starts_with("```")).collect::<Vec<_>>().join("\n");
    // Only accept it if it compiles.
    if acp_core::policy::PolicyEngine::from_yaml(&cleaned).is_ok() { Some(cleaned) } else { None }
}

/// G3: POST /policy/author {text, tests?[{tool,principal}]} -> best-effort DSL draft + the verification
/// matrix (allow/deny per test request through the real engine). Deploy remains a separate, signed step.
pub(crate) async fn policy_author(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) { return r; }
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    // Prefer a real LLM drafter when configured (OpenAI-compatible chat/completions); the deterministic
    // pattern drafter is the offline fallback. Either way the draft is VERIFIED below before it can ship.
    let draft = match author_llm_draft(&st, text).await {
        Some(d) => d,
        None => match acp_core::policy::author::draft_from_text(text) {
            Some(d) => d,
            None => return Json(serde_json::json!({"ok": false, "error": "could not draft from that description; rephrase or use the editor", "draft": ""})).into_response(),
        },
    };
    let reqs: Vec<acp_core::policy::author::TestRequest> = body.get("tests").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|t| {
        Some(acp_core::policy::author::TestRequest { tool: t.get("tool")?.as_str()?.to_string(), principal: t.get("principal").and_then(|p| p.as_str()).unwrap_or("").to_string() })
    }).collect()).unwrap_or_default();
    match acp_core::policy::author::verify_matrix(&draft, &reqs) {
        Ok(matrix) => Json(serde_json::json!({"ok": true, "draft": draft, "matrix": matrix})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e, "draft": draft})).into_response(),
    }
}

pub(crate) fn deploy_signer(store_dir: &str) -> acp_core::sign::Ed25519Signer {
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
pub(crate) async fn policy_store_rules(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    let src = match st.policy_store.as_ref().map(|p| acp_core::policy::store::current_source(p)) {
        Some(Ok(s)) => s,
        _ => return Json(serde_json::json!({"rules": [], "count": 0})),
    };
    let pol = match acp_core::policy::dsl::parse_str(&src) {
        Ok(p) => p,
        Err(e) => return Json(serde_json::json!({"rules": [], "count": 0, "error": e.to_string()})),
    };
    let reg = st.registry.as_ref().and_then(|p| acp_core::registry::Registry::load(p).ok());
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
    use acp_core::policy::dsl::ObligationKind;
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
                    ObligationKind::Disclose => "disclose".to_string(),
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
pub(crate) async fn policy_store_deploy(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::EditPolicy) {
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
    match acp_core::policy::store::deploy(src, &store, &signer, author) {
        Ok(d) => Json(serde_json::json!({"ok": true, "version": d.version, "hash": d.hash})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
