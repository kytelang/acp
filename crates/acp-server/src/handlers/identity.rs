//! Control-plane HTTP handlers: identity.
use crate::state::AppState;
use crate::common::*;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;

pub(crate) async fn vendor_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterApp) { return r; }
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
pub(crate) async fn vendor_review(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterApp) { return r; }
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

pub(crate) async fn vendors_list(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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
pub(crate) async fn tenants_list(State(st): State<Arc<AppState>>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"tenants": ["default"]})).into_response() };
    match store.list_tenants().await {
        Ok(mut ts) => { if ts.is_empty() { ts.push("default".to_string()); } Json(serde_json::json!({"tenants": ts})).into_response() }
        Err(e) => Json(serde_json::json!({"tenants": ["default"], "error": e})).into_response(),
    }
}

/// Registered apps (read-only view for the console).
pub(crate) async fn apps(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let tenant = tenant_of(&headers, &None);
    if let Some(store) = &st.store {
        match store.list_apps(&tenant).await {
            Ok(apps) => return Json(serde_json::json!({"apps": apps})).into_response(),
            Err(e) => return Json(serde_json::json!({"apps": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_core::registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.apps().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"owner":a.owner})).collect();
            Json(serde_json::json!({"apps": list})).into_response()
        }
        _ => Json(serde_json::json!({"apps": []})).into_response(),
    }
}

/// Registered agents (read-only).
pub(crate) async fn agents(State(st): State<Arc<AppState>>, headers: HeaderMap) -> impl IntoResponse {
    let tenant = tenant_of(&headers, &None);
    if let Some(store) = &st.store {
        match store.list_agents(&tenant).await {
            Ok(agents) => return Json(serde_json::json!({"agents": agents})).into_response(),
            Err(e) => return Json(serde_json::json!({"agents": [], "error": e})).into_response(),
        }
    }
    match st.registry.as_ref().map(|p| acp_core::registry::Registry::load(p)) {
        Some(Ok(reg)) => {
            let list: Vec<_> = reg.agents().into_iter().map(|a| serde_json::json!({"id":a.id,"name":a.name,"app_id":a.app_id,"active":a.active})).collect();
            Json(serde_json::json!({"agents": list})).into_response()
        }
        _ => Json(serde_json::json!({"agents": []})).into_response(),
    }
}

/// POST /agents/resolve-key: resolve an agent's authenticated identity from its per-agent virtual key
/// alone (audit P0 F1). Unauthenticated because the key IS the credential; a wrong key returns
/// verified:false. Used by the LLM gateway to bind a call to a verified agent+app instead of a
/// spoofable header.
pub(crate) async fn agent_resolve_key(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let key = body.get("key").and_then(|v| v.as_str()).unwrap_or("");
    if key.is_empty() { return Json(serde_json::json!({"ok": false, "error": "key is required"})).into_response(); }
    let token_sha = acp_core::canonical::sha256_hex_bytes(key.as_bytes());
    match store.resolve_agent_by_token_sha(&token_sha).await {
        Ok(Some((agent_id, name, app_id, tenant))) => Json(serde_json::json!({"ok": true, "verified": true, "agent_id": agent_id, "name": name, "app_id": app_id, "tenant": tenant})).into_response(),
        Ok(None) => Json(serde_json::json!({"ok": true, "verified": false})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// POST /agents/verify: the enforcement path verifies an agent by id + token against the store, so a
/// DB-registered agent is honoured without a registry file. Returns the display identity when valid.
/// Ungated: it only confirms a token the caller already holds.
pub(crate) async fn agent_verify(State(st): State<Arc<AppState>>, Json(body): Json<serde_json::Value>) -> Response {
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
pub(crate) async fn app_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterApp) { return r; }
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
pub(crate) async fn agent_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let app_id = body.get("app_id").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if app_id.is_empty() || name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "app_id and name are required"})).into_response(); }
    // Referential integrity (audit P1 E2): reject an agent whose parent app does not exist.
    let tenant0 = tenant_of(&headers, &None);
    if !store.app_exists(&app_id, &tenant0).await { return Json(serde_json::json!({"ok": false, "error": format!("unknown app_id '{app_id}'")})).into_response(); }
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
pub(crate) async fn agent_deactivate(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    match store.deactivate_agent(&id).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}

/// DEV ONLY: issue a mock bearer token for a role, so the console can authenticate without real
/// Entra during local use. Present only when --dev-auth is set.
/// A5 (SCIM 2.0): the role groups ACP recognises, in SCIM ListResponse shape, so an IdP or an
/// operator can see the provisionable groups and the capabilities each grants. Gated on Export
/// (read-only administrative view). Groups are the ACP role catalogue (single source of truth).
pub(crate) async fn scim_groups(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
    let resources: Vec<serde_json::Value> = acp_core::auth::role_catalogue().into_iter().map(|(name, caps)| {
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
pub(crate) async fn scim_users(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::Export) { return r; }
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

/// Resolve a human principal's directory groups from the IdP-provisioned SCIM directory, so a
/// workstation proxy can populate `principal_scopes` for group-based policy automatically, without a
/// local flag. Looks the principal up by id or email (case-insensitive). Returns group names only.
pub(crate) async fn principal_groups(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> Response {
    if let Err(r) = authorize_report(&st, &axum::http::HeaderMap::new()) { return r; }
    let who = q.get("id").map(|s| s.trim().to_lowercase()).unwrap_or_default();
    let groups = if who.is_empty() {
        Vec::new()
    } else {
        st.scim_users
            .iter()
            .find(|(id, email, _)| id.to_lowercase() == who || email.to_lowercase() == who)
            .map(|(_, _, g)| g.clone())
            .unwrap_or_default()
    };
    Json(serde_json::json!({"principal": who, "groups": groups})).into_response()
}


/// Default per-agent capability config: the forward-proxy firewall on, mcp/guard off. Editable from
/// the console Agent config page and fetched by `acp-agent run --agent-id ... --control-plane ...`.
fn default_agent_config() -> serde_json::Value {
    serde_json::json!({
        "firewall": {"enabled": true,  "listen": "127.0.0.1:8080"},
        "mcp":      {"enabled": false, "listen": "127.0.0.1:8090", "upstream": ""},
        "guard":    {"enabled": false, "listen": "127.0.0.1:8091", "upstream": "", "pubkey": ""}
    })
}

/// GET /agent-config/:group: the stored capability config for a directory group (defaults if none
/// saved yet). Config is keyed by group so it scales across a large fleet: a workstation resolves its
/// user's group and fetches that group's config, rather than a config per machine.
pub(crate) async fn agent_config_get(State(st): State<Arc<AppState>>, Path(group): Path<String>) -> Response {
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"group": group, "config": default_agent_config()})).into_response() };
    let cfg = store
        .get_state(&format!("agentcfg:group:{group}"))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .unwrap_or_else(default_agent_config);
    Json(serde_json::json!({"group": group, "config": cfg})).into_response()
}

/// POST /agent-config/:group: store the capability config for a directory group (RegisterAgent scope).
/// Body is the config object, or {config: {...}}.
pub(crate) async fn agent_config_set(State(st): State<Arc<AppState>>, headers: HeaderMap, Path(group): Path<String>, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    if group.trim().is_empty() { return Json(serde_json::json!({"ok": false, "error": "group is required"})).into_response(); }
    let cfg = body.get("config").cloned().unwrap_or(body);
    match store.put_state(&format!("agentcfg:group:{group}"), &cfg.to_string(), now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "group": group})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}


/// GET /groups: the registered directory groups (created from the console), for the Agent config
/// dropdown. Union with any groups already seen in the SCIM directory so real IdP groups are offered.
pub(crate) async fn groups_list(State(st): State<Arc<AppState>>) -> Response {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (_, email_or_id, groups) in &st.scim_users {
        let _ = email_or_id;
        for g in groups { names.insert(g.clone()); }
    }
    if let Some(store) = &st.store {
        if let Ok(rows) = store.list_state_prefix("groupreg:").await {
            for (_, v) in rows { if !v.trim().is_empty() { names.insert(v); } }
        }
    }
    Json(serde_json::json!({"groups": names.into_iter().collect::<Vec<_>>()})).into_response()
}

/// POST /groups {name}: register a directory group name (RegisterAgent scope).
pub(crate) async fn group_register(State(st): State<Arc<AppState>>, headers: HeaderMap, Json(body): Json<serde_json::Value>) -> Response {
    if let Err(r) = authorize(&st.auth, &headers, acp_core::auth::Capability::RegisterAgent) { return r; }
    let store = match &st.store { Some(s) => s, None => return Json(serde_json::json!({"ok": false, "error": "no --store configured"})).into_response() };
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if name.is_empty() { return Json(serde_json::json!({"ok": false, "error": "group name is required"})).into_response(); }
    match store.put_state(&format!("groupreg:{name}"), &name, now_ms() as i64).await {
        Ok(()) => Json(serde_json::json!({"ok": true, "name": name})).into_response(),
        Err(e) => Json(serde_json::json!({"ok": false, "error": e})).into_response(),
    }
}
