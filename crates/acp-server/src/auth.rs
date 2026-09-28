//! Control-plane RBAC: the Auth holder, capability and report-token checks, JWKS loading, the
//! dev-token endpoint, and construction of the auth layer from configuration. RBAC is opt-in;
//! with no auth configured every request is allowed (the local demo path).
use crate::common::now_ms;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::collections::HashMap as StdHashMap;
use std::sync::Arc;

/// Optional control-plane RBAC. When present, mutating endpoints require a verified bearer token
/// with the right capability. `dev` is an in-memory mock issuer for local use (issues test tokens);
/// production sets jwks+cfg from the org IdP and leaves dev None.
pub(crate) struct Auth {
    pub(crate) jwks: std::sync::Arc<std::sync::RwLock<acp_core::auth::Jwks>>,
    pub(crate) cfg: acp_core::auth::EntraConfig,
    pub(crate) dev: Option<acp_core::auth::MockEntra>,
}

/// Load a JWKS from a URL (fetched) or a file path (read). Used for real Entra keys.
pub(crate) async fn load_jwks(source: &str) -> Result<acp_core::auth::Jwks, String> {
    let body = if source.starts_with("http") {
        reqwest::get(source).await.map_err(|e| e.to_string())?
            .text().await.map_err(|e| e.to_string())?
    } else {
        std::fs::read_to_string(source).map_err(|e| e.to_string())?
    };
    acp_core::auth::Jwks::from_jwks_json(&body).map_err(|e| format!("{e:?}"))
}

/// Authorise a request for a capability. RBAC disabled (auth None) allows everything (local demo).
pub(crate) fn authorize(auth: &Option<Auth>, headers: &HeaderMap, cap: acp_core::auth::Capability) -> Result<Option<acp_core::auth::Principal>, Response> {
    let a = match auth { Some(a) => a, None => return Ok(None) };
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":"missing bearer token"}))).into_response())?;
    let jwks = a.jwks.read().unwrap();
    let p = acp_core::auth::verify(token, &jwks, &a.cfg, now_ms())
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false,"error":format!("invalid token: {e:?}")}))).into_response())?;
    if !p.can(cap) {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"ok":false,"error":format!("principal lacks {cap:?}")}))).into_response());
    }
    Ok(Some(p))
}

/// E1: PEP reporting routes present a shared bearer token when the server is configured with one.
/// Fail-closed when a token is set; open (dev) when it is not, with the check a no-op.
pub(crate) fn authorize_report(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
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

/// Build the control-plane RBAC layer from configuration. `--dev-auth` uses an in-memory mock
/// issuer; --entra-* or --oidc-* configure a real issuer (JWKS refreshed hourly from a URL).
/// Returns None when no auth is configured (RBAC off). Fails closed (exits) on a bad setup.
pub(crate) async fn build(
    dev_auth: bool,
    entra_tenant: &Option<String>,
    entra_audience: &Option<String>,
    oidc_jwks: &Option<String>,
    oidc_issuer: &Option<String>,
    oidc_audience: &Option<String>,
) -> Option<Auth> {
    if dev_auth && std::env::var("ACP_ALLOW_DEV_AUTH").ok().as_deref() != Some("1") {
        tracing::info!("--dev-auth requires ACP_ALLOW_DEV_AUTH=1 (never enable in production)");
        std::process::exit(2);
    }
    // Control-plane RBAC (opt-in). Three ways to enable, in priority order:
    //   --dev-auth                         : in-memory mock issuer (local use)
    //   --entra-tenant + --entra-audience  : real Entra; issuer + JWKS URL derived from the tenant
    //   --oidc-jwks(url|file) + --oidc-issuer + --oidc-audience : explicit
    // With none, RBAC is off and the local demo is unaffected.
     if dev_auth {
        let mock = acp_core::auth::MockEntra::new("common", "acp-app");
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
                        cfg: acp_core::auth::EntraConfig { issuer, audience },
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
    }
}

pub(crate) async fn dev_token(State(st): State<Arc<AppState>>, Query(q): Query<StdHashMap<String, String>>) -> impl IntoResponse {
    match st.auth.as_ref().and_then(|a| a.dev.as_ref()) {
        Some(mock) => {
            let role = q.get("role").map(String::as_str).unwrap_or("PolicyAdmin");
            let tok = mock.issue("dev-oid", "dev@local", "common", &[role], now_ms(), 3600);
            Json(serde_json::json!({"token": tok, "role": role}))
        }
        None => Json(serde_json::json!({"error": "dev auth not enabled"})),
    }
}
