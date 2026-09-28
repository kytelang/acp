//! Cross-cutting helpers shared by the control-plane handlers: authorization, tenancy, signing,
//! webhooks and small utilities.
use crate::state::AppState;
use axum::http::HeaderMap;
use std::sync::Arc;

// Auth checks live in crate::auth; re-export so handlers keep using them via the common prelude.
pub(crate) use crate::auth::{authorize, authorize_report};

pub(crate) fn fire_webhook(st: &Arc<AppState>, event_type: &str, fields: serde_json::Value) {
    let now = now_ms();
    // Generic HMAC-signed webhook sink.
    if let Some(url) = st.webhook_url.clone() {
        let secret = st.webhook_secret.clone().unwrap_or_default();
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
    // Named Slack adapter: post the same event as an injection-safe Block Kit message.
    if let Some(url) = st.slack_webhook_url.clone() {
        let msg = acp_core::notify::render_slack_event(event_type, &fields);
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let _ = client.post(&url)
                .header("content-type", "application/json")
                .body(msg.to_string())
                .send().await;
        });
    }
}

/// A5: load the SCIM user directory (id, email, role groups) from a JSON file, or return a demo
/// mapping so the SCIM endpoints are exercisable under the mocked IdP. The file is a JSON array of
/// {id, email, groups:[role,...]}.
pub(crate) fn load_scim_users(path: Option<&str>) -> Vec<(String, String, Vec<String>)> {
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



/// The actor string to attribute a change to: the verified principal's username (or oid), else
/// "console" when RBAC is off (local/dev). Threaded into evidence and control-plane records so a
/// change is attributable to the authenticated admin, not a hardcoded literal (gap A9).
/// T1: resolve the tenant for a request: the `x-acp-tenant` header if present, else the authenticated
/// principal's Entra tenant (when it is a real tenant, not the dev "common"), else "default".
pub(crate) fn tenant_of(headers: &HeaderMap, principal: &Option<acp_core::auth::Principal>) -> String {
    if let Some(h) = headers.get("x-acp-tenant").and_then(|v| v.to_str().ok()) {
        let t = h.trim();
        if !t.is_empty() { return t.to_string(); }
    }
    if let Some(p) = principal {
        if !p.tenant.is_empty() && p.tenant != "common" { return p.tenant.clone(); }
    }
    "default".to_string()
}

pub(crate) fn actor_of(p: &Option<acp_core::auth::Principal>) -> String {
    match p {
        Some(pr) if !pr.username.is_empty() => pr.username.clone(),
        Some(pr) => pr.oid.clone(),
        None => "console".to_string(),
    }
}

/// Load-or-create the Ed25519 signer used to sign console-initiated deployments. Persisted next to
/// the store so the signed manifest stays verifiable across restarts. The proxy trusts the pubkey
/// embedded in current.json (tamper-evidence of the file against the signed hash).
/// Sign endpoint dispositions with a key kept next to the enrollment log (created 0600 if absent).
/// M1: derive a deterministic per-tenant Ed25519 signer from the control-plane key seed + tenant id,
/// so each tenant's records are signed with a distinct key (still verifiable via the embedded pubkey).
pub(crate) fn tenant_signer(path: &str, tenant: &str) -> acp_core::sign::Ed25519Signer {
    if tenant == "default" { return enroll_signer(path); }
    let base = enroll_signer(path).seed();
    let mut seed = [0u8; 32];
    let derived = acp_core::canonical::sha256_hex_bytes(&[&base[..], b":", tenant.as_bytes()].concat());
    let bytes = hex::decode(&derived).unwrap_or_default();
    seed.copy_from_slice(&bytes[..32]);
    acp_core::sign::Ed25519Signer::from_seed(&seed)
}

pub(crate) fn enroll_signer(path: &str) -> acp_core::sign::Ed25519Signer {
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

pub(crate) fn load_enrollment(path: &str) -> acp_core::enrollment::EnrollmentLog {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Random hex, for generated ids and one-time agent tokens.
pub(crate) fn rand_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    let _ = getrandom::getrandom(&mut b);
    hex::encode(b)
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}


pub(crate) fn grc_doc(id: &str, kind: &str, subject: &str, title: &str, status: &str, body: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "kind": kind, "subject": subject, "title": title, "status": status, "body": body})
}
