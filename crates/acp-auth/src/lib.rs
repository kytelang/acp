//! Console / API authentication modelled on Azure Entra ID (decision H0.8), with RBAC.
//!
//! ACP verifies a bearer JWT the way a relying party verifies an Entra ID token: resolve the
//! signing key from a JWKS by the header `kid`, check the algorithm, verify the signature, then
//! validate `iss` (the Entra tenant issuer), `aud` (our app's client id), and the `nbf`/`exp`
//! window. The authenticated principal carries the Entra `oid`, `tid` (tenant), and app `roles`,
//! which map to ACP capabilities (edit-policy, approve, export, see-args).
//!
//! Production points the JWKS fetch at Entra's real keys (RS256). This build ships a `MockEntra`
//! IdP that issues EdDSA-signed tokens against an in-memory JWKS, so the whole verify-and-authorise
//! path is exercised deterministically offline. EdDSA is a real JOSE algorithm; an RS256 key is
//! simply another JWKS entry once an RSA verifier is linked. Nothing above the JWKS seam changes.

use acp_core::sign::{verify_ed25519, Ed25519Signer, Signer};
use base64::Engine;
use std::collections::{BTreeSet, HashMap};

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn unb64url(s: &str) -> Result<Vec<u8>, AuthError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AuthError::Malformed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Malformed,
    UnknownKey,
    AlgMismatch,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    Expired,
    NotYetValid,
}

/// One signing key in the JWKS: its algorithm and public key bytes.
#[derive(Debug, Clone)]
pub struct JwkKey {
    pub alg: String,
    pub public_key: Vec<u8>,
}

/// The key set used to verify tokens, keyed by `kid`.
#[derive(Debug, Default, Clone)]
pub struct Jwks {
    keys: HashMap<String, JwkKey>,
}

impl Jwks {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, kid: &str, alg: &str, public_key: Vec<u8>) {
        self.keys.insert(
            kid.to_string(),
            JwkKey {
                alg: alg.to_string(),
                public_key,
            },
        );
    }
    fn get(&self, kid: &str) -> Option<&JwkKey> {
        self.keys.get(kid)
    }
}

/// What the relying party requires of a token.
#[derive(Debug, Clone)]
pub struct EntraConfig {
    /// e.g. https://login.microsoftonline.com/{tenant}/v2.0
    pub issuer: String,
    /// Our app (client) id; the token `aud` must equal this.
    pub audience: String,
}

/// The authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Entra object id (stable per user).
    pub oid: String,
    pub username: String,
    /// Entra tenant id (`tid`).
    pub tenant: String,
    pub roles: Vec<String>,
}

/// Capabilities ACP gates on. Roles map to these; the enforcement path checks a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    EditPolicy,
    Approve,
    Export,
    SeeArgs,
}

impl Principal {
    /// Map Entra app roles to ACP capabilities. Unknown roles grant nothing (fail-closed).
    pub fn capabilities(&self) -> BTreeSet<Capability> {
        let mut caps = BTreeSet::new();
        for r in &self.roles {
            match r.as_str() {
                "PolicyAdmin" => {
                    caps.insert(Capability::EditPolicy);
                }
                "Approver" => {
                    caps.insert(Capability::Approve);
                }
                "Auditor" => {
                    caps.insert(Capability::Export);
                }
                "SecurityOfficer" => {
                    caps.insert(Capability::SeeArgs);
                }
                _ => {}
            }
        }
        caps
    }
    pub fn can(&self, cap: Capability) -> bool {
        self.capabilities().contains(&cap)
    }
}

/// Verify a bearer JWT and return the authenticated principal, or a specific failure. `now_ms` is
/// injected so tests are deterministic and so clock handling is explicit.
pub fn verify(
    token: &str,
    jwks: &Jwks,
    cfg: &EntraConfig,
    now_ms: u64,
) -> Result<Principal, AuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::Malformed);
    }
    let header: serde_json::Value =
        serde_json::from_slice(&unb64url(parts[0])?).map_err(|_| AuthError::Malformed)?;
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::Malformed)?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or(AuthError::Malformed)?;

    let key = jwks.get(kid).ok_or(AuthError::UnknownKey)?;
    if key.alg != alg {
        return Err(AuthError::AlgMismatch);
    }

    // Verify the signature over "header.payload" before trusting any claim.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = unb64url(parts[2])?;
    let ok = match alg {
        "EdDSA" => verify_ed25519(&key.public_key, signing_input.as_bytes(), &sig),
        // RS256 etc. would verify here once an RSA backend is linked; until then, reject.
        _ => false,
    };
    if !ok {
        return Err(AuthError::BadSignature);
    }

    let claims: serde_json::Value =
        serde_json::from_slice(&unb64url(parts[1])?).map_err(|_| AuthError::Malformed)?;

    if claims.get("iss").and_then(|v| v.as_str()) != Some(cfg.issuer.as_str()) {
        return Err(AuthError::WrongIssuer);
    }
    // aud may be a string or an array; require our audience to be present.
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == &cfg.audience,
        Some(serde_json::Value::Array(a)) => {
            a.iter().any(|v| v.as_str() == Some(cfg.audience.as_str()))
        }
        _ => false,
    };
    if !aud_ok {
        return Err(AuthError::WrongAudience);
    }

    let now_s = now_ms / 1000;
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
        if now_s >= exp {
            return Err(AuthError::Expired);
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_u64()) {
        if now_s < nbf {
            return Err(AuthError::NotYetValid);
        }
    }

    let roles = claims
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|r| r.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(Principal {
        oid: claims
            .get("oid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        username: claims
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        tenant: claims
            .get("tid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        roles,
    })
}

/// A mock Entra ID issuer for tests and offline dev. Issues EdDSA-signed tokens and exposes a JWKS.
pub struct MockEntra {
    signer: Ed25519Signer,
    kid: String,
    issuer: String,
    audience: String,
}

impl MockEntra {
    pub fn new(tenant: &str, audience: &str) -> Self {
        MockEntra {
            signer: Ed25519Signer::generate(),
            kid: "mock-kid-1".to_string(),
            issuer: format!("https://login.microsoftonline.com/{tenant}/v2.0"),
            audience: audience.to_string(),
        }
    }

    pub fn config(&self) -> EntraConfig {
        EntraConfig {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
        }
    }

    pub fn jwks(&self) -> Jwks {
        let mut j = Jwks::new();
        j.add(&self.kid, "EdDSA", self.signer.public_key());
        j
    }

    /// Issue a token for a user with roles, valid for `ttl_s` seconds from `now_ms`.
    pub fn issue(
        &self,
        oid: &str,
        username: &str,
        tenant: &str,
        roles: &[&str],
        now_ms: u64,
        ttl_s: u64,
    ) -> String {
        let now_s = now_ms / 1000;
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": self.kid});
        let claims = serde_json::json!({
            "iss": self.issuer,
            "aud": self.audience,
            "oid": oid,
            "preferred_username": username,
            "tid": tenant,
            "roles": roles,
            "iat": now_s,
            "nbf": now_s,
            "exp": now_s + ttl_s,
        });
        let h = b64url(serde_json::to_string(&header).unwrap().as_bytes());
        let c = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        let signing_input = format!("{h}.{c}");
        let sig = b64url(&self.signer.sign(signing_input.as_bytes()));
        format!("{signing_input}.{sig}")
    }
}
