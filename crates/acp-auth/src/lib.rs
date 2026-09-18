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
    /// For EdDSA: the raw public key. For RS256: the RSA modulus (n), big-endian.
    pub public_key: Vec<u8>,
    /// For RS256: the RSA public exponent (e), big-endian. Empty for EdDSA.
    pub rsa_e: Vec<u8>,
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
            JwkKey { alg: alg.to_string(), public_key, rsa_e: Vec::new() },
        );
    }
    /// Add an RSA (RS256) key by its modulus (n) and exponent (e), both big-endian. This is how a
    /// real Entra JWKS key is represented.
    pub fn add_rsa(&mut self, kid: &str, n: Vec<u8>, e: Vec<u8>) {
        self.keys.insert(
            kid.to_string(),
            JwkKey { alg: "RS256".to_string(), public_key: n, rsa_e: e },
        );
    }

    /// Parse a JWKS document (Entra format: {"keys":[{kid,kty,alg,n,e}...]}) into a key set. RSA
    /// keys have base64url n/e; EdDSA (OKP) keys have base64url x. Unknown key types are skipped.
    pub fn from_jwks_json(src: &str) -> Result<Jwks, AuthError> {
        let doc: serde_json::Value = serde_json::from_str(src).map_err(|_| AuthError::Malformed)?;
        let keys = doc.get("keys").and_then(|v| v.as_array()).ok_or(AuthError::Malformed)?;
        let mut jwks = Jwks::new();
        for k in keys {
            let kid = match k.get("kid").and_then(|v| v.as_str()) { Some(s) => s, None => continue };
            match k.get("kty").and_then(|v| v.as_str()) {
                Some("RSA") => {
                    let n = k.get("n").and_then(|v| v.as_str()).and_then(|s| unb64url(s).ok());
                    let e = k.get("e").and_then(|v| v.as_str()).and_then(|s| unb64url(s).ok());
                    if let (Some(n), Some(e)) = (n, e) { jwks.add_rsa(kid, n, e); }
                }
                Some("OKP") => {
                    if let Some(x) = k.get("x").and_then(|v| v.as_str()).and_then(|s| unb64url(s).ok()) {
                        jwks.add(kid, "EdDSA", x);
                    }
                }
                _ => {}
            }
        }
        Ok(jwks)
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
    /// Engage or clear the emergency kill-switch (break-glass).
    BreakGlass,
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
                "BreakGlassOperator" => {
                    caps.insert(Capability::BreakGlass);
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
        "RS256" => {
            // Real Entra tokens are RSASSA-PKCS1-v1_5 over SHA-256. Verify against the RSA (n, e).
            let pk = ring::signature::RsaPublicKeyComponents { n: &key.public_key, e: &key.rsa_e };
            pk.verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &sig,
            )
            .is_ok()
        }
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

#[cfg(test)]
mod rs256_tests {
    use super::*;

    const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vY29tbW9uL3YyLjAiLCJhdWQiOiJhY3AtYXBwIiwiZXhwIjo5OTk5OTk5OTk5LCJuYmYiOjAsIm9pZCI6Im9pZC1hbGljZS0xIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2VAY29ycCIsInRpZCI6InRlbmFudC0xIiwicm9sZXMiOlsiUG9saWN5QWRtaW4iXX0.FK201WoJgW5c-suBNGiEgPgjgobVypw40Ul6QF_cf-CT51mQSWqNQVcxF5XTh1N8XD8rby3bkjWjz74oL0ZwkR-ewxUCxV24Z_i1TlBNcK5i1AcPDBRA0cYT4f7QWjwl_ayN_bKy59aqU-oKZK03SsoLoLBkKXAsC65xzvIWLdwOFOH7aHJgewJxYleMk33GNldQSdheWxIIC5TXquO6QWk9r1zkWRPv9EibO_gFlNA9WDM7jNfUk--ogqtZukkrYv73cpsrNLpWc8CGxszcOvZzIfLmhh65cJu6-J7MdxBujYa2pTdf4KSyr-XJkZcw350gfRChkY_Jl5aG8TmBTg";
    const N_HEX: &str = "c2245469e34e351993e99fbce14d22e9fc526598298259925cb4aad0778e5a8efb964d7e7e7ff11de4cdba1c2e60ac3f7eebcf7085c71d5d9d492d64c13e020215bcab5d113383156c482dd46f4c5648267ed667ee3a68ebbda8c851b30d185f68c6c3fd17cfc3ecfc3097d4194ce242c4d4234bc510b9872921a90778e1c9587bce4388450fc0247be3c8f2f001b1bb45a1115163b870e07e87c147ea08a599a77ae7cc8df145d82f9c78b223c93cfc9e37b0f43359d8fc0690dbc5bd15961b790804a2a1694d0c1d9cfbe84105519f81eb79569c97e86cfe25e6e78abd6c0f2764d31d2b44b617b790e026b78c908e53b9627f5481e25d754fab1c9ce17d67";
    const E_HEX: &str = "010001";

    fn cfg() -> EntraConfig {
        EntraConfig {
            issuer: "https://login.microsoftonline.com/common/v2.0".into(),
            audience: "acp-app".into(),
        }
    }

    #[test]
    fn verifies_a_real_rs256_token() {
        // A genuine RS256 JWT signed by a 2048-bit RSA key (openssl), keyed by its modulus/exponent.
        // Proves the real Entra signature path, not the EdDSA mock.
        let mut jwks = Jwks::new();
        jwks.add_rsa("test-rsa-1", hex::decode(N_HEX).unwrap(), hex::decode(E_HEX).unwrap());
        let p = verify(TOKEN, &jwks, &cfg(), 1_000_000).expect("real RS256 token verifies");
        assert_eq!(p.oid, "oid-alice-1");
        assert_eq!(p.tenant, "tenant-1");
        assert!(p.can(Capability::EditPolicy), "PolicyAdmin -> EditPolicy");
    }

    #[test]
    fn a_tampered_rs256_token_is_rejected() {
        let mut jwks = Jwks::new();
        jwks.add_rsa("test-rsa-1", hex::decode(N_HEX).unwrap(), hex::decode(E_HEX).unwrap());
        // Flip a character in the signature segment.
        let mut parts: Vec<&str> = TOKEN.split('.').collect();
        let mut sig = parts[2].to_string();
        sig.replace_range(0..1, if sig.starts_with('A') { "B" } else { "A" });
        let forged = format!("{}.{}.{}", parts[0], parts[1], sig);
        let _ = &mut parts;
        assert!(verify(&forged, &jwks, &cfg(), 1_000_000).is_err(), "bad signature must reject");
    }

    #[test]
    fn parses_an_entra_style_jwks_and_verifies() {
        use base64::Engine;
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hex::decode(N_HEX).unwrap());
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hex::decode(E_HEX).unwrap());
        let doc = serde_json::json!({
            "keys": [{"kty": "RSA", "kid": "test-rsa-1", "alg": "RS256", "n": n_b64, "e": e_b64}]
        }).to_string();
        let jwks = Jwks::from_jwks_json(&doc).unwrap();
        let p = verify(TOKEN, &jwks, &cfg(), 1_000_000).expect("verifies against parsed JWKS");
        assert_eq!(p.username, "alice@corp");
    }
}
