//! App + agent registration and verified identity.
//!
//! ACP governs *agents* running inside *apps*. For a policy to say "agent triage in app portal may
//! not call payments.*", those identities must be real and un-spoofable. This registry is the source
//! of truth: an app is registered, an agent is registered under it and issued a one-time token, and
//! on every tool call the proxy verifies the presented (agent id, token) against the registry and
//! stamps the VERIFIED app/agent into the trusted policy context. An agent cannot assert its own id;
//! it proves it. Local-first: the registry persists as a JSON file the proxy loads (no cloud).

use acp_core::canonical::sha256_hex_bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("os rng");
    hex::encode(b)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct App {
    pub id: String,
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Agent {
    pub id: String,
    pub app_id: String,
    pub name: String,
    /// SHA-256 of the issued bearer token. The plaintext token is shown once at registration and
    /// never stored, so a leaked registry file does not leak agent credentials.
    pub token_sha256: String,
    pub active: bool,
}

/// Where a human principal's identity was established. Determines how far it can be trusted. The
/// human principal is always proxy-injected (from the MCP OAuth token or an enrolment binding), never
/// asserted by the agent. When no verified human is available the principal is `unattributed`, so the
/// gap is visible to policy rather than silent (a rule can deny or step-up unattributed high-risk work).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSource {
    /// Verified subject claim from the org identity provider, via the MCP OAuth token (strongest).
    Oauth,
    /// The launching OS or SSO user, bound to the agent session at proxy enrolment (local agents).
    OsLogin,
    Sso,
    /// No verified human behind the call.
    Unattributed,
}

impl PrincipalSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalSource::Oauth => "oauth",
            PrincipalSource::OsLogin => "os_login",
            PrincipalSource::Sso => "sso",
            PrincipalSource::Unattributed => "unattributed",
        }
    }
    /// A principal is "verified" for policy purposes when it came from any real source.
    pub fn verified(&self) -> bool {
        !matches!(self, PrincipalSource::Unattributed)
    }
}

/// A human on whose behalf an agent acts. Durable identity; the per-session binding is a `Delegation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HumanPrincipal {
    pub id: String,
    pub display: String,
    pub source: PrincipalSource,
}

impl HumanPrincipal {
    /// The sentinel principal used when no verified human is available.
    pub fn unattributed() -> Self {
        HumanPrincipal { id: "unattributed".into(), display: "unattributed".into(), source: PrincipalSource::Unattributed }
    }
    pub fn verified(&self) -> bool {
        self.source.verified()
    }
}

/// The verified identity the proxy stamps into the policy context: the agent (always verified from
/// its token) plus the human principal it acts for (unattributed until a verified human is attached).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub agent_id: String,
    pub app_id: String,
    /// Human-friendly names, what policy authors reference (`when: { agent: "triage" }`).
    pub agent_name: String,
    pub app_name: String,
    /// The human principal (D1). Defaults to the unattributed sentinel; `with_principal` attaches a
    /// verified one once the proxy has resolved it from the OAuth token or enrolment.
    pub principal_id: String,
    pub principal_display: String,
    pub principal_source: PrincipalSource,
}

impl Identity {
    pub fn principal_verified(&self) -> bool {
        self.principal_source.verified()
    }
    /// Attach a resolved human principal to this (agent-only) identity.
    pub fn with_principal(mut self, p: &HumanPrincipal) -> Self {
        self.principal_id = p.id.clone();
        self.principal_display = p.display.clone();
        self.principal_source = p.source;
        self
    }
}

/// The per-session envelope binding an agent to the human it acts for, for a task, with an expiry.
/// Constructed by the proxy at enrolment from a verified `Identity`; stamped context is derived from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub agent_id: String,
    pub agent_name: String,
    pub principal_id: String,
    pub principal_source: PrincipalSource,
    pub task: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

impl Delegation {
    pub fn from_identity(id: &Identity, task: &str, issued_ms: u64, ttl_ms: u64) -> Self {
        Delegation {
            agent_id: id.agent_id.clone(),
            agent_name: id.agent_name.clone(),
            principal_id: id.principal_id.clone(),
            principal_source: id.principal_source,
            task: task.to_string(),
            issued_ms,
            expires_ms: issued_ms.saturating_add(ttl_ms),
        }
    }
    pub fn active(&self, now_ms: u64) -> bool {
        now_ms < self.expires_ms
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Registry {
    apps: BTreeMap<String, App>,
    agents: BTreeMap<String, Agent>,
    #[serde(default)]
    principals: BTreeMap<String, HumanPrincipal>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_app(&mut self, name: &str, owner: &str) -> App {
        let app = App { id: format!("app-{}", rand_hex(6)), name: name.to_string(), owner: owner.to_string() };
        self.apps.insert(app.id.clone(), app.clone());
        app
    }

    /// Register an agent under an existing app. Returns the agent plus the ONE-TIME plaintext token
    /// the agent must present on each call; only its hash is retained.
    pub fn register_agent(&mut self, app_id: &str, name: &str) -> Result<(Agent, String), String> {
        if !self.apps.contains_key(app_id) {
            return Err(format!("no such app: {app_id}"));
        }
        let token = rand_hex(32);
        let agent = Agent {
            id: format!("agt-{}", rand_hex(6)),
            app_id: app_id.to_string(),
            name: name.to_string(),
            token_sha256: sha256_hex_bytes(token.as_bytes()),
            active: true,
        };
        self.agents.insert(agent.id.clone(), agent.clone());
        Ok((agent, token))
    }

    /// Verify a presented (agent id, token). Fail-closed: unknown agent, inactive agent, wrong
    /// token, or a dangling app all return None.
    pub fn verify(&self, agent_id: &str, token: &str) -> Option<Identity> {
        let agent = self.agents.get(agent_id)?;
        if !agent.active {
            return None;
        }
        if agent.token_sha256 != sha256_hex_bytes(token.as_bytes()) {
            return None;
        }
        let app = self.apps.get(&agent.app_id)?;
        Some(Identity {
            agent_id: agent.id.clone(),
            app_id: agent.app_id.clone(),
            agent_name: agent.name.clone(),
            app_name: app.name.clone(),
            principal_id: "unattributed".to_string(),
            principal_display: "unattributed".to_string(),
            principal_source: PrincipalSource::Unattributed,
        })
    }

    /// Revoke an agent (deprovision). Its calls stop verifying immediately.
    pub fn deactivate_agent(&mut self, agent_id: &str) -> bool {
        match self.agents.get_mut(agent_id) {
            Some(a) => {
                a.active = false;
                true
            }
            None => false,
        }
    }

    pub fn apps(&self) -> Vec<&App> {
        self.apps.values().collect()
    }
    pub fn agents(&self) -> Vec<&Agent> {
        self.agents.values().collect()
    }

    /// Register a human principal (D1). The id is stable; `resolve_principal` looks it up on a call.
    pub fn register_principal(&mut self, display: &str, source: PrincipalSource) -> HumanPrincipal {
        let p = HumanPrincipal { id: format!("usr-{}", rand_hex(6)), display: display.to_string(), source };
        self.principals.insert(p.id.clone(), p.clone());
        p
    }
    pub fn principals(&self) -> Vec<&HumanPrincipal> {
        self.principals.values().collect()
    }
    /// Resolve a principal id to its record, or the unattributed sentinel if unknown/absent. Never
    /// fails: an unresolved principal degrades to `unattributed` rather than blocking the call here
    /// (policy decides what an unattributed principal may do).
    pub fn resolve_principal(&self, principal_id: &str) -> HumanPrincipal {
        self.principals.get(principal_id).cloned().unwrap_or_else(HumanPrincipal::unattributed)
    }

    pub fn load(path: &str) -> Result<Registry, String> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::new()),
            Err(e) => Err(e.to_string()),
        }
    }
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_verify_an_agent() {
        let mut r = Registry::new();
        let app = r.register_app("portal", "team-x");
        let (agent, token) = r.register_agent(&app.id, "triage").unwrap();
        // The right token verifies to the agent's identity.
        let id = r.verify(&agent.id, &token).expect("verifies");
        assert_eq!(id.agent_id, agent.id);
        assert_eq!(id.app_id, app.id);
        // A wrong token does not.
        assert!(r.verify(&agent.id, "wrong").is_none());
        // The plaintext token is never stored.
        assert_ne!(agent.token_sha256, token);
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let mut r = Registry::new();
        let app = r.register_app("portal", "team");
        let (agent, token) = r.register_agent(&app.id, "a").unwrap();
        assert!(r.verify(&agent.id, &token).is_some());
        assert!(r.deactivate_agent(&agent.id));
        assert!(r.verify(&agent.id, &token).is_none(), "revoked agent must not verify");
    }

    #[test]
    fn an_agent_needs_a_real_app() {
        let mut r = Registry::new();
        assert!(r.register_agent("app-nope", "a").is_err());
    }

    #[test]
    fn round_trips_through_json() {
        let mut r = Registry::new();
        let app = r.register_app("portal", "team");
        let (agent, token) = r.register_agent(&app.id, "a").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let r2: Registry = serde_json::from_str(&json).unwrap();
        assert!(r2.verify(&agent.id, &token).is_some(), "verify survives persistence");
    }

    #[test]
    fn identity_defaults_to_unattributed_then_takes_a_principal() {
        let mut r = Registry::new();
        let app = r.register_app("portal", "team");
        let (agent, token) = r.register_agent(&app.id, "triage").unwrap();
        let id = r.verify(&agent.id, &token).unwrap();
        // No verified human yet.
        assert!(!id.principal_verified());
        assert_eq!(id.principal_source, PrincipalSource::Unattributed);
        // Attach a verified principal.
        let alice = r.register_principal("alice@corp", PrincipalSource::Oauth);
        let id2 = id.with_principal(&alice);
        assert!(id2.principal_verified());
        assert_eq!(id2.principal_id, alice.id);
    }

    #[test]
    fn resolve_principal_degrades_to_unattributed() {
        let mut r = Registry::new();
        let alice = r.register_principal("alice", PrincipalSource::Sso);
        assert_eq!(r.resolve_principal(&alice.id).display, "alice");
        // Unknown id never errors; it degrades.
        assert!(!r.resolve_principal("usr-nope").verified());
    }

    #[test]
    fn delegation_binds_agent_to_principal_and_expires() {
        let mut r = Registry::new();
        let app = r.register_app("portal", "team");
        let (agent, token) = r.register_agent(&app.id, "triage").unwrap();
        let bob = r.register_principal("bob", PrincipalSource::Oauth);
        let id = r.verify(&agent.id, &token).unwrap().with_principal(&bob);
        let d = Delegation::from_identity(&id, "close-tickets", 1_000, 60_000);
        assert_eq!(d.principal_id, bob.id);
        assert!(d.active(30_000));
        assert!(!d.active(61_001), "delegation expires with its ttl");
    }

    #[test]
    fn old_registry_json_without_principals_still_loads() {
        // A v1 file predates the principals map; serde default must fill it.
        let v1 = r#"{"apps":{},"agents":{}}"#;
        let r: Registry = serde_json::from_str(v1).unwrap();
        assert_eq!(r.principals().len(), 0);
    }
}
