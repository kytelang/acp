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

/// The verified identity the proxy stamps into the policy context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub agent_id: String,
    pub app_id: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Registry {
    apps: BTreeMap<String, App>,
    agents: BTreeMap<String, Agent>,
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
        self.apps.get(&agent.app_id)?;
        Some(Identity { agent_id: agent.id.clone(), app_id: agent.app_id.clone() })
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
}
