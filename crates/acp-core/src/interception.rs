//! Configuration-driven traffic interception: the endpoint rule registry and matcher
//! (traffic-interception design, phase 1).
//!
//! A signed, versioned list of endpoint rules is the source of truth for which destinations ACP
//! inspects and how. Each rule is a match (host / sni / path / port predicates), a classification,
//! and an action. The matcher is pure and first-match: given a destination it returns the decision.
//! The forward proxy (phase 2) is the mechanism that applies it; this module is the brain it consults.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};

/// What ACP does with matching traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Decrypt, extract the prompt/completion body, run content + policy engines.
    InspectPrompt,
    /// Treat the body as a tool call and run the MCP decision path.
    GovernToolCall,
    /// Scan the body for exfiltration (PII/secrets) only, no model-call governance.
    DlpOnly,
    /// Refuse the connection.
    Block,
    /// Allow without inspection (recorded as seen).
    Pass,
}

impl Action {
    /// True when the action must read the request body (and so must terminate TLS).
    pub fn needs_body(&self) -> bool {
        matches!(self, Action::InspectPrompt | Action::GovernToolCall | Action::DlpOnly)
    }
}

/// The action for destinations that match no rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultAction {
    /// Record as shadow AI, then pass.
    FlagAndPass,
    /// Record as shadow AI, then block.
    FlagAndBlock,
    Pass,
    Block,
}

impl DefaultAction {
    pub fn flags(&self) -> bool {
        matches!(self, DefaultAction::FlagAndPass | DefaultAction::FlagAndBlock)
    }
    pub fn blocks(&self) -> bool {
        matches!(self, DefaultAction::FlagAndBlock | DefaultAction::Block)
    }
}

/// Match predicates. All present predicates must hold (AND). Absent predicates are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Match {
    /// True if this predicate set has any path condition (so it can only be decided after decrypt).
    pub fn has_path_predicate(&self) -> bool {
        self.path_contains.is_some() || self.path_prefix.is_some()
    }

    /// Do the host / sni / port predicates hold? (The part decidable before decryption.)
    fn host_level_matches(&self, host: &str, port: u16) -> bool {
        let h = host.to_ascii_lowercase();
        if let Some(v) = &self.host_contains {
            if !h.contains(&v.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(v) = &self.host_suffix {
            if !h.ends_with(&v.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(v) = &self.host_exact {
            if h != v.to_ascii_lowercase() {
                return false;
            }
        }
        if let Some(v) = &self.sni {
            // SNI is the same string as host at this layer; match it the same way.
            if !h.contains(&v.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(p) = self.port {
            if p != port {
                return false;
            }
        }
        true
    }

    fn path_level_matches(&self, path: &str) -> bool {
        if let Some(v) = &self.path_contains {
            if !path.contains(v.as_str()) {
                return false;
            }
        }
        if let Some(v) = &self.path_prefix {
            if !path.starts_with(v.as_str()) {
                return false;
            }
        }
        true
    }

    /// Full match: host-level AND path-level (path known).
    pub fn matches(&self, host: &str, path: &str, port: u16) -> bool {
        self.host_level_matches(host, port) && self.path_level_matches(path)
    }
}

/// One endpoint rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "match")]
    pub match_: Match,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classify: Option<String>,
    pub action: Action,
}

/// The decision the matcher returns for one destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub rule_id: Option<String>,
    pub classification: String,
    pub action: Action,
    /// Whether the destination matched no rule (hit the default).
    pub defaulted: bool,
    /// Whether to record it as shadow AI (default-flag path).
    pub flag: bool,
}

/// The signed, versioned endpoint rule registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRegistry {
    pub version: u32,
    pub default: DefaultAction,
    #[serde(default)]
    pub endpoints: Vec<EndpointRule>,
}

impl EndpointRegistry {
    /// Parse from YAML.
    pub fn from_yaml(src: &str) -> Result<EndpointRegistry, String> {
        serde_yaml::from_str(src).map_err(|e| format!("invalid endpoint registry YAML: {e}"))
    }

    /// Evaluate a full destination (path known). First matching rule wins; else the default.
    pub fn evaluate(&self, host: &str, path: &str, port: u16) -> Decision {
        for r in &self.endpoints {
            if r.match_.matches(host, path, port) {
                return Decision {
                    rule_id: r.id.clone(),
                    classification: r.classify.clone().unwrap_or_else(|| "other".into()),
                    action: r.action,
                    defaulted: false,
                    flag: false,
                };
            }
        }
        Decision {
            rule_id: None,
            classification: "other".into(),
            action: if self.default.blocks() { Action::Block } else { Action::Pass },
            defaulted: true,
            flag: self.default.flags(),
        }
    }

    /// SNI-stage least-inspection gate: should this connection be decrypted at all? True if any rule
    /// whose host/sni/port predicates match would need the body (either its action needs the body, or
    /// it has a path predicate that can only be evaluated after decryption).
    pub fn should_decrypt(&self, host: &str, port: u16) -> bool {
        // Precedence-aware least-inspection gate. Walk rules in order; the first rule whose host-level
        // predicates match decides: a path predicate forces decryption (the path is only visible after
        // TLS termination), otherwise decrypt only if the action needs the body. An earlier terminal
        // block/pass rule short-circuits, so a host with such a rule ahead of any path rule is never
        // decrypted. Caveat: a path-only rule (no host predicate) host-matches every destination,
        // so it forces decrypting all traffic to see the path; scope path rules to a host to avoid it.
        for r in &self.endpoints {
            if !r.match_.host_level_matches(host, port) {
                continue;
            }
            if r.match_.has_path_predicate() {
                return true;
            }
            return r.action.needs_body();
        }
        false
    }

    /// Sign the registry (canonical bytes + Ed25519).
    pub fn sign(&self, signer: &dyn Signer) -> SignedRegistry {
        let bytes = crate::canonical::canonical_bytes(self);
        let sig = signer.sign(&bytes);
        SignedRegistry {
            registry: self.clone(),
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// A signed endpoint registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRegistry {
    pub registry: EndpointRegistry,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

pub fn verify(signed: &SignedRegistry) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&pk, &crate::canonical::canonical_bytes(&signed.registry), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn reg() -> EndpointRegistry {
        EndpointRegistry::from_yaml(
            r#"
version: 1
default: flag-and-pass
endpoints:
  - id: anthropic
    match: { host_contains: claude.ai }
    classify: model-api
    action: inspect-prompt
  - id: openai
    match: { host_exact: api.openai.com }
    classify: model-api
    action: inspect-prompt
  - id: deepseek
    match: { host_contains: deepseek.com }
    classify: model-api
    action: block
  - id: mcp
    match: { host_suffix: internal, path_contains: /mcp }
    classify: mcp
    action: govern-tool-call
"#,
        )
        .unwrap()
    }

    #[test]
    fn host_contains_selects_inspect_prompt() {
        let d = reg().evaluate("api.claude.ai", "/v1/messages", 443);
        assert_eq!(d.action, Action::InspectPrompt);
        assert_eq!(d.rule_id.as_deref(), Some("anthropic"));
        assert_eq!(d.classification, "model-api");
        assert!(!d.defaulted);
    }

    #[test]
    fn path_predicate_selects_tool_governance() {
        let d = reg().evaluate("tools.internal", "/mcp/call", 443);
        assert_eq!(d.action, Action::GovernToolCall);
        assert_eq!(d.rule_id.as_deref(), Some("mcp"));
    }

    #[test]
    fn block_rule_wins() {
        assert_eq!(reg().evaluate("api.deepseek.com", "/x", 443).action, Action::Block);
    }

    #[test]
    fn unregistered_hits_default_flag_and_pass() {
        let d = reg().evaluate("example.com", "/", 443);
        assert!(d.defaulted);
        assert!(d.flag);
        assert_eq!(d.action, Action::Pass);
    }

    #[test]
    fn first_match_wins() {
        // exact rule must beat a later broader one if listed first; here openai exact then check order
        let d = reg().evaluate("api.openai.com", "/v1/chat", 443);
        assert_eq!(d.rule_id.as_deref(), Some("openai"));
    }

    #[test]
    fn should_decrypt_only_for_body_needing_hosts() {
        let r = reg();
        assert!(r.should_decrypt("api.claude.ai", 443), "inspect-prompt host needs body");
        assert!(!r.should_decrypt("api.deepseek.com", 443), "block host does not need body");
        assert!(!r.should_decrypt("example.com", 443), "unmatched host does not decrypt");
    }

    #[test]
    fn registry_signs_and_verifies() {
        let signed = reg().sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.registry.version = 999;
        assert!(!verify(&bad));
    }
}
