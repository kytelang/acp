//! The YAML policy DSL: types, parsing, and validation.

use acp_core::types::Verdict;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_allow")]
    pub default: Verdict,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub metadata: Option<Meta>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub when: When,
    pub verdict: Verdict,
    #[serde(default)]
    pub approvers: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// Obligations to apply when this rule allows (model v2, D4). Parsed and carried into the
    /// decision here; the proxy executes them (redact/rate-limit/confirm) at enforcement time.
    #[serde(default)]
    pub obligations: Vec<Obligation>,
}

/// An "allow but ..." obligation attached to an allowing rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationKind {
    /// Require human confirmation before proceeding (routes to the approvals inbox, like step-up).
    Confirm,
    /// Strip or mask the named argument/result fields before the call proceeds.
    Redact,
    /// Cap the call frequency for this (agent, resource) window.
    RateLimit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Obligation {
    pub kind: ObligationKind,
    /// Fields to strip/mask (redact).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    /// Max calls per window (rate_limit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    /// Window length in milliseconds (rate_limit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct When {
    /// Tool name; exact, glob (`db.*`), `*`, or absent for any. Optional in model v2: a rule may
    /// match purely by resource / operation / principal.
    #[serde(default)]
    pub tool: Option<String>,
    /// Registered app id; exact, glob, or absent for any. Trusted (proxy-injected from the
    /// verified registry identity), so an agent cannot spoof it.
    #[serde(default)]
    pub app: Option<String>,
    /// Registered agent id; exact, glob, or absent for any. Trusted, as above.
    #[serde(default)]
    pub agent: Option<String>,
    /// Registered human principal the agent acts for; exact, glob, or absent for any. Trusted
    /// (proxy-injected from the verified delegation). Use "unattributed" to match calls with no
    /// verified human behind them (model v2, D1).
    #[serde(default)]
    pub principal: Option<String>,
    /// Resource class the tool touches (database, filesystem, ...); exact, glob, or absent for any.
    /// Trusted: derived by the proxy from the tool via the resource taxonomy (model v2, D2).
    #[serde(default)]
    pub resource: Option<String>,
    /// Operation the tool performs (read, write, delete, ...); exact, glob, or absent for any.
    /// Trusted: tool-derived, never taken from arguments (model v2, D3).
    #[serde(default)]
    pub operation: Option<String>,
    /// Argument matchers against agent-supplied arguments (the `context.args` namespace).
    #[serde(default)]
    pub arg: BTreeMap<String, Matcher>,
    /// Trusted matcher on the proxy-injected environment (the `context.env` namespace).
    #[serde(default)]
    pub env: Option<Matcher>,
    /// Trusted matcher on the proxy-derived impact level (the `context.impact` namespace).
    #[serde(default)]
    pub impact: Option<Matcher>,
}

/// A single-key matcher map, e.g. `{ gt: 50000 }` or `{ in: [a, b] }`.
#[derive(Debug, Clone, Deserialize)]
pub struct Matcher(pub BTreeMap<String, serde_yaml::Value>);

impl Matcher {
    pub fn op(&self) -> Option<(&str, &serde_yaml::Value)> {
        self.0.iter().next().map(|(k, v)| (k.as_str(), v))
    }
}

fn default_allow() -> Verdict {
    Verdict::Allow
}

/// Parse a YAML policy document.
pub fn parse_str(src: &str) -> Result<Policy, serde_yaml::Error> {
    serde_yaml::from_str(src)
}

/// Compile-time validation (decision D9): reject constructs that are unsound or unsupported in
/// v0, so an author cannot ship a policy that silently misbehaves.
pub fn validate(policy: &Policy) -> Result<(), String> {
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err("a rule has an empty id".into());
        }
        // The `regex` matcher is deferred past M2; reject it rather than compile an inert rule.
        for (key, m) in &rule.when.arg {
            if let Some((op, _)) = m.op() {
                if op == "regex" {
                    return Err(format!(
                        "rule '{}': the 'regex' matcher on '{}' is not supported in v0",
                        rule.id, key
                    ));
                }
            } else {
                return Err(format!("rule '{}': empty matcher on '{}'", rule.id, key));
            }
        }
    }
    Ok(())
}
