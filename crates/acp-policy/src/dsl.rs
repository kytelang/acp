//! The YAML policy DSL: types, parsing, and validation.

use acp_core::types::Verdict;
use serde::Deserialize;
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct When {
    /// Tool name; exact, glob (`db.*`), or `*` for any.
    pub tool: String,
    /// Registered app id; exact, glob, or absent for any. Trusted (proxy-injected from the
    /// verified registry identity), so an agent cannot spoof it.
    #[serde(default)]
    pub app: Option<String>,
    /// Registered agent id; exact, glob, or absent for any. Trusted, as above.
    #[serde(default)]
    pub agent: Option<String>,
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
