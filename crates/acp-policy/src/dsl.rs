//! The YAML policy DSL: types and parsing.

use acp_core::types::Verdict;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_allow")]
    pub default: Verdict,
    /// Optional top-level `mode: shadow` (also settable as acp-server config).
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
    /// Argument matchers; BTreeMap so compiled output is deterministic (sorted keys).
    #[serde(default)]
    pub arg: BTreeMap<String, Matcher>,
}

/// A single-key matcher map, e.g. `{ gt: 50000 }` or `{ in: [a, b] }`.
///
/// Modelled as a one-entry map (not a Rust enum) because serde_yaml encodes externally-
/// tagged enums with `!Tag` syntax, which is not the `{op: value}` shape authors write.
/// The compiler interprets the single (operator, value) pair.
#[derive(Debug, Clone, Deserialize)]
pub struct Matcher(pub BTreeMap<String, serde_yaml::Value>);

impl Matcher {
    /// The (operator, value) pair, or None if the map is empty.
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
