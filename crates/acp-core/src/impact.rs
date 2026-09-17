//! Configurable impact taxonomy (decision E4/D13).
//!
//! Impact is no longer a hardcoded heuristic: it is a declarative, versioned, per-tenant config
//! evaluated into the trusted context namespace. A default taxonomy reproduces the v0 heuristic.
//! The taxonomy version is stamped into evidence so a historical decision is reproducible.

use crate::types::BlastRadius;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct ImpactTaxonomy {
    /// Version id stamped into evidence, e.g. "impact@1".
    pub version: String,
    /// Argument value (for the `operation` field) treated as destructive.
    #[serde(default)]
    pub destructive_ops: Vec<String>,
    /// Substrings in the tool name treated as destructive.
    #[serde(default)]
    pub destructive_tool_substrings: Vec<String>,
    /// Numeric argument keys whose large values raise impact.
    #[serde(default)]
    pub amount_keys: Vec<String>,
    /// Threshold above which an amount is "large".
    #[serde(default)]
    pub amount_high_threshold: f64,
    /// Argument keys whose presence means the action leaves the boundary (external recipient).
    #[serde(default)]
    pub external_keys: Vec<String>,
    /// points >= high_at -> High; >= medium_at -> Medium; else Low.
    #[serde(default)]
    pub medium_at: i32,
    #[serde(default)]
    pub high_at: i32,
}

impl Default for ImpactTaxonomy {
    fn default() -> Self {
        ImpactTaxonomy {
            version: "impact@default-1".into(),
            destructive_ops: ["delete", "drop", "truncate", "remove", "wipe", "destroy"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            destructive_tool_substrings: [
                "delete", "drop", "truncate", "remove", "wipe", "destroy",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            amount_keys: ["amount_cents", "amount", "quantity", "count"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            amount_high_threshold: 10_000.0,
            external_keys: ["to", "recipient", "external"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            medium_at: 2,
            high_at: 4,
        }
    }
}

impl ImpactTaxonomy {
    pub fn from_yaml(src: &str) -> Result<Self, String> {
        serde_yaml::from_str(src).map_err(|e| e.to_string())
    }

    /// Score a tool call into a blast-radius level, deterministically.
    pub fn score(&self, tool: &str, args: &Value) -> BlastRadius {
        let mut points = 0i32;
        if let Some(op) = args.get("operation").and_then(Value::as_str) {
            if self
                .destructive_ops
                .iter()
                .any(|d| d.eq_ignore_ascii_case(op))
            {
                points += 2;
            }
        }
        let tool_l = tool.to_ascii_lowercase();
        if self
            .destructive_tool_substrings
            .iter()
            .any(|d| tool_l.contains(d.as_str()))
        {
            points += 1;
        }
        for k in &self.amount_keys {
            if let Some(n) = args.get(k).and_then(Value::as_f64) {
                points += if n > self.amount_high_threshold {
                    2
                } else if n > 0.0 {
                    1
                } else {
                    0
                };
            }
        }
        if let Some(t) = args.get("target").and_then(Value::as_str) {
            if t == "*" || t.eq_ignore_ascii_case("all") {
                points += 2;
            }
        }
        if self.external_keys.iter().any(|k| args.get(k).is_some()) {
            points += 2;
        }
        if points >= self.high_at {
            BlastRadius::High
        } else if points >= self.medium_at {
            BlastRadius::Medium
        } else {
            BlastRadius::Low
        }
    }
}
