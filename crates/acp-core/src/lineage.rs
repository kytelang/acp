//! Data-boundary lineage records (decision v2.2.1).
//!
//! Governance needs to answer "which class of data reached which tool, and under what purpose".
//! This records, per decision, the data classes the classifier detected in the arguments and the
//! declared purpose, using only class labels (pii/secret/...), never the raw values. The record is
//! meant to attach to the evidence leaf, so lineage is queryable without ever storing payloads.

use std::collections::{BTreeMap, BTreeSet};

/// One lineage entry: classes that flowed to a tool for a stated purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub tool: String,
    pub classes: BTreeSet<String>,
    pub purpose: String,
}

/// Accumulates lineage across decisions. Keyed by tool for "what reached this tool" queries.
#[derive(Debug, Default)]
pub struct LineageLog {
    by_tool: BTreeMap<String, BTreeSet<String>>,
}

impl LineageLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `classes` (class labels only) flowed to `tool` for `purpose`. Returns the Flow
    /// so the caller can attach it to the evidence record.
    pub fn record(&mut self, tool: &str, classes: &[String], purpose: &str) -> Flow {
        let set: BTreeSet<String> = classes.iter().cloned().collect();
        self.by_tool
            .entry(tool.to_string())
            .or_default()
            .extend(set.iter().cloned());
        Flow {
            tool: tool.to_string(),
            classes: set,
            purpose: purpose.to_string(),
        }
    }

    /// All data classes ever seen flowing to a tool.
    pub fn classes_for(&self, tool: &str) -> BTreeSet<String> {
        self.by_tool.get(tool).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_class_flow_per_tool_without_raw_values() {
        let mut l = LineageLog::new();
        let f = l.record("email.send", &["pii".into()], "customer-support");
        assert_eq!(f.purpose, "customer-support");
        assert!(f.classes.contains("pii"));
        l.record("email.send", &["secret".into()], "customer-support");
        let seen = l.classes_for("email.send");
        assert!(seen.contains("pii") && seen.contains("secret"));
        assert!(l.classes_for("catalog.read").is_empty());
    }

    #[test]
    fn a_flow_carries_only_labels() {
        let mut l = LineageLog::new();
        let f = l.record("db.write", &["pii".into()], "billing");
        // The Flow has classes and purpose, no field for argument content.
        let dbg = format!("{f:?}");
        assert!(dbg.contains("pii") && dbg.contains("billing"));
    }
}
