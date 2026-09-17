//! MCP version-drift ownership (decision v2.1.3).
//!
//! The MCP spec evolves; a new release can add action-bearing methods. If the interception surface
//! does not keep up, a new method could pass ungoverned. This tracks the set of methods ACP knows
//! how to govern and flags any observed method it does not, so drift becomes an alert (and a
//! worklist), never a silent bypass.

use std::collections::BTreeSet;

#[derive(Debug, Default)]
pub struct MethodRegistry {
    governed: BTreeSet<String>,
}

impl MethodRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn govern(&mut self, method: &str) {
        self.governed.insert(method.to_string());
    }

    /// Methods observed on the wire that ACP does not yet know how to govern. Any of these could be
    /// action-bearing, so they are surfaced for review rather than assumed safe.
    pub fn ungoverned(&self, observed: &[String]) -> Vec<String> {
        let mut out: Vec<String> = observed
            .iter()
            .filter(|m| !self.governed.contains(*m))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_unknown_method_is_flagged_not_bypassed() {
        let mut r = MethodRegistry::new();
        r.govern("tools/call");
        r.govern("tools/list");
        let seen = vec![
            "tools/call".into(),
            "resources/write".into(),
            "tools/list".into(),
        ];
        assert_eq!(
            r.ungoverned(&seen),
            vec!["resources/write"],
            "the new method is surfaced"
        );
    }

    #[test]
    fn a_fully_known_surface_has_no_drift() {
        let mut r = MethodRegistry::new();
        r.govern("tools/call");
        assert!(r.ungoverned(&["tools/call".into()]).is_empty());
    }
}
