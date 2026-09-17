//! Discovery plane for un-governed AI usage (decision v2.3.1).
//!
//! Before you can govern agent traffic you have to find it. This compares observed tool endpoints
//! against the set already routed through the proxy and produces a "govern this next" worklist. It
//! also records what the discovery pass did NOT cover, so a partial scan never masquerades as
//! full coverage (the no-silent-truncation rule).

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// Observed endpoints not currently routed through the proxy: the worklist.
    pub ungoverned: Vec<String>,
    /// Scopes the pass could not inspect (e.g. a namespace with no read access).
    pub not_covered: Vec<String>,
}

/// Compare observed endpoints against the governed set. `uncovered_scopes` is passed through so the
/// report is explicit about gaps rather than silently complete.
pub fn discover(
    observed: &[String],
    governed: &[String],
    uncovered_scopes: &[String],
) -> DiscoveryReport {
    let gov: BTreeSet<&String> = governed.iter().collect();
    let mut ungoverned: Vec<String> = observed
        .iter()
        .filter(|e| !gov.contains(e))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ungoverned.sort();
    let mut not_covered = uncovered_scopes.to_vec();
    not_covered.sort();
    not_covered.dedup();
    DiscoveryReport {
        ungoverned,
        not_covered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ungoverned_endpoints_become_the_worklist() {
        let r = discover(
            &["a.tool".into(), "b.tool".into(), "c.tool".into()],
            &["b.tool".into()],
            &[],
        );
        assert_eq!(r.ungoverned, vec!["a.tool", "c.tool"]);
    }

    #[test]
    fn uncovered_scopes_are_reported_not_hidden() {
        let r = discover(
            &["a.tool".into()],
            &[],
            &["ns:secret".into(), "ns:secret".into()],
        );
        assert_eq!(r.not_covered, vec!["ns:secret"], "gaps surfaced, deduped");
    }
}
