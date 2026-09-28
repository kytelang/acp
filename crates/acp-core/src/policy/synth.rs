//! Least-privilege policy synthesis (gap G2).
//!
//! `acp learn` observes what agents actually do in shadow mode. This turns those observations into the
//! smallest policy that permits exactly what was seen and denies everything else: a default-deny policy
//! with one rule per distinct observed (tool, resource, operation) that was allowed (or held for
//! step-up), preserving the observed verdict. An action never seen falls through to the default deny.
//!
//! Writing an allow-list from scratch is the biggest barrier to adopting an authorization product; this
//! removes it. The output is the model-v2 DSL as YAML, reviewed as a diff and signed off by a human
//! before it is deployed (the server and console handle that gate); nothing here deploys anything.

use std::collections::BTreeMap;

/// One observed action, distilled from a decision record in the ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedAction {
    pub tool: String,
    pub resource: String,
    pub operation: String,
    /// "allow", "step_up" or "deny" (as recorded).
    pub verdict: String,
}

/// Quote a YAML scalar if it contains characters that are unsafe bare (dots, slashes, etc.).
fn yq(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

/// Synthesise the smallest allow-only (default-deny) policy that permits exactly the observed
/// allowed and step-up actions. Returns a model-v2 DSL YAML document. Deterministic: rules are sorted
/// by (tool, resource, operation), so the same observations always yield byte-identical output (a
/// stable diff for review).
pub fn synthesize_least_privilege(observed: &[ObservedAction]) -> String {
    // Key on the tool: it uniquely determines the action, and its resource/operation are tool-derived,
    // so keying on the tool alone is robust to taxonomy drift (a rule keyed on a stored resource that
    // the live taxonomy later reclassifies would wrongly deny). Collapse to the least restrictive
    // verdict actually seen (allow beats step_up); denied observations are left to the default deny.
    // Finer narrowing (resource, operation, argument class) is a future refinement.
    let mut keep: BTreeMap<String, &'static str> = BTreeMap::new();
    for a in observed {
        let permit = match a.verdict.as_str() {
            "allow" => "allow",
            "step_up" => "step_up",
            _ => continue, // deny (and anything else) is covered by default-deny
        };
        let cur = keep.entry(a.tool.clone()).or_insert(permit);
        if permit == "allow" {
            *cur = "allow"; // allow wins over step_up for the same action
        }
    }

    let mut out = String::new();
    out.push_str("# Least-privilege policy proposed by `acp learn` from observed traffic.\n");
    out.push_str("# Default-deny: it permits exactly what was observed and denies everything else.\n");
    out.push_str("# Review the diff and sign off before deploying.\n");
    out.push_str("version: 1\n");
    out.push_str("default: deny\n");
    out.push_str("rules:\n");
    if keep.is_empty() {
        out.push_str("  []\n");
        return out;
    }
    let mut n = 0;
    for (tool, verdict) in &keep {
        n += 1;
        out.push_str(&format!("  - id: allow-{n}\n"));
        out.push_str(&format!("    when: {{ tool: {} }}\n", yq(tool)));
        out.push_str(&format!("    verdict: {verdict}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::eval::PolicyEngine;
    use crate::policy::context::build_context_identified_full;
    use crate::impact::ImpactTaxonomy;
    use crate::resource::ResourceTaxonomy;
    use crate::types::Verdict;

    fn observed(tool: &str, verdict: &str) -> ObservedAction {
        let (r, o) = ResourceTaxonomy::default().classify(tool);
        ObservedAction { tool: tool.into(), resource: r.as_str().into(), operation: o.as_str().into(), verdict: verdict.into() }
    }
    fn ctx(tool: &str) -> serde_json::Value {
        build_context_identified_full(tool, &serde_json::json!({}), "prod", "a", "", "alice", &[],
            &ImpactTaxonomy::default(), &ResourceTaxonomy::default())
    }

    #[test]
    fn synthesised_policy_allows_observed_and_denies_unobserved() {
        // Observed: two tools allowed. Held out: a third, never seen.
        let obs = vec![observed("db.query", "allow"), observed("send_email", "allow")];
        let yaml = synthesize_least_privilege(&obs);
        let e = PolicyEngine::from_yaml(&yaml).expect("synthesised policy must compile");
        assert_eq!(e.default_verdict(), Verdict::Deny);
        // every observed action is permitted
        assert_eq!(e.evaluate(ctx("db.query")).verdict, Verdict::Allow, "observed tool allowed");
        assert_eq!(e.evaluate(ctx("send_email")).verdict, Verdict::Allow, "observed tool allowed");
        // an unobserved action is denied by the default
        assert_eq!(e.evaluate(ctx("get_secret")).verdict, Verdict::Deny, "unobserved tool denied");
    }

    #[test]
    fn denied_observations_are_not_granted() {
        // A tool that was only ever denied must not appear as an allow rule.
        let obs = vec![observed("db.query", "allow"), observed("wipe_disk", "deny")];
        let yaml = synthesize_least_privilege(&obs);
        let e = PolicyEngine::from_yaml(&yaml).unwrap();
        assert_eq!(e.evaluate(ctx("db.query")).verdict, Verdict::Allow);
        assert_eq!(e.evaluate(ctx("wipe_disk")).verdict, Verdict::Deny, "a denied-only tool stays denied");
    }

    #[test]
    fn step_up_observation_is_preserved() {
        let obs = vec![observed("payments.charge", "step_up")];
        let yaml = synthesize_least_privilege(&obs);
        assert!(yaml.contains("verdict: step_up"), "a step-up observation yields a step-up rule");
        let e = PolicyEngine::from_yaml(&yaml).unwrap();
        assert_eq!(e.evaluate(ctx("payments.charge")).verdict, Verdict::StepUp);
    }

    #[test]
    fn empty_observations_yield_a_valid_deny_all() {
        let yaml = synthesize_least_privilege(&[]);
        let e = PolicyEngine::from_yaml(&yaml).unwrap();
        assert_eq!(e.evaluate(ctx("db.query")).verdict, Verdict::Deny);
    }
}
