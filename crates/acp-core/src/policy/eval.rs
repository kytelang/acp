//! The Cedar evaluation engine (decisions D2/D9/D13).
//!
//! A `PolicyEngine` compiles the YAML DSL to Cedar, loads it into a `cedar-policy` PolicySet,
//! and evaluates an action context into a four-way `PolicyOutcome`. Key soundness properties:
//!   - namespaced context (the compiler keeps agent data under `context.args`);
//!   - any Cedar evaluation or context-construction error is fail-closed (deny), never a
//!     silent fall-through to the default (D13/A3);
//!   - when several policies co-determine, verdict precedence is deny > step_up > shadow > allow.

use crate::policy::compile::compile_to_cedar;
use crate::policy::dsl;
use crate::types::Verdict;
use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request};
use std::str::FromStr;

/// The resolved policy result for one action (impact and provenance are added by the proxy).
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyOutcome {
    pub verdict: Verdict,
    pub rule_id: Option<String>,
    pub approvers: Vec<String>,
    pub reason: Option<String>,
    /// Obligations to apply on an allow (model v2, D4). Empty for a plain allow/deny.
    pub obligations: Vec<dsl::Obligation>,
}

pub struct PolicyEngine {
    pset: PolicySet,
    hash: String,
    default: Verdict,
    /// Global observe (shadow / dry-run) mode: downgrade blocking verdicts to `shadow` so the
    /// action proceeds while the intended verdict is still recorded as evidence (M-observe).
    observe: bool,
}

impl PolicyEngine {
    /// Build an engine from YAML source: validate, compile to Cedar, load, and hash the source.
    pub fn from_yaml(src: &str) -> Result<PolicyEngine, String> {
        let policy = dsl::parse_str(src).map_err(|e| format!("invalid policy YAML: {e}"))?;
        dsl::validate(&policy)?;
        let cedar_src = compile_to_cedar(&policy);
        let pset =
            PolicySet::from_str(&cedar_src).map_err(|e| format!("cedar compile error: {e}"))?;
        let hash = crate::canonical::sha256_hex(&src.to_string());
        Ok(PolicyEngine {
            pset,
            hash,
            default: policy.default,
            observe: policy.mode.as_deref() == Some("observe"),
        })
    }

    /// Content hash over the YAML source; stamped into every evidence record.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn default_verdict(&self) -> Verdict {
        self.default
    }

    /// True when the manifest set `enforcement_mode: observe` (dry-run).
    pub fn is_observe(&self) -> bool {
        self.observe
    }

    /// Evaluate a context JSON value into a four-way outcome.
    pub fn evaluate(&self, context_json: serde_json::Value) -> PolicyOutcome {
        let ctx = match Context::from_json_value(context_json, None) {
            Ok(c) => c,
            Err(_) => return fail_closed("context construction error (fail-closed)"),
        };
        let (p, a, r) = fixed_entities();
        let req = match Request::new(p, a, r, ctx, None) {
            Ok(req) => req,
            Err(_) => return fail_closed("request construction error (fail-closed)"),
        };
        let resp = Authorizer::new().is_authorized(&req, &self.pset, &Entities::empty());

        // Any evaluation error fails closed (D13/A3), never a silent fall-through.
        if resp.diagnostics().errors().next().is_some() {
            return fail_closed("policy evaluation error (fail-closed)");
        }

        // Resolve the verdict across all determining policies by precedence.
        let mut chosen: Option<PolicyOutcome> = None;
        for pid in resp.diagnostics().reason() {
            let pol = match self.pset.policy(pid) {
                Some(p) => p,
                None => continue,
            };
            let verdict = match pol.annotation("verdict").and_then(parse_verdict) {
                Some(v) => v,
                None => return fail_closed("determining policy without a verdict (fail-closed)"),
            };
            let candidate = PolicyOutcome {
                verdict,
                rule_id: pol.annotation("id").map(str::to_string),
                approvers: pol
                    .annotation("approvers")
                    .map(|s| s.split(',').map(str::to_string).collect())
                    .unwrap_or_default(),
                reason: pol.annotation("reason").map(str::to_string),
                obligations: pol
                    .annotation("obligations")
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_default(),
            };
            chosen = Some(match chosen {
                Some(cur) if rank(cur.verdict) >= rank(candidate.verdict) => cur,
                _ => candidate,
            });
        }

        let outcome = chosen.unwrap_or(PolicyOutcome {
            verdict: self.default,
            rule_id: None,
            approvers: vec![],
            reason: None,
            obligations: vec![],
        });
        self.apply_observe(outcome)
    }

    /// In observe mode, a deny or step_up is recorded but not enforced: the effective verdict becomes
    /// `shadow` (evaluated, would-block, action proceeds) and the reason is annotated with the verdict
    /// that would have applied under enforce. Allow and shadow pass through unchanged. Fail-closed
    /// system errors are NOT downgraded: observe relaxes policy decisions, not internal safety.
    fn apply_observe(&self, mut o: PolicyOutcome) -> PolicyOutcome {
        if !self.observe {
            return o;
        }
        let would = match o.verdict {
            Verdict::Deny => "would deny",
            Verdict::StepUp => "would step_up",
            _ => return o,
        };
        o.reason = Some(match o.reason.take() {
            Some(r) => format!("observe mode: {would} ({r})"),
            None => format!("observe mode: {would}"),
        });
        o.verdict = Verdict::Shadow;
        o
    }
}

/// Precedence for co-determining policies: deny > step_up > shadow > allow.
fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Deny => 3,
        Verdict::StepUp => 2,
        Verdict::Shadow => 1,
        Verdict::Allow => 0,
    }
}

fn parse_verdict(s: &str) -> Option<Verdict> {
    match s {
        "allow" => Some(Verdict::Allow),
        "deny" => Some(Verdict::Deny),
        "step_up" => Some(Verdict::StepUp),
        "shadow" => Some(Verdict::Shadow),
        _ => None,
    }
}

fn fail_closed(reason: &str) -> PolicyOutcome {
    PolicyOutcome {
        verdict: Verdict::Deny,
        rule_id: Some("eval-error".into()),
        approvers: vec![],
        reason: Some(reason.into()),
        obligations: vec![],
    }
}

/// Fixed request entities. Policies constrain only `context`, so the head entities are dummies.
fn fixed_entities() -> (EntityUid, EntityUid, EntityUid) {
    (
        EntityUid::from_str(r#"Agent::"self""#).unwrap(),
        EntityUid::from_str(r#"Action::"call""#).unwrap(),
        EntityUid::from_str(r#"Tool::"t""#).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::context::build_context_identified_full;
    use crate::impact::ImpactTaxonomy;
    use crate::resource::ResourceTaxonomy;

    fn ctx(tool: &str, agent: &str, principal: &str) -> serde_json::Value {
        build_context_identified_full(
            tool, &serde_json::json!({}), "prod", agent, "", principal, &[],
            &ImpactTaxonomy::default(), &ResourceTaxonomy::default(),
        )
    }

    fn ctx_grp(tool: &str, principal: &str, groups: &[&str]) -> serde_json::Value {
        let g: Vec<String> = groups.iter().map(|s| s.to_string()).collect();
        build_context_identified_full(
            tool, &serde_json::json!({}), "prod", "a", "", principal, &g,
            &ImpactTaxonomy::default(), &ResourceTaxonomy::default(),
        )
    }

    #[test]
    fn policy_matches_on_the_principal_group() {
        // One org-wide policy differentiates by IdP group: finance is denied shell.exec, others allowed.
        let src = "version: 1\ndefault: allow\nrules:\n  - id: finance-no-shell\n    when: { group: finance, tool: shell.exec }\n    verdict: deny\n";
        let e = PolicyEngine::from_yaml(src).unwrap();
        // A user in the finance group is denied.
        assert_eq!(e.evaluate(ctx_grp("shell.exec", "alice", &["finance", "all-staff"])).verdict, Verdict::Deny);
        // A user in a different group is allowed (default).
        assert_eq!(e.evaluate(ctx_grp("shell.exec", "bob", &["engineering"])).verdict, Verdict::Allow);
        // A user with no groups is allowed (the group rule does not match).
        assert_eq!(e.evaluate(ctx_grp("shell.exec", "carol", &[])).verdict, Verdict::Allow);
        // The same finance user calling a different tool is unaffected by the shell rule.
        assert_eq!(e.evaluate(ctx_grp("db.query", "alice", &["finance"])).verdict, Verdict::Allow);
    }

    #[test]
    fn resource_and_operation_are_matched_from_the_tool() {
        // Deny any delete on the database resource, for any agent.
        let src = "version: 1\ndefault: allow\nrules:\n  - id: no-db-delete\n    when: { resource: database, operation: delete }\n    verdict: deny\n";
        let e = PolicyEngine::from_yaml(src).unwrap();
        // db.delete_row -> (database, delete): denied.
        assert_eq!(e.evaluate(ctx("db.delete_row", "any", "")).verdict, Verdict::Deny);
        // db.query -> (database, read): allowed (default).
        assert_eq!(e.evaluate(ctx("db.query", "any", "")).verdict, Verdict::Allow);
        // write_file -> (filesystem, write): not database, allowed.
        assert_eq!(e.evaluate(ctx("write_file", "any", "")).verdict, Verdict::Allow);
    }

    #[test]
    fn principal_scope_matches_the_verified_human() {
        // Unattributed callers may not touch secrets.
        let src = "version: 1\ndefault: allow\nrules:\n  - id: no-anon-secrets\n    when: { resource: secrets, principal: unattributed }\n    verdict: deny\n";
        let e = PolicyEngine::from_yaml(src).unwrap();
        assert_eq!(e.evaluate(ctx("get_secret", "a", "unattributed")).verdict, Verdict::Deny);
        // A verified human (alice) is allowed.
        assert_eq!(e.evaluate(ctx("get_secret", "a", "alice")).verdict, Verdict::Allow);
    }

    #[test]
    fn observe_mode_downgrades_blocks_to_shadow_but_records_the_intended_verdict() {
        // Same rules, one enforce and one observe. In observe the deny is evaluated and recorded
        // (as shadow, with the intended verdict in the reason) but does not block.
        let rules = "rules:
  - id: no-db-delete
    when: { resource: database, operation: delete }
    verdict: deny
    reason: no deletes
  - id: refund-approval
    when: { tool: pay.refund }
    verdict: step_up
";
        let enforce = PolicyEngine::from_yaml(&format!("version: 1\ndefault: allow\n{rules}")).unwrap();
        assert!(!enforce.is_observe());
        assert_eq!(enforce.evaluate(ctx("db.delete_row", "a", "")).verdict, Verdict::Deny);
        assert_eq!(enforce.evaluate(ctx("pay.refund", "a", "")).verdict, Verdict::StepUp);

        let observe = PolicyEngine::from_yaml(&format!("version: 1\ndefault: allow\nenforcement_mode: observe\n{rules}")).unwrap();
        assert!(observe.is_observe());
        let d = observe.evaluate(ctx("db.delete_row", "a", ""));
        assert_eq!(d.verdict, Verdict::Shadow, "deny is downgraded to shadow under observe");
        assert_eq!(d.rule_id.as_deref(), Some("no-db-delete"), "the rule is still attributed");
        assert!(d.reason.as_deref().unwrap().contains("would deny"), "reason records the intended verdict: {:?}", d.reason);
        let s = observe.evaluate(ctx("pay.refund", "a", ""));
        assert_eq!(s.verdict, Verdict::Shadow);
        assert!(s.reason.as_deref().unwrap().contains("would step_up"));
        // an allow is untouched by observe mode.
        assert_eq!(observe.evaluate(ctx("db.query", "a", "")).verdict, Verdict::Allow);
    }

    #[test]
    fn unknown_enforcement_mode_is_rejected() {
        let src = "version: 1\ndefault: allow\nenforcement_mode: whatever\nrules: []\n";
        assert!(PolicyEngine::from_yaml(src).is_err());
    }

    #[test]
    fn obligations_round_trip_into_the_outcome() {
        let src = "version: 1\ndefault: allow\nrules:\n  - id: mask-pii\n    when: { resource: database, operation: read }\n    verdict: allow\n    obligations:\n      - kind: redact\n        fields: [ssn, card]\n";
        let e = PolicyEngine::from_yaml(src).unwrap();
        let out = e.evaluate(ctx("db.query", "a", ""));
        assert_eq!(out.verdict, Verdict::Allow);
        assert_eq!(out.obligations.len(), 1);
        assert_eq!(out.obligations[0].kind, dsl::ObligationKind::Redact);
        assert_eq!(out.obligations[0].fields, vec!["ssn".to_string(), "card".to_string()]);
    }
}
