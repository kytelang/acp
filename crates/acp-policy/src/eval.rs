//! The Cedar evaluation engine (decisions D2/D9/D13).
//!
//! A `PolicyEngine` compiles the YAML DSL to Cedar, loads it into a `cedar-policy` PolicySet,
//! and evaluates an action context into a four-way `PolicyOutcome`. Key soundness properties:
//!   - namespaced context (the compiler keeps agent data under `context.args`);
//!   - any Cedar evaluation or context-construction error is fail-closed (deny), never a
//!     silent fall-through to the default (D13/A3);
//!   - when several policies co-determine, verdict precedence is deny > step_up > shadow > allow.

use crate::compile::compile_to_cedar;
use crate::dsl;
use acp_core::types::Verdict;
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
}

impl PolicyEngine {
    /// Build an engine from YAML source: validate, compile to Cedar, load, and hash the source.
    pub fn from_yaml(src: &str) -> Result<PolicyEngine, String> {
        let policy = dsl::parse_str(src).map_err(|e| format!("invalid policy YAML: {e}"))?;
        dsl::validate(&policy)?;
        let cedar_src = compile_to_cedar(&policy);
        let pset =
            PolicySet::from_str(&cedar_src).map_err(|e| format!("cedar compile error: {e}"))?;
        let hash = acp_core::canonical::sha256_hex(&src.to_string());
        Ok(PolicyEngine {
            pset,
            hash,
            default: policy.default,
        })
    }

    /// Content hash over the YAML source; stamped into every evidence record.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn default_verdict(&self) -> Verdict {
        self.default
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

        chosen.unwrap_or(PolicyOutcome {
            verdict: self.default,
            rule_id: None,
            approvers: vec![],
            reason: None,
            obligations: vec![],
        })
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
    use crate::context::build_context_identified_full;
    use acp_core::impact::ImpactTaxonomy;
    use acp_core::resource::ResourceTaxonomy;

    fn ctx(tool: &str, agent: &str, principal: &str) -> serde_json::Value {
        build_context_identified_full(
            tool, &serde_json::json!({}), "prod", agent, "", principal,
            &ImpactTaxonomy::default(), &ResourceTaxonomy::default(),
        )
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
