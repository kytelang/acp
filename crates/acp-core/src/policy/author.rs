//! Plain-English policy authoring with verification (gap G3).
//!
//! A compliance user describes a rule in English; a drafter proposes the model-v2 DSL; and, crucially,
//! the Cedar engine plus generated test cases show exactly what the draft allows and blocks before it
//! goes live. The verification is the guarantee: even if an LLM writes the rule, the operator sees the
//! concrete allow/deny matrix and must confirm it. This module provides a deterministic best-effort
//! drafter for common phrasings (an external LLM can replace it behind the same seam) and the
//! verification matrix, which is the part that must never be skipped.

use crate::policy::eval::PolicyEngine;
use crate::policy::context::build_context_identified_full;
use crate::impact::ImpactTaxonomy;
use crate::resource::ResourceTaxonomy;
use crate::types::Verdict;
use serde::Serialize;

/// A best-effort draft of a single rule from an English description. Recognises a few compliance
/// phrasings (deny/allow an operation on a resource, optionally for unattributed callers). Returns a
/// compilable model-v2 DSL document, or None if nothing was recognised (then route to an LLM drafter).
pub fn draft_from_text(text: &str) -> Option<String> {
    let t = text.to_ascii_lowercase();
    let verdict = if t.contains("deny") || t.contains("must not") || t.contains("may not") || t.contains("no agent") || t.contains("block") {
        "deny"
    } else if t.contains("require approval") || t.contains("step up") || t.contains("step-up") {
        "step_up"
    } else if t.contains("allow") || t.contains("permit") {
        "allow"
    } else {
        return None;
    };
    // Resource keywords -> resource class.
    let resource = ["database", "filesystem", "secrets", "network", "payments", "model"]
        .iter().find(|r| t.contains(**r)).map(|r| r.to_string());
    // Operation keywords -> operation.
    let operation = [("delete", "delete"), ("write", "write"), ("read", "read"), ("send", "write"), ("export", "read")]
        .iter().find(|(kw, _)| t.contains(kw)).map(|(_, op)| op.to_string());
    let unattributed = t.contains("unattributed") || t.contains("without a verified") || t.contains("anonymous");
    if resource.is_none() && operation.is_none() && !unattributed {
        return None;
    }
    let mut when = Vec::new();
    if let Some(r) = &resource { when.push(format!("resource: {r}")); }
    if let Some(o) = &operation { when.push(format!("operation: {o}")); }
    if unattributed { when.push("principal: unattributed".to_string()); }
    Some(format!(
        "version: 1\ndefault: allow\nrules:\n  - id: authored-1\n    when: {{ {} }}\n    verdict: {verdict}\n",
        when.join(", ")
    ))
}

/// A test request for the verification matrix.
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub tool: String,
    pub principal: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MatrixRow {
    pub tool: String,
    pub principal: String,
    pub verdict: String,
}

fn verdict_str(v: Verdict) -> &'static str {
    match v { Verdict::Allow => "allow", Verdict::Deny => "deny", Verdict::StepUp => "step_up", Verdict::Shadow => "shadow" }
}

/// Verify a candidate DSL by evaluating each test request through the real engine, returning the
/// allow/deny matrix. Returns Err with the compile error if the draft does not compile (so a bad draft
/// is reported, never deployed).
pub fn verify_matrix(dsl: &str, requests: &[TestRequest]) -> Result<Vec<MatrixRow>, String> {
    let engine = PolicyEngine::from_yaml(dsl)?;
    let tax = ImpactTaxonomy::default();
    let rtax = ResourceTaxonomy::default();
    Ok(requests.iter().map(|r| {
        let ctx = build_context_identified_full(&r.tool, &serde_json::json!({}), "prod", "agent", "", &r.principal, &[], &tax, &rtax);
        MatrixRow { tool: r.tool.clone(), principal: r.principal.clone(), verdict: verdict_str(engine.evaluate(ctx).verdict).to_string() }
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drafts_a_deny_rule_from_english() {
        let dsl = draft_from_text("No agent may delete from the database").unwrap();
        assert!(dsl.contains("resource: database"));
        assert!(dsl.contains("operation: delete"));
        assert!(dsl.contains("verdict: deny"));
        // and it compiles + verifies
        let m = verify_matrix(&dsl, &[
            TestRequest { tool: "db.delete_row".into(), principal: "alice".into() },
            TestRequest { tool: "db.query".into(), principal: "alice".into() },
        ]).unwrap();
        assert_eq!(m[0].verdict, "deny", "delete on database denied");
        assert_eq!(m[1].verdict, "allow", "read on database allowed (default)");
    }

    #[test]
    fn unrecognised_text_returns_none_for_llm_fallback() {
        assert!(draft_from_text("please make the agent behave nicely").is_none());
    }

    #[test]
    fn a_non_compiling_draft_is_reported_not_deployed() {
        assert!(verify_matrix("version: 1\nrules:\n  - bogus\n", &[]).is_err());
    }
}
