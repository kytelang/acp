//! Policy enforcement for `tools/call` (M2.6, decisions D9).
//!
//! Context building and the safe-tool-name check live in `acp-policy` so the proxy and the CLI
//! (`acp policy-test`) derive context identically. This module maps the four-way verdict to an
//! MCP-framed proxy action.

use acp_core::types::Verdict;
use acp_jsonrpc::ToolCall;
use acp_policy::{valid_tool, PolicyEngine};
use serde_json::{json, Value};

/// What the proxy should do with a gated tool call.
pub enum Enforce {
    Forward,
    Reply(String),
}

fn deny_result(id: &Value, rule: &str, reason: &str, impact: &str) -> String {
    // Explainable denial (E3): what fired, why, the impact, and how to proceed.
    let text = format!(
        "blocked by policy rule '{rule}': {reason} (impact={impact}). To proceed, adjust the flagged argument(s) or request human approval."
    );
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"isError": true, "content": [{"type": "text", "text": text}],
                   "structuredContent": {"blocked": true, "rule": rule, "reason": reason, "impact": impact}}
    })
    .to_string()
}

fn approval_required(id: &Value, rule: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32001,
            "message": format!("approval required (step-up) by rule '{rule}'; re-issue after approval")}
    })
    .to_string()
}

use acp_core::impact::ImpactTaxonomy;
use acp_policy::{build_context_with, PolicyOutcome};

/// The full assessment of a tool call: the proxy action plus the fields needed to build an
/// evidence record (M3). `gated` is true for deny/step_up (which must fail closed on a write
/// failure, D5).
pub struct Assessment {
    pub enforce: Enforce,
    pub outcome: PolicyOutcome,
    pub impact: &'static str,
    pub impact_taxonomy: String,
}

fn impact_str(tax: &ImpactTaxonomy, tool: &str, args: &Value) -> &'static str {
    match tax.score(tool, args) {
        acp_core::types::BlastRadius::Low => "low",
        acp_core::types::BlastRadius::Medium => "medium",
        acp_core::types::BlastRadius::High => "high",
    }
}

/// Evaluate a tool call and return both the enforcement action and the evidence fields.
pub fn assess(engine: &PolicyEngine, env: &str, tc: &ToolCall, tax: &ImpactTaxonomy) -> Assessment {
    let impact = impact_str(tax, &tc.name, &tc.arguments);
    if !valid_tool(&tc.name) {
        return Assessment {
            enforce: Enforce::Reply(deny_result(
                &tc.id,
                "safe-entity",
                "invalid tool name",
                impact,
            )),
            outcome: PolicyOutcome {
                verdict: Verdict::Deny,
                rule_id: Some("safe-entity".into()),
                approvers: vec![],
                reason: Some("invalid tool name".into()),
            },
            impact,
            impact_taxonomy: tax.version.clone(),
        };
    }
    let outcome = engine.evaluate(build_context_with(&tc.name, &tc.arguments, env, tax));
    let enforce = enforce_for(outcome.verdict, tc, &outcome, impact);
    Assessment {
        enforce,
        outcome,
        impact,
        impact_taxonomy: tax.version.clone(),
    }
}

/// Map a (possibly overridden) verdict to the proxy action. Exposed so a runtime override such as
/// break-glass can re-derive the enforcement action after changing the verdict, using the exact
/// same replies as the normal path.
pub fn enforce_for(
    verdict: Verdict,
    tc: &ToolCall,
    outcome: &PolicyOutcome,
    impact: &str,
) -> Enforce {
    match verdict {
        Verdict::Allow | Verdict::Shadow => Enforce::Forward,
        Verdict::Deny => Enforce::Reply(deny_result(
            &tc.id,
            outcome.rule_id.as_deref().unwrap_or("policy"),
            outcome.reason.as_deref().unwrap_or("blocked by policy"),
            impact,
        )),
        Verdict::StepUp => Enforce::Reply(approval_required(
            &tc.id,
            outcome.rule_id.as_deref().unwrap_or("policy"),
        )),
    }
}
