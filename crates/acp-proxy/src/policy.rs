//! Policy enforcement for `tools/call` (M2.6, decisions D9).
//!
//! Context building and the safe-tool-name check live in `acp-policy` so the proxy and the CLI
//! (`acp policy-test`) derive context identically. This module maps the four-way verdict to an
//! MCP-framed proxy action.

use acp_core::types::Verdict;
use acp_jsonrpc::ToolCall;
use acp_policy::{build_context, valid_tool, PolicyEngine};
use serde_json::{json, Value};

/// What the proxy should do with a gated tool call.
pub enum Enforce {
    Forward,
    Reply(String),
}

fn deny_result(id: &Value, rule: &str, reason: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{"type": "text",
                "text": format!("blocked by policy rule '{rule}': {reason}")}]
        }
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

use acp_core::blast_radius;
use acp_policy::PolicyOutcome;

/// The full assessment of a tool call: the proxy action plus the fields needed to build an
/// evidence record (M3). `gated` is true for deny/step_up (which must fail closed on a write
/// failure, D5).
pub struct Assessment {
    pub enforce: Enforce,
    pub outcome: PolicyOutcome,
    pub impact: &'static str,
}

fn impact_str(tool: &str, args: &Value) -> &'static str {
    match blast_radius::score(tool, args) {
        acp_core::types::BlastRadius::Low => "low",
        acp_core::types::BlastRadius::Medium => "medium",
        acp_core::types::BlastRadius::High => "high",
    }
}

/// Evaluate a tool call and return both the enforcement action and the evidence fields.
pub fn assess(engine: &PolicyEngine, env: &str, tc: &ToolCall) -> Assessment {
    let impact = impact_str(&tc.name, &tc.arguments);
    if !valid_tool(&tc.name) {
        return Assessment {
            enforce: Enforce::Reply(deny_result(&tc.id, "safe-entity", "invalid tool name")),
            outcome: PolicyOutcome {
                verdict: Verdict::Deny,
                rule_id: Some("safe-entity".into()),
                approvers: vec![],
                reason: Some("invalid tool name".into()),
            },
            impact,
        };
    }
    let outcome = engine.evaluate(build_context(&tc.name, &tc.arguments, env));
    let enforce = match outcome.verdict {
        Verdict::Allow | Verdict::Shadow => Enforce::Forward,
        Verdict::Deny => Enforce::Reply(deny_result(
            &tc.id,
            outcome.rule_id.as_deref().unwrap_or("policy"),
            outcome.reason.as_deref().unwrap_or("blocked by policy"),
        )),
        Verdict::StepUp => Enforce::Reply(approval_required(
            &tc.id,
            outcome.rule_id.as_deref().unwrap_or("policy"),
        )),
    };
    Assessment {
        enforce,
        outcome,
        impact,
    }
}
