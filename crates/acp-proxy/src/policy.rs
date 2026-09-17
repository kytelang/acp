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

/// Evaluate and enforce a tool call.
pub fn enforce(engine: &PolicyEngine, env: &str, tc: &ToolCall) -> Enforce {
    if !valid_tool(&tc.name) {
        return Enforce::Reply(deny_result(&tc.id, "safe-entity", "invalid tool name"));
    }
    let out = engine.evaluate(build_context(&tc.name, &tc.arguments, env));
    match out.verdict {
        Verdict::Allow | Verdict::Shadow => Enforce::Forward,
        Verdict::Deny => Enforce::Reply(deny_result(
            &tc.id,
            out.rule_id.as_deref().unwrap_or("policy"),
            out.reason.as_deref().unwrap_or("blocked by policy"),
        )),
        Verdict::StepUp => Enforce::Reply(approval_required(
            &tc.id,
            out.rule_id.as_deref().unwrap_or("policy"),
        )),
    }
}
