//! Step-up approval flow at the proxy (decision D8).
//!
//! A step-up call attempts to consume an approval keyed by
//! `hash(session, principal, tool, arg_hash)`. The first attempt has no approval, so one is
//! opened and the agent gets `-32001 approval required`; it re-issues the identical call, and once
//! a human has approved, the same key consumes exactly once and the call is forwarded. Because the
//! key includes the canonical `arg_hash`, a re-issue whose arguments differ maps to a different
//! key and cannot ride the approval (canonical binding).

use acp_approvals::{ApprovalStore, ApprovalView};
use acp_core::canonical::sha256_hex;
use acp_jsonrpc::ToolCall;
use serde_json::{json, Value};

/// Default approval time-to-live (15 minutes).
pub const TTL_MS: u64 = 15 * 60 * 1000;

pub enum Step {
    /// Approved and consumed: forward the call. Carries the approval view for evidence.
    Forward(Box<ApprovalView>),
    /// Held: `-32001 approval required` (first issue or still pending). Not terminal.
    Held(String),
    /// Terminal block (denied / expired / already used): a structured isError.
    Denied(String),
}

fn approval_id(session: &str, principal: &str, tool: &str, arg_hash: &str) -> String {
    sha256_hex(&json!({"s": session, "p": principal, "t": tool, "a": arg_hash}))
}

fn held(id: &Value, approval_id: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": id,
        "error": {"code": -32001, "message": "approval required (step-up); re-issue after approval",
                  "data": {"approvalId": approval_id, "retryAfter": 5}}
    })
    .to_string()
}

fn denied(id: &Value, reason: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": id,
        "result": {"isError": true, "content": [{"type": "text", "text": format!("blocked (step-up): {reason}")}]}
    })
    .to_string()
}

/// Run the step-up flow for one tool call.
pub fn handle(
    store: &ApprovalStore,
    session: &str,
    principal: &str,
    tc: &ToolCall,
    impact: &str,
) -> Step {
    let arg_hash = sha256_hex(&tc.arguments);
    let id = approval_id(session, principal, &tc.name, &arg_hash);

    match store.consume(&id, session, principal, &arg_hash) {
        Ok(view) => Step::Forward(Box::new(view)),
        Err(reason) if reason == "approval pending" => Step::Held(held(&tc.id, &id)),
        Err(reason) if reason == "no such approval" => {
            // First issue: open the approval with the presented context the approver will see.
            let presented = json!({"tool": tc.name, "impact": impact, "arg_hash": arg_hash});
            let _ = store.request(
                &id, session, principal, &tc.name, &arg_hash, &presented, TTL_MS,
            );
            Step::Held(held(&tc.id, &id))
        }
        Err(reason) => Step::Denied(denied(&tc.id, &reason)),
    }
}
