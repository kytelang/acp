//! The M1 interception decision for the client-to-server direction.
//!
//! M1 does not yet evaluate policy (that is M2). It enforces the transparency contract and the
//! D10 anti-bypass posture: known safe methods and `tools/call` pass through; an unknown
//! action-bearing *request* (one with an id) is denied by default, so protocol drift is not a
//! silent bypass. Notifications and responses are relayed.

use acp_jsonrpc::Inspected;

/// JSON-RPC error code used when the proxy blocks a call before forwarding.
pub const CODE_BLOCKED: i64 = -32001;

/// What the proxy should do with a client-to-server frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Forward the frame to the tool server unchanged.
    Forward,
    /// Do not forward; return a JSON-RPC error to the client with this code and message.
    Deny { code: i64, message: String },
}

/// Client-to-server methods that are known to be safe (read-only or protocol handshake) and
/// pass through in v0. `tools/call` is handled separately (recognised, gated from M2).
const SAFE_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "logging/setLevel",
    "completion/complete",
];

/// Decide what to do with a single client-to-server frame.
pub fn decide(insp: &Inspected) -> Action {
    // Not JSON, or a response/notification with no method: relay (never a failure point).
    let method = match &insp.method {
        Some(m) => m.as_str(),
        None => return Action::Forward,
    };
    // Recognised tool call: forward in M1; policy evaluation lands in M2.
    if insp.is_tool_call {
        return Action::Forward;
    }
    // Known-safe methods and all notifications pass through.
    if SAFE_METHODS.contains(&method) || method.starts_with("notifications/") {
        return Action::Forward;
    }
    // Unknown method. If it is a request (has an id) we can and do deny it (D10 default-deny of
    // unknown action-bearing methods). Unknown notifications (no id) are relayed.
    if insp.id.is_some() {
        Action::Deny {
            code: CODE_BLOCKED,
            message: format!(
                "method '{method}' is not permitted: unknown action-bearing methods are denied by default (D10)"
            ),
        }
    } else {
        Action::Forward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_jsonrpc::inspect;

    fn decide_raw(s: &str) -> Action {
        decide(&inspect(s.as_bytes()))
    }

    #[test]
    fn safe_and_toolcall_forward() {
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#),
            Action::Forward
        );
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#),
            Action::Forward
        );
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x"}}"#),
            Action::Forward
        );
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Action::Forward
        );
    }

    #[test]
    fn unknown_request_denied_notification_forwarded() {
        // unknown request (has id) -> deny
        match decide_raw(r#"{"jsonrpc":"2.0","id":9,"method":"danger/act"}"#) {
            Action::Deny { code, .. } => assert_eq!(code, CODE_BLOCKED),
            other => panic!("expected deny, got {other:?}"),
        }
        // unknown notification (no id) -> forward (cannot respond, low risk)
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","method":"weird/notify"}"#),
            Action::Forward
        );
        // a response (no method) -> forward
        assert_eq!(
            decide_raw(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Action::Forward
        );
        // not JSON -> forward (never a failure point)
        assert_eq!(decide_raw("not json"), Action::Forward);
    }
}
