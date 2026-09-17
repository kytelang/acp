//! Non-MCP adapter model (decision v2.1.1).
//!
//! ACP's value is the decision engine and the evidence log, not the MCP wire specifically. A raw
//! HTTP tool call or a function-calling framework should feed the SAME action context so the exact
//! same policy and evidence path apply. This maps a generic tool invocation into the fields the
//! decision engine consumes, so a new front-end is an adapter, not a fork of the core.

use serde_json::Value;

/// A tool invocation arriving from any surface (MCP, raw HTTP, a function-call framework).
#[derive(Debug, Clone)]
pub struct RawInvocation {
    /// A stable tool name in `namespace.verb` form (the adapter is responsible for normalising).
    pub tool: String,
    pub args: Value,
    /// The surface this came from, recorded for provenance (e.g. "mcp", "http", "openai-tools").
    pub source: String,
}

/// The engine-facing shape: exactly what the policy context builder needs. Deliberately identical
/// across surfaces, so the decision + evidence path does not branch on the front-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalisedCall {
    pub tool: String,
    pub args: Value,
    pub source: String,
}

/// Turn any surface's raw HTTP tool call into a normalised call. `method`+`path` map to a tool name
/// when the caller has not already supplied one (e.g. `POST /v1/payments/charge` -> `payments.charge`).
pub fn from_http(method: &str, path: &str, body: Value) -> NormalisedCall {
    let segs: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    // Drop a leading version segment like "v1".
    let start = if segs
        .first()
        .map(|s| s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false)
    {
        1
    } else {
        0
    };
    let tool = segs[start..].join(".");
    let tool = if tool.is_empty() {
        method.to_ascii_lowercase()
    } else {
        tool
    };
    NormalisedCall {
        tool,
        args: body,
        source: "http".to_string(),
    }
}

/// Normalise an already-structured invocation (MCP or a framework) with no path parsing.
pub fn from_invocation(inv: RawInvocation) -> NormalisedCall {
    NormalisedCall {
        tool: inv.tool,
        args: inv.args,
        source: inv.source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn http_and_mcp_produce_the_same_normalised_call() {
        let http = from_http("POST", "/v1/payments/charge", json!({"amount": 100}));
        let mcp = from_invocation(RawInvocation {
            tool: "payments.charge".into(),
            args: json!({"amount": 100}),
            source: "http".into(),
        });
        assert_eq!(
            http, mcp,
            "the decision engine sees an identical call from either surface"
        );
        assert_eq!(http.tool, "payments.charge");
    }

    #[test]
    fn version_prefix_is_stripped() {
        let c = from_http("DELETE", "/v2/files/report.csv", json!({}));
        assert_eq!(c.tool, "files.report.csv");
    }
}
