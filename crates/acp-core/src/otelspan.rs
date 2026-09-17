//! OpenTelemetry governance spans (decision F9).
//!
//! A customer running OpenTelemetry should see ACP's decision as a linked span in their own
//! traces, with the trace context propagated, so they can correlate a gated call with the rest of
//! the request. The one hard rule: the span carries the decision metadata (tool, verdict, rule,
//! impact, ids) and never the argument payload. This builds the span as structured attributes and
//! is designed so there is no code path that places raw args into it.

use serde_json::{json, Value};

/// The propagated trace context plus the decision facts a span needs. No argument payload.
#[derive(Debug, Clone)]
pub struct SpanInput {
    pub trace_id: String,
    pub parent_span_id: String,
    pub span_id: String,
    pub decision_id: String,
    pub tool: String,
    pub verdict: String,
    pub rule_id: Option<String>,
    pub impact: String,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
}

/// Build an OTLP-style span. Attribute values are decision metadata only.
pub fn build_span(s: &SpanInput) -> Value {
    json!({
        "traceId": s.trace_id,
        "spanId": s.span_id,
        "parentSpanId": s.parent_span_id,
        "name": format!("acp.decision {}", s.tool),
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": s.start_unix_nano,
        "endTimeUnixNano": s.end_unix_nano,
        "attributes": [
            {"key": "acp.decision_id", "value": {"stringValue": s.decision_id}},
            {"key": "acp.tool", "value": {"stringValue": s.tool}},
            {"key": "acp.verdict", "value": {"stringValue": s.verdict}},
            {"key": "acp.rule_id", "value": {"stringValue": s.rule_id.clone().unwrap_or_default()}},
            {"key": "acp.impact", "value": {"stringValue": s.impact}}
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_links_the_trace_and_carries_the_decision() {
        let s = SpanInput {
            trace_id: "abc123".into(),
            parent_span_id: "parent1".into(),
            span_id: "span1".into(),
            decision_id: "run-7".into(),
            tool: "payments.charge".into(),
            verdict: "deny".into(),
            rule_id: Some("cap".into()),
            impact: "high".into(),
            start_unix_nano: 1,
            end_unix_nano: 2,
        };
        let span = build_span(&s);
        assert_eq!(span["traceId"], json!("abc123"));
        assert_eq!(span["parentSpanId"], json!("parent1"));
        assert_eq!(span["attributes"][2]["value"]["stringValue"], json!("deny"));
    }

    #[test]
    fn span_never_contains_argument_payload() {
        // Even though a real decision had these args, the span input has no field for them, so
        // there is no path to leak them. Assert the serialised span contains none of the secret.
        let s = SpanInput {
            trace_id: "t".into(),
            parent_span_id: "p".into(),
            span_id: "s".into(),
            decision_id: "d".into(),
            tool: "email.send".into(),
            verdict: "step_up".into(),
            rule_id: None,
            impact: "medium".into(),
            start_unix_nano: 0,
            end_unix_nano: 0,
        };
        let text = serde_json::to_string(&build_span(&s)).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("@"), "no email/args content in the span");
    }
}
