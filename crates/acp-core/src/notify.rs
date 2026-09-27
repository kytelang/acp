//! Injection-safe notification rendering for approval holds (decision F4).
//!
//! An approval notification carries attacker-influenced data: the tool name and the policy reason
//! come from traffic. If those were concatenated into a Slack/Teams markup template, a crafted
//! argument could forge buttons or spoof text. This renders every notification as structured data
//! (a JSON payload) with user-controlled fields placed only as values, never interpolated into
//! markup, so injection is impossible by construction. All channels (Teams Adaptive Card,
//! PagerDuty event, Slack Block Kit, email JSON) share this one contract.

use serde_json::{json, Value};

/// The facts a hold notification needs. All fields may contain hostile content and are treated as
/// opaque data.
#[derive(Debug, Clone)]
pub struct HoldNotice {
    pub approval_id: String,
    pub tool: String,
    pub reason: String,
    pub impact: String,
    pub requested_by: String,
}

/// Render a Teams-style Adaptive Card. User fields are values in the JSON tree, so no field can
/// introduce new structure or markup.
pub fn render_teams_card(n: &HoldNotice) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": "Approval required", "weight": "Bolder"},
                    {"type": "FactSet", "facts": [
                        {"title": "Tool", "value": n.tool},
                        {"title": "Impact", "value": n.impact},
                        {"title": "Reason", "value": n.reason},
                        {"title": "Requested by", "value": n.requested_by}
                    ]}
                ],
                "actions": [
                    {"type": "Action.Submit", "title": "Approve", "data": {"approval_id": n.approval_id, "decision": "approve"}},
                    {"type": "Action.Submit", "title": "Deny", "data": {"approval_id": n.approval_id, "decision": "deny"}}
                ]
            }
        }]
    })
}

/// Render a PagerDuty Events API v2 trigger payload for an ageing step-up.
pub fn render_pagerduty(routing_key: &str, n: &HoldNotice) -> Value {
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": n.approval_id,
        "payload": {
            "summary": format!("ACP approval hold: {} ({})", n.tool, n.impact),
            "source": "acp",
            "severity": "warning",
            "custom_details": {"tool": n.tool, "reason": n.reason, "requested_by": n.requested_by}
        }
    })
}

/// Render a Slack message (Block Kit) for an approval hold. User fields are placed only as text
/// values inside `section` fields, never interpolated into `mrkdwn` control syntax, so a hostile
/// tool name or reason cannot forge blocks or actions.
pub fn render_slack_message(n: &HoldNotice) -> Value {
    json!({
        "text": "ACP approval required",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "Approval required"}},
            {"type": "section", "fields": [
                {"type": "plain_text", "text": format!("Tool: {}", n.tool)},
                {"type": "plain_text", "text": format!("Impact: {}", n.impact)},
                {"type": "plain_text", "text": format!("Reason: {}", n.reason)},
                {"type": "plain_text", "text": format!("Requested by: {}", n.requested_by)}
            ]},
            {"type": "context", "elements": [
                {"type": "plain_text", "text": format!("approval_id: {}", n.approval_id)}
            ]}
        ]
    })
}

/// Render a Slack message for a generic control-plane event (the same `{type, event}` shape the
/// webhook sink receives). Every event field becomes a plain_text value, so no field can introduce
/// Slack markup or block structure. `fields` is the event object; non-string values are stringified.
pub fn render_slack_event(event_type: &str, fields: &Value) -> Value {
    let mut section_fields: Vec<Value> = Vec::new();
    if let Some(obj) = fields.as_object() {
        for (k, v) in obj {
            let val = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            section_fields.push(json!({"type": "plain_text", "text": format!("{k}: {val}")}));
        }
    }
    // Slack caps a section at 10 fields; keep the first 10 and note the rest in context.
    let overflow = section_fields.len().saturating_sub(10);
    section_fields.truncate(10);
    let mut blocks = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": format!("ACP: {event_type}")}}),
    ];
    if !section_fields.is_empty() {
        blocks.push(json!({"type": "section", "fields": section_fields}));
    }
    if overflow > 0 {
        blocks.push(json!({"type": "context", "elements": [
            {"type": "plain_text", "text": format!("(+{overflow} more field(s) omitted)")}
        ]}));
    }
    json!({"text": format!("ACP {event_type}"), "blocks": blocks})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hostile() -> HoldNotice {
        HoldNotice {
            approval_id: "ap-1".into(),
            // An attacker tries to break out of any naive template.
            tool: r#"fs.delete","injected":"x"#.into(),
            reason: "```\n<script>alert(1)</script> {{7*7}}".into(),
            impact: "high".into(),
            requested_by: "agent-9".into(),
        }
    }

    #[test]
    fn hostile_fields_stay_data_and_cannot_forge_structure() {
        let card = render_teams_card(&hostile());
        // The hostile tool string is a single JSON value, not a new key.
        let facts = &card["attachments"][0]["content"]["body"][1]["facts"];
        assert_eq!(facts[0]["value"], json!(r#"fs.delete","injected":"x"#));
        // No "injected" key leaked into the object anywhere: round-trip and check.
        let s = serde_json::to_string(&card).unwrap();
        let reparsed: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(reparsed, card, "payload round-trips as pure data");
        // The action still carries the real approval id, not an attacker-chosen one.
        assert_eq!(
            card["attachments"][0]["content"]["actions"][0]["data"]["approval_id"],
            json!("ap-1")
        );
    }

    #[test]
    fn pagerduty_dedup_key_is_the_approval_id() {
        let p = render_pagerduty("routing-123", &hostile());
        assert_eq!(p["dedup_key"], json!("ap-1"));
        assert_eq!(p["event_action"], json!("trigger"));
        assert_eq!(
            p["payload"]["custom_details"]["reason"],
            json!("```\n<script>alert(1)</script> {{7*7}}")
        );
    }

    #[test]
    fn slack_message_keeps_hostile_fields_as_values() {
        let m = render_slack_message(&hostile());
        let s = serde_json::to_string(&m).unwrap();
        let re: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(re, m, "slack payload round-trips as pure data");
        assert_eq!(m["blocks"][2]["elements"][0]["text"], json!("approval_id: ap-1"));
    }

    #[test]
    fn slack_event_stringifies_fields_and_caps_ten() {
        let ev = json!({"a":"1","b":2,"c":"3","d":4,"e":"5","f":6,"g":"7","h":8,"i":"9","j":10,"k":"11","l":12});
        let m = render_slack_event("grc.created", &ev);
        // header present
        assert_eq!(m["blocks"][0]["text"]["text"], json!("ACP: grc.created"));
        // section capped at 10 fields
        assert_eq!(m["blocks"][1]["fields"].as_array().unwrap().len(), 10);
        // overflow context noted
        assert!(m["blocks"][2]["elements"][0]["text"].as_str().unwrap().contains("more field"));
    }
}
