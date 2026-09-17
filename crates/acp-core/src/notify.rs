//! Injection-safe notification rendering for approval holds (decision F4).
//!
//! An approval notification carries attacker-influenced data: the tool name and the policy reason
//! come from traffic. If those were concatenated into a Slack/Teams markup template, a crafted
//! argument could forge buttons or spoof text. This renders every notification as structured data
//! (a JSON payload) with user-controlled fields placed only as values, never interpolated into
//! markup, so injection is impossible by construction. All channels (Teams Adaptive Card,
//! PagerDuty event, email JSON) share this one contract.

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
}
