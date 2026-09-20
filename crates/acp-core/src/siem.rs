//! SIEM export formatters (gap-closure, section 5: connector breadth).
//!
//! `otelspan.rs` builds an OTLP span; this adds the other line formats a SOC expects: ArcSight CEF,
//! OCSF JSON, and an RFC 5424 syslog line. Pure string/JSON builders over a small decision event, so
//! the CLI can render a ledger to any of them for forwarding. ACP owns the evidence; the SIEM owns
//! correlation and alerting.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The minimal shape of a governed decision, projected from a ledger record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub decision_id: String,
    pub ts_ms: u64,
    pub agent: String,
    pub principal: String,
    pub tool: String,
    pub resource: String,
    pub operation: String,
    pub verdict: String,
    pub rule_id: String,
    pub impact: String,
}

fn severity(impact: &str) -> u8 {
    match impact {
        "high" => 9,
        "medium" => 6,
        "low" => 3,
        _ => 5,
    }
}

fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|").replace('\n', " ")
}

fn cef_ext_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('=', "\\=").replace('\n', " ")
}

/// ArcSight Common Event Format line.
pub fn to_cef(e: &DecisionEvent) -> String {
    let name = format!("AI {} on {}", e.operation, e.resource);
    format!(
        "CEF:0|ACP|acp|1.0|{}|{}|{}|externalId={} rt={} act={} suser={} sproc={} cs1Label=tool cs1={} cs2Label=resource cs2={} cs3Label=rule cs3={}",
        cef_escape(&e.verdict),
        cef_escape(&name),
        severity(&e.impact),
        cef_ext_escape(&e.decision_id),
        e.ts_ms,
        cef_ext_escape(&e.verdict),
        cef_ext_escape(&e.principal),
        cef_ext_escape(&e.agent),
        cef_ext_escape(&e.tool),
        cef_ext_escape(&e.resource),
        cef_ext_escape(&e.rule_id),
    )
}

/// OCSF (Open Cybersecurity Schema Framework) event as JSON. Modelled as an API Activity event with
/// an allow/deny disposition, which is how a per-call authorization decision maps cleanly.
pub fn to_ocsf(e: &DecisionEvent) -> Value {
    // OCSF disposition ids: 1 = Allowed, 2 = Blocked (others mapped to Other=99).
    let (disp_id, disp) = match e.verdict.as_str() {
        "allow" | "shadow" => (1, "Allowed"),
        "deny" => (2, "Blocked"),
        "step_up" => (99, "Step-Up"),
        _ => (99, "Other"),
    };
    json!({
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "activity_id": 0,
        "time": e.ts_ms,
        "severity_id": match severity(&e.impact) { 9 => 4, 6 => 3, 3 => 2, _ => 1 },
        "disposition_id": disp_id,
        "disposition": disp,
        "metadata": {"product": {"vendor_name": "ACP", "name": "acp"}, "version": "1.4.0", "uid": e.decision_id},
        "actor": {"user": {"name": e.principal}, "process": {"name": e.agent}},
        "api": {"operation": e.operation, "service": {"name": e.resource}},
        "resources": [{"name": e.resource, "type": e.resource}],
        "unmapped": {"tool": e.tool, "rule_id": e.rule_id, "verdict": e.verdict, "impact": e.impact},
    })
}

/// RFC 5424 syslog line (structured data carries the decision fields).
pub fn to_syslog(e: &DecisionEvent) -> String {
    // PRI 134 = facility local0 (16) * 8 + severity info (6).
    let sd = format!(
        "[acp@0 verdict=\"{}\" agent=\"{}\" principal=\"{}\" tool=\"{}\" resource=\"{}\" operation=\"{}\" rule=\"{}\" impact=\"{}\"]",
        e.verdict, e.agent, e.principal, e.tool, e.resource, e.operation, e.rule_id, e.impact
    );
    format!(
        "<134>1 - - acp - {} {} governed decision {}",
        e.decision_id, sd, e.verdict
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> DecisionEvent {
        DecisionEvent {
            decision_id: "dec-1".into(),
            ts_ms: 1700000000000,
            agent: "coding-assistant".into(),
            principal: "alice".into(),
            tool: "db.delete_row".into(),
            resource: "database".into(),
            operation: "delete".into(),
            verdict: "deny".into(),
            rule_id: "no-db-delete".into(),
            impact: "high".into(),
        }
    }

    #[test]
    fn cef_has_prefix_and_fields() {
        let s = to_cef(&ev());
        assert!(s.starts_with("CEF:0|ACP|acp|1.0|deny|"));
        assert!(s.contains("cs1=db.delete_row"));
        assert!(s.contains("suser=alice"));
        assert!(s.contains("|9|"), "high impact -> severity 9");
    }

    #[test]
    fn ocsf_maps_deny_to_blocked() {
        let v = to_ocsf(&ev());
        assert_eq!(v["class_uid"], 6003);
        assert_eq!(v["disposition_id"], 2);
        assert_eq!(v["disposition"], "Blocked");
        assert_eq!(v["unmapped"]["tool"], "db.delete_row");
    }

    #[test]
    fn syslog_is_rfc5424_shaped_with_sd() {
        let s = to_syslog(&ev());
        assert!(s.starts_with("<134>1 "));
        assert!(s.contains("[acp@0 "));
        assert!(s.contains("verdict=\"deny\""));
    }

    #[test]
    fn cef_escapes_pipes_and_equals() {
        let mut e = ev();
        e.verdict = "de|ny".into();
        e.rule_id = "a=b".into();
        let s = to_cef(&e);
        assert!(s.contains("de\\|ny"));
        assert!(s.contains("cs3=a\\=b"));
    }
}
