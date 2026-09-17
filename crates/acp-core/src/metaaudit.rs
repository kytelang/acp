//! Self-governance meta-audit log (decision H0.7).
//!
//! ACP governs agents; something has to govern ACP. Every change to the control itself, the
//! policy, signing keys, RBAC, approver groups, break-glass, must land in a tamper-evident
//! record so an auditor can see who weakened the gate and when. These events are designed to be
//! appended to the same RFC 6962 Merkle ledger as decisions, so they inherit its tamper-evidence
//! (any edit or deletion breaks the signed tree head). This module defines the event shape and
//! its canonical bytes; the ledger append lives in `acp-ledger`.

use serde::{Deserialize, Serialize};

/// The kind of self-governance change being recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaKind {
    PolicyChange,
    KeyRotation,
    RbacChange,
    ApproverGroupChange,
    BreakGlassEngage,
    BreakGlassRevert,
}

/// One meta-audit event. `before`/`after` are content hashes or ids, never raw secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaEvent {
    pub kind: MetaKind,
    /// Who made the change (an authenticated principal id).
    pub actor: String,
    /// Mandatory human reason.
    pub reason: String,
    /// Prior state reference (e.g. old policy hash), if any.
    pub before: Option<String>,
    /// New state reference (e.g. new policy hash), if any.
    pub after: Option<String>,
    pub ts_ms: u64,
}

impl MetaEvent {
    pub fn new(kind: MetaKind, actor: &str, reason: &str, ts_ms: u64) -> Result<Self, String> {
        if reason.trim().is_empty() {
            return Err("meta-audit event requires a reason".into());
        }
        Ok(MetaEvent {
            kind,
            actor: actor.to_string(),
            reason: reason.to_string(),
            before: None,
            after: None,
            ts_ms,
        })
    }

    pub fn transition(mut self, before: Option<&str>, after: Option<&str>) -> Self {
        self.before = before.map(str::to_string);
        self.after = after.map(str::to_string);
        self
    }

    /// Stable JSON for this event, used as the ledger leaf payload. Field order is fixed by the
    /// struct definition and serde, so the same event always hashes to the same leaf.
    pub fn to_record(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": 1,
            "type": "meta",
            "kind": self.kind,
            "actor": self.actor,
            "reason": self.reason,
            "before": self.before,
            "after": self.after,
            "ts_ms": self.ts_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_mandatory() {
        assert!(MetaEvent::new(MetaKind::KeyRotation, "root", "", 1).is_err());
        assert!(MetaEvent::new(MetaKind::KeyRotation, "root", "quarterly", 1).is_ok());
    }

    #[test]
    fn a_policy_change_records_the_hash_transition() {
        let e = MetaEvent::new(MetaKind::PolicyChange, "alice", "tighten fs.write", 100)
            .unwrap()
            .transition(Some("hashA"), Some("hashB"));
        let r = e.to_record();
        assert_eq!(r["type"], "meta");
        assert_eq!(r["kind"], "policy_change");
        assert_eq!(r["before"], "hashA");
        assert_eq!(r["after"], "hashB");
    }

    #[test]
    fn the_record_is_deterministic() {
        let mk = || {
            MetaEvent::new(MetaKind::RbacChange, "bob", "add approver", 7)
                .unwrap()
                .transition(None, Some("group:payments"))
                .to_record()
                .to_string()
        };
        assert_eq!(mk(), mk(), "same event, same bytes");
    }
}
