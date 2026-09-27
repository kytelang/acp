//! Ticketing / ITSM materialisation of a hold (decision F5).
//!
//! When a call is held for approval, some customers want it to appear as a Jira/ServiceNow ticket
//! that an approver resolves in their existing queue. The ticket must carry redacted details only,
//! and resolving it must consume the single-use approval exactly once, so the ticket id becomes
//! part of the presented-context evidence. This models the ticket lifecycle as a strict state
//! machine so a double-resolve or a resolve-after-consume cannot execute the call twice.

/// The lifecycle of a hold ticket. Transitions are one-way; a consumed ticket is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketState {
    Open,
    Approved,
    Denied,
    Consumed,
}

#[derive(Debug, Clone)]
pub struct Ticket {
    pub id: String,
    pub approval_id: String,
    pub summary: String,
    pub state: TicketState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    NotApproved,
    AlreadyResolved,
    AlreadyConsumed,
}

impl Ticket {
    /// Materialise a hold as an open ticket. `summary` must already be redacted by the caller.
    pub fn open(id: &str, approval_id: &str, summary: &str) -> Self {
        Ticket {
            id: id.to_string(),
            approval_id: approval_id.to_string(),
            summary: summary.to_string(),
            state: TicketState::Open,
        }
    }

    pub fn approve(&mut self) -> Result<(), TicketError> {
        match self.state {
            TicketState::Open => {
                self.state = TicketState::Approved;
                Ok(())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::AlreadyResolved),
        }
    }

    pub fn deny(&mut self) -> Result<(), TicketError> {
        match self.state {
            TicketState::Open => {
                self.state = TicketState::Denied;
                Ok(())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::AlreadyResolved),
        }
    }

    /// Consume the single-use approval that this ticket represents. Only an approved, not-yet-
    /// consumed ticket can be consumed, and only once: the second attempt fails closed.
    pub fn consume(&mut self) -> Result<String, TicketError> {
        match self.state {
            TicketState::Approved => {
                self.state = TicketState::Consumed;
                Ok(self.approval_id.clone())
            }
            TicketState::Consumed => Err(TicketError::AlreadyConsumed),
            _ => Err(TicketError::NotApproved),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approved_ticket_consumes_its_approval_exactly_once() {
        let mut t = Ticket::open("JIRA-1", "ap-9", "held: payments.charge (high)");
        t.approve().unwrap();
        assert_eq!(
            t.consume().unwrap(),
            "ap-9",
            "consuming yields the approval id"
        );
        assert_eq!(
            t.consume(),
            Err(TicketError::AlreadyConsumed),
            "no double execution"
        );
    }

    #[test]
    fn an_unapproved_ticket_cannot_be_consumed() {
        let mut t = Ticket::open("SN-1", "ap-1", "held");
        assert_eq!(t.consume(), Err(TicketError::NotApproved));
    }

    #[test]
    fn a_resolved_ticket_cannot_be_resolved_again() {
        let mut t = Ticket::open("SN-2", "ap-2", "held");
        t.deny().unwrap();
        assert_eq!(t.approve(), Err(TicketError::AlreadyResolved));
    }
}

/// Jira connector (named adapter over the generic ticket-resolution rail).
///
/// ACP does not embed a Jira client; it exchanges two small, pure JSON mappings with Jira:
/// - outbound: `render_jira_issue` builds a create-issue REST body, tagging the issue with a label
///   that carries the ACP object id so the round-trip is unambiguous.
/// - inbound: `map_jira_webhook` reads a Jira `issue_updated` webhook and, from the ACP label plus
///   the new status, produces the same `{action, id, status}` the generic `/tickets/callback` rail
///   already applies. Intermediate transitions (no terminal status) map to nothing.
///
/// The label convention is `acp-approval:<id>` for a step-up hold and `acp-grc:<id>` for a GRC
/// record. Unknown labels map to nothing (fail-closed): a stray Jira issue cannot resolve anything.
pub mod jira {
    use serde_json::{json, Value};

    /// A resolution decoded from a Jira webhook, in the generic ticket-rail vocabulary.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct JiraResolution {
        /// "approve" | "deny" | "grc-status".
        pub action: String,
        /// The ACP object id (an approval id or a GRC record id).
        pub id: String,
        /// The GRC status to set (only for action "grc-status").
        pub status: Option<String>,
    }

    /// Build a Jira create-issue REST body for an ACP object. `acp_label` is the full label, for
    /// example "acp-approval:ap-123". Summary and description are placed only as values.
    pub fn render_jira_issue(project_key: &str, summary: &str, description: &str, acp_label: &str) -> Value {
        json!({
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": "Task"},
                "labels": [acp_label]
            }
        })
    }

    /// Classify a Jira status name into a terminal decision: Some(true) = approved/done,
    /// Some(false) = rejected/declined, None = an intermediate transition to ignore.
    fn decision_of(status: &str) -> Option<bool> {
        let s = status.to_ascii_lowercase();
        if s.contains("done") || s.contains("approve") || s.contains("resolved") || s.contains("accept") || s.contains("complete") {
            Some(true)
        } else if s.contains("reject") || s.contains("declin") || s.contains("deny") || s.contains("won't") || s.contains("wont") {
            Some(false)
        } else {
            None
        }
    }

    /// Extract the (kind, id) from the ACP label on the issue. kind is "approval" or "grc".
    fn acp_ref(labels: &[&str]) -> Option<(&'static str, String)> {
        for l in labels {
            if let Some(id) = l.strip_prefix("acp-approval:") {
                if !id.is_empty() { return Some(("approval", id.to_string())); }
            }
            if let Some(id) = l.strip_prefix("acp-grc:") {
                if !id.is_empty() { return Some(("grc", id.to_string())); }
            }
        }
        None
    }

    /// Map a Jira `issue_updated` webhook to an ACP ticket resolution, or None when it does not
    /// concern ACP or is not a terminal transition.
    pub fn map_jira_webhook(payload: &Value) -> Option<JiraResolution> {
        let fields = payload.get("issue").and_then(|i| i.get("fields"))?;
        let labels: Vec<&str> = fields
            .get("labels")
            .and_then(|l| l.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let (kind, id) = acp_ref(&labels)?;
        let status = fields.get("status").and_then(|s| s.get("name")).and_then(|n| n.as_str())?;
        let approved = decision_of(status)?;
        Some(match kind {
            "approval" => JiraResolution {
                action: if approved { "approve".into() } else { "deny".into() },
                id,
                status: None,
            },
            _ => JiraResolution {
                action: "grc-status".into(),
                id,
                status: Some(if approved { "approved".into() } else { "rejected".into() }),
            },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn webhook(labels: Value, status: &str) -> Value {
            json!({"webhookEvent": "jira:issue_updated",
                   "issue": {"key": "OPS-7", "fields": {"labels": labels, "status": {"name": status}}}})
        }

        #[test]
        fn approval_done_maps_to_approve() {
            let r = map_jira_webhook(&webhook(json!(["acp-approval:ap-9"]), "Done")).unwrap();
            assert_eq!(r, JiraResolution { action: "approve".into(), id: "ap-9".into(), status: None });
        }

        #[test]
        fn approval_rejected_maps_to_deny() {
            let r = map_jira_webhook(&webhook(json!(["acp-approval:ap-9"]), "Rejected")).unwrap();
            assert_eq!(r.action, "deny");
        }

        #[test]
        fn grc_done_maps_to_grc_status_approved() {
            let r = map_jira_webhook(&webhook(json!(["acp-grc:grc-3"]), "Approved")).unwrap();
            assert_eq!(r, JiraResolution { action: "grc-status".into(), id: "grc-3".into(), status: Some("approved".into()) });
        }

        #[test]
        fn intermediate_transition_maps_to_nothing() {
            assert!(map_jira_webhook(&webhook(json!(["acp-approval:ap-9"]), "In Progress")).is_none());
        }

        #[test]
        fn non_acp_issue_maps_to_nothing() {
            assert!(map_jira_webhook(&webhook(json!(["backend", "urgent"]), "Done")).is_none());
        }

        #[test]
        fn render_issue_carries_the_acp_label() {
            let v = render_jira_issue("OPS", "hold: fs.delete", "redacted", "acp-approval:ap-1");
            assert_eq!(v["fields"]["labels"][0], json!("acp-approval:ap-1"));
            assert_eq!(v["fields"]["project"]["key"], json!("OPS"));
        }
    }
}
