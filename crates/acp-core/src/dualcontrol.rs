//! Four-eyes / dual-control for sensitive operations (decision H1.9).
//!
//! Some operations are too dangerous for one person: key rotation, PII export, a production policy
//! change. Dual-control requires two DISTINCT approvers, and the requester may not self-approve.
//! This is the authorisation gate; each grant is designed to be written to the meta-audit log so
//! the four-eyes decision is itself auditable.
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct DualControlRequest {
    pub id: String,
    pub operation: String,
    pub requester: String,
    approvers: BTreeSet<String>,
}

impl DualControlRequest {
    pub fn new(id: &str, operation: &str, requester: &str) -> Self {
        DualControlRequest {
            id: id.to_string(),
            operation: operation.to_string(),
            requester: requester.to_string(),
            approvers: BTreeSet::new(),
        }
    }

    /// Record an approval. The requester cannot approve their own request (self-approval is
    /// rejected), and a repeated approver does not count twice.
    pub fn approve(&mut self, approver: &str) -> Result<(), String> {
        if approver == self.requester {
            return Err("requester cannot self-approve (four-eyes)".into());
        }
        self.approvers.insert(approver.to_string());
        Ok(())
    }

    /// Authorised only once at least two distinct non-requester approvers have signed off.
    pub fn authorised(&self) -> bool {
        self.approvers.len() >= 2
    }

    pub fn approver_count(&self) -> usize {
        self.approvers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_approver_is_not_enough() {
        let mut r = DualControlRequest::new("k1", "key-rotation", "alice");
        r.approve("bob").unwrap();
        assert!(!r.authorised(), "one approver is insufficient");
    }

    #[test]
    fn two_distinct_approvers_authorise() {
        let mut r = DualControlRequest::new("k1", "key-rotation", "alice");
        r.approve("bob").unwrap();
        r.approve("carol").unwrap();
        assert!(r.authorised());
    }

    #[test]
    fn the_requester_cannot_self_approve() {
        let mut r = DualControlRequest::new("k1", "prod-policy-change", "alice");
        assert!(r.approve("alice").is_err());
        // And a duplicate approver does not fake a second signature.
        r.approve("bob").unwrap();
        r.approve("bob").unwrap();
        assert!(!r.authorised(), "same approver twice is still one approval");
    }
}
