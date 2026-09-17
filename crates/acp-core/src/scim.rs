//! SCIM 2.0 approver-group lifecycle (decision F8).
//!
//! Approval authority must track the IdP: when a user is deprovisioned there, their power to
//! approve a held call has to disappear within the sync window, and that change has to be
//! auditable. This models the SCIM side effects as pure state transitions over an approver
//! directory, so the enforcement path can ask "can this principal approve for this group" and get
//! a fail-closed answer. The wire handler (a SCIM REST endpoint) drives these transitions; the
//! logic here is what makes deprovisioning actually remove authority.

use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Default, Clone)]
struct User {
    active: bool,
    groups: BTreeSet<String>,
}

/// The approver directory synced from the IdP over SCIM.
#[derive(Debug, Default)]
pub struct ApproverDirectory {
    users: HashMap<String, User>,
}

/// A change the caller can log to the meta-audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Provisioned,
    Deprovisioned,
    GroupsUpdated,
    NoOp,
}

impl ApproverDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// SCIM create/replace: the user exists and is active with the given groups.
    pub fn provision(&mut self, user_id: &str, groups: &[String]) -> Change {
        let existed = self.users.get(user_id).map(|u| u.active).unwrap_or(false);
        let u = self.users.entry(user_id.to_string()).or_default();
        u.active = true;
        u.groups = groups.iter().cloned().collect();
        if existed {
            Change::GroupsUpdated
        } else {
            Change::Provisioned
        }
    }

    /// SCIM delete/deactivate: the user can no longer approve anything.
    pub fn deprovision(&mut self, user_id: &str) -> Change {
        match self.users.get_mut(user_id) {
            Some(u) if u.active => {
                u.active = false;
                u.groups.clear();
                Change::Deprovisioned
            }
            _ => Change::NoOp,
        }
    }

    /// The enforcement question: may this principal approve for this group? Fail-closed for an
    /// unknown or deactivated user.
    pub fn can_approve(&self, user_id: &str, group: &str) -> bool {
        match self.users.get(user_id) {
            Some(u) => u.active && u.groups.contains(group),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_grants_group_scoped_approval() {
        let mut d = ApproverDirectory::new();
        assert_eq!(
            d.provision("alice", &["payments".into(), "prod".into()]),
            Change::Provisioned
        );
        assert!(d.can_approve("alice", "payments"));
        assert!(!d.can_approve("alice", "hr"), "not in that group");
        assert!(
            !d.can_approve("bob", "payments"),
            "unknown user fails closed"
        );
    }

    #[test]
    fn deprovisioning_removes_approval_authority() {
        let mut d = ApproverDirectory::new();
        d.provision("alice", &["payments".into()]);
        assert!(d.can_approve("alice", "payments"));
        assert_eq!(d.deprovision("alice"), Change::Deprovisioned);
        assert!(
            !d.can_approve("alice", "payments"),
            "authority gone after deprovision"
        );
        assert_eq!(d.deprovision("alice"), Change::NoOp, "idempotent");
    }

    #[test]
    fn reprovisioning_updates_groups() {
        let mut d = ApproverDirectory::new();
        d.provision("alice", &["payments".into()]);
        assert_eq!(d.provision("alice", &["hr".into()]), Change::GroupsUpdated);
        assert!(!d.can_approve("alice", "payments"));
        assert!(d.can_approve("alice", "hr"));
    }
}
