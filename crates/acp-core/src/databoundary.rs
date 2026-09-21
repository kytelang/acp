//! Data-boundary enforcement (destination-aware DLP).
//!
//! The content firewall decides whether text is safe regardless of where it is going; the data
//! boundary decides whether classified data may cross to a particular destination. Example: a secret
//! written to the local filesystem may be fine, but the same secret egressing to an external network
//! endpoint is exfiltration. Rules are keyed on (data class, destination resource) and the most
//! restrictive match wins. Pure and deterministic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BoundaryAction {
    Allow,
    Redact,
    Deny,
}

impl BoundaryAction {
    fn rank(self) -> u8 {
        match self {
            BoundaryAction::Deny => 2,
            BoundaryAction::Redact => 1,
            BoundaryAction::Allow => 0,
        }
    }
}

/// A rule: data of `from_class` (for example "secret" or "pii") going to `to_resource` (for example
/// "network") takes `action`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryRule {
    pub from_class: String,
    pub to_resource: String,
    pub action: BoundaryAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBoundaryPolicy {
    #[serde(default)]
    pub rules: Vec<BoundaryRule>,
    #[serde(default = "default_allow")]
    pub default: BoundaryAction,
}

fn default_allow() -> BoundaryAction {
    BoundaryAction::Allow
}

impl Default for DataBoundaryPolicy {
    fn default() -> Self {
        DataBoundaryPolicy { rules: Vec::new(), default: BoundaryAction::Allow }
    }
}

/// Evaluate the boundary for an action carrying `data_classes` going to `to_resource`. The most
/// restrictive matching rule wins (deny > redact > allow); no match falls to the default.
pub fn evaluate(policy: &DataBoundaryPolicy, data_classes: &[String], to_resource: &str) -> BoundaryAction {
    let mut chosen = policy.default;
    let mut matched = false;
    for r in &policy.rules {
        if r.to_resource == to_resource && data_classes.iter().any(|c| c == &r.from_class) {
            if !matched || r.action.rank() > chosen.rank() {
                chosen = r.action;
            }
            matched = true;
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DataBoundaryPolicy {
        DataBoundaryPolicy {
            rules: vec![
                BoundaryRule { from_class: "secret".into(), to_resource: "network".into(), action: BoundaryAction::Deny },
                BoundaryRule { from_class: "pii".into(), to_resource: "network".into(), action: BoundaryAction::Redact },
            ],
            default: BoundaryAction::Allow,
        }
    }

    #[test]
    fn secret_to_network_is_denied() {
        assert_eq!(evaluate(&policy(), &["secret".into()], "network"), BoundaryAction::Deny);
    }

    #[test]
    fn pii_to_network_is_redacted() {
        assert_eq!(evaluate(&policy(), &["pii".into()], "network"), BoundaryAction::Redact);
    }

    #[test]
    fn secret_to_filesystem_is_allowed_by_default() {
        assert_eq!(evaluate(&policy(), &["secret".into()], "filesystem"), BoundaryAction::Allow);
    }

    #[test]
    fn most_restrictive_wins() {
        // Both secret (deny) and pii (redact) present, going to network -> deny.
        assert_eq!(evaluate(&policy(), &["pii".into(), "secret".into()], "network"), BoundaryAction::Deny);
    }
}
