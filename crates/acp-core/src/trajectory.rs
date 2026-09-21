//! Intent / trajectory governance.
//!
//! Per-call authorisation cannot see a "toxic combination" of individually-allowed actions (read a
//! secret, then egress to the network = exfiltration) or a runaway burst of high-impact actions
//! (goal drift). This governs the SEQUENCE: it keeps a per-session trajectory and denies the action
//! that completes a forbidden combination or exceeds a velocity budget. Pure and deterministic; the
//! caller feeds it each action and applies the verdict.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// One action in a session's trajectory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEvent {
    pub resource: String,
    pub operation: String,
    /// "low" | "medium" | "high".
    pub impact: String,
    pub ts_ms: u64,
}

/// A forbidden combination: if all of `require` occur within `within_ms`, the completing action is
/// denied even though each was individually allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToxicCombo {
    pub id: String,
    /// (resource, operation) pairs that together are dangerous.
    pub require: Vec<(String, String)>,
    pub within_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryPolicy {
    #[serde(default)]
    pub combos: Vec<ToxicCombo>,
    /// Max high-impact actions allowed within `window_ms` (0 = unlimited).
    #[serde(default)]
    pub max_high_impact: usize,
    #[serde(default)]
    pub window_ms: u64,
}

impl Default for TrajectoryPolicy {
    fn default() -> Self {
        TrajectoryPolicy { combos: Vec::new(), max_high_impact: 0, window_ms: 60_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrajectoryVerdict {
    Allow,
    Deny(String),
}

impl TrajectoryVerdict {
    pub fn allowed(&self) -> bool {
        matches!(self, TrajectoryVerdict::Allow)
    }
}

/// Per-session trajectory monitor. Keeps a bounded recent history and evaluates the policy.
pub struct TrajectoryMonitor {
    policy: TrajectoryPolicy,
    history: VecDeque<ActionEvent>,
    cap: usize,
}

impl TrajectoryMonitor {
    pub fn new(policy: TrajectoryPolicy) -> Self {
        TrajectoryMonitor { policy, history: VecDeque::new(), cap: 1024 }
    }

    /// Record an action and return whether it is allowed given the session so far. A denied action
    /// is still recorded (so the sequence is complete for evidence), but the caller must block it.
    pub fn record_and_check(&mut self, ev: ActionEvent) -> TrajectoryVerdict {
        let now = ev.ts_ms;
        self.history.push_back(ev.clone());
        while self.history.len() > self.cap {
            self.history.pop_front();
        }

        // Velocity: too many high-impact actions in the window.
        if self.policy.max_high_impact > 0 {
            let win = self.policy.window_ms;
            let highs = self
                .history
                .iter()
                .filter(|e| e.impact == "high" && now.saturating_sub(e.ts_ms) <= win)
                .count();
            if highs > self.policy.max_high_impact {
                return TrajectoryVerdict::Deny(format!(
                    "velocity: {highs} high-impact actions within {win}ms exceeds {}",
                    self.policy.max_high_impact
                ));
            }
        }

        // Toxic combinations: the current action completes a forbidden set within its window.
        for combo in &self.policy.combos {
            // The current action must be one of the required pairs (it "completes" the combo).
            let current_in = combo.require.iter().any(|(r, o)| r == &ev.resource && o == &ev.operation);
            if !current_in {
                continue;
            }
            let all_present = combo.require.iter().all(|(r, o)| {
                self.history
                    .iter()
                    .any(|e| &e.resource == r && &e.operation == o && now.saturating_sub(e.ts_ms) <= combo.within_ms)
            });
            if all_present {
                return TrajectoryVerdict::Deny(format!(
                    "toxic combination '{}' completed within {}ms",
                    combo.id, combo.within_ms
                ));
            }
        }
        TrajectoryVerdict::Allow
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(res: &str, op: &str, impact: &str, ts: u64) -> ActionEvent {
        ActionEvent { resource: res.into(), operation: op.into(), impact: impact.into(), ts_ms: ts }
    }

    fn exfil_policy() -> TrajectoryPolicy {
        TrajectoryPolicy {
            combos: vec![ToxicCombo {
                id: "read-secret-then-egress".into(),
                require: vec![("secrets".into(), "read".into()), ("network".into(), "egress".into())],
                within_ms: 60_000,
            }],
            max_high_impact: 0,
            window_ms: 60_000,
        }
    }

    #[test]
    fn toxic_combination_denies_the_completing_action() {
        let mut m = TrajectoryMonitor::new(exfil_policy());
        assert!(m.record_and_check(ev("secrets", "read", "medium", 1000)).allowed(), "reading a secret alone is allowed");
        let v = m.record_and_check(ev("network", "egress", "medium", 2000));
        assert!(!v.allowed(), "egress after reading a secret completes the exfil combo");
    }

    #[test]
    fn combo_outside_window_is_allowed() {
        let mut m = TrajectoryMonitor::new(exfil_policy());
        m.record_and_check(ev("secrets", "read", "medium", 1000));
        // egress 2 minutes later: the read is outside the 60s window.
        assert!(m.record_and_check(ev("network", "egress", "medium", 130_000)).allowed());
    }

    #[test]
    fn velocity_denies_a_high_impact_burst() {
        let policy = TrajectoryPolicy { combos: vec![], max_high_impact: 2, window_ms: 10_000 };
        let mut m = TrajectoryMonitor::new(policy);
        assert!(m.record_and_check(ev("database", "delete", "high", 1000)).allowed());
        assert!(m.record_and_check(ev("database", "delete", "high", 2000)).allowed());
        let v = m.record_and_check(ev("database", "delete", "high", 3000));
        assert!(!v.allowed(), "third high-impact action within the window is denied");
    }

    #[test]
    fn unrelated_actions_do_not_trip_the_combo() {
        let mut m = TrajectoryMonitor::new(exfil_policy());
        assert!(m.record_and_check(ev("filesystem", "read", "low", 1000)).allowed());
        assert!(m.record_and_check(ev("network", "egress", "low", 2000)).allowed(), "egress without a prior secret read is fine");
    }
}
