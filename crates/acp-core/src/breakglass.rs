//! Break-glass / emergency controls (decision F2).
//!
//! Real incidents need a way to override the control, but an unbounded, unlogged override is
//! itself the risk. Every break-glass mode here carries a mandatory reason and a TTL, auto-
//! reverts when the TTL passes, and is designed to be written to the tamper-evident meta-audit
//! log (see `metaaudit`). `EmergencyBypass` forwards a call that would otherwise be held.

use crate::types::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Stop enforcing deny/step_up; record only. Narrower than a full bypass.
    DisableEnforce,
    /// Deny everything: containment during an active compromise.
    LockdownAll,
    /// Forward calls that would be held for approval: unblock an operator mid-incident.
    EmergencyBypass,
}

/// An active break-glass grant. Construct via `BreakGlass::engage` so a reason is mandatory.
#[derive(Debug, Clone)]
pub struct BreakGlass {
    pub mode: Mode,
    pub reason: String,
    pub engaged_ms: u64,
    pub ttl_ms: u64,
}

impl BreakGlass {
    /// Engage a mode. `reason` must be non-empty; TTL bounds the window.
    pub fn engage(mode: Mode, reason: &str, now_ms: u64, ttl_ms: u64) -> Result<Self, String> {
        if reason.trim().is_empty() {
            return Err("break-glass requires a reason".into());
        }
        if ttl_ms == 0 {
            return Err("break-glass requires a non-zero TTL".into());
        }
        Ok(BreakGlass {
            mode,
            reason: reason.to_string(),
            engaged_ms: now_ms,
            ttl_ms,
        })
    }

    pub fn active(&self, now_ms: u64) -> bool {
        now_ms < self.engaged_ms.saturating_add(self.ttl_ms)
    }

    /// Apply the mode to a base verdict at `now_ms`. Once the TTL passes, the base verdict is
    /// returned unchanged: the override auto-reverts with no operator action.
    pub fn apply(&self, base: Verdict, now_ms: u64) -> Verdict {
        if !self.active(now_ms) {
            return base;
        }
        match self.mode {
            Mode::LockdownAll => Verdict::Deny,
            Mode::DisableEnforce => match base {
                Verdict::Deny | Verdict::StepUp => Verdict::Shadow,
                other => other,
            },
            Mode::EmergencyBypass => match base {
                Verdict::StepUp => Verdict::Allow,
                other => other,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_mandatory() {
        assert!(BreakGlass::engage(Mode::LockdownAll, "  ", 0, 1000).is_err());
        assert!(BreakGlass::engage(Mode::LockdownAll, "incident-42", 0, 1000).is_ok());
    }

    #[test]
    fn emergency_bypass_forwards_a_would_hold_call() {
        let bg = BreakGlass::engage(Mode::EmergencyBypass, "pager", 0, 1000).unwrap();
        assert_eq!(bg.apply(Verdict::StepUp, 500), Verdict::Allow);
        // A deny is not loosened by emergency-bypass.
        assert_eq!(bg.apply(Verdict::Deny, 500), Verdict::Deny);
    }

    #[test]
    fn the_override_auto_reverts_after_the_ttl() {
        let bg = BreakGlass::engage(Mode::EmergencyBypass, "pager", 0, 1000).unwrap();
        assert_eq!(bg.apply(Verdict::StepUp, 1500), Verdict::StepUp, "expired");
        assert!(!bg.active(1500));
    }

    #[test]
    fn lockdown_denies_everything_while_active() {
        let bg = BreakGlass::engage(Mode::LockdownAll, "breach", 0, 1000).unwrap();
        assert_eq!(bg.apply(Verdict::Allow, 10), Verdict::Deny);
    }
}
