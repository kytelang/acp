//! Break-glass / emergency controls (decision F2).
//!
//! Real incidents need a way to override the control, but an unbounded, unlogged override is
//! itself the risk. Every break-glass mode here carries a mandatory reason and a TTL, auto-
//! reverts when the TTL passes, and is designed to be written to the tamper-evident meta-audit
//! log (see `metaaudit`). `EmergencyBypass` forwards a call that would otherwise be held.

use crate::metaaudit::{MetaEvent, MetaKind};
use crate::types::Verdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Stop enforcing deny/step_up; record only. Narrower than a full bypass.
    DisableEnforce,
    /// Deny everything: containment during an active compromise.
    LockdownAll,
    /// Forward calls that would be held for approval: unblock an operator mid-incident.
    EmergencyBypass,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::DisableEnforce => "disable_enforce",
            Mode::LockdownAll => "lockdown_all",
            Mode::EmergencyBypass => "emergency_bypass",
        }
    }
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "disable_enforce" => Some(Mode::DisableEnforce),
            "lockdown_all" => Some(Mode::LockdownAll),
            "emergency_bypass" => Some(Mode::EmergencyBypass),
            _ => None,
        }
    }
}

/// On-disk break-glass grant: the local channel between an operator (or the control server) and a
/// proxy. The operator writes this file (via `acp break-glass`), the proxy watches it and applies
/// the grant. Local-file based so it works for both the stdio and HTTP transports and needs no
/// cloud or network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantFile {
    pub mode: String,
    pub reason: String,
    pub actor: String,
    pub engaged_ms: u64,
    pub ttl_ms: u64,
}

impl GrantFile {
    pub fn new(mode: Mode, reason: &str, actor: &str, now_ms: u64, ttl_ms: u64) -> Self {
        GrantFile {
            mode: mode.as_str().to_string(),
            reason: reason.to_string(),
            actor: actor.to_string(),
            engaged_ms: now_ms,
            ttl_ms,
        }
    }
    /// Parse into a live grant, or None if the mode is unknown or the grant is invalid.
    pub fn to_break_glass(&self) -> Option<(BreakGlass, String)> {
        let mode = Mode::parse(&self.mode)?;
        let bg = BreakGlass::engage(mode, &self.reason, self.engaged_ms, self.ttl_ms).ok()?;
        Some((bg, self.actor.clone()))
    }
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

/// Tracks active break-glass grants and ties every engage/revert to the meta-audit log (F2).
/// A grant auto-reverts when its TTL passes; `sweep` produces the revert meta-events to record.
#[derive(Debug, Default)]
pub struct BreakGlassRegistry {
    grants: Vec<(BreakGlass, String)>,
}

impl BreakGlassRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace all active grants with `grant` (or clear if None). Used by the file-watch channel to
    /// reflect the current on-disk grant exactly.
    pub fn replace_all(&mut self, grant: Option<(BreakGlass, String)>) {
        self.grants.clear();
        if let Some(g) = grant {
            self.grants.push(g);
        }
    }

    /// Engage a mode. Returns the meta-audit event the caller must append to the tamper-evident
    /// log, so there is no way to engage break-glass without an auditable record.
    pub fn engage(
        &mut self,
        mode: Mode,
        reason: &str,
        actor: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<MetaEvent, String> {
        let bg = BreakGlass::engage(mode, reason, now_ms, ttl_ms)?;
        let ev = MetaEvent::new(MetaKind::BreakGlassEngage, actor, reason, now_ms)?
            .transition(None, Some(&format!("{mode:?}")));
        self.grants.push((bg, actor.to_string()));
        Ok(ev)
    }

    /// The verdict after applying every currently-active grant to a base verdict.
    pub fn effective(&self, base: Verdict, now_ms: u64) -> Verdict {
        self.grants
            .iter()
            .filter(|(g, _)| g.active(now_ms))
            .fold(base, |acc, (g, _)| g.apply(acc, now_ms))
    }

    /// Drop expired grants and return a revert meta-event for each, for the meta-audit log.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<MetaEvent> {
        let mut reverts = Vec::new();
        let mut kept = Vec::new();
        for (g, actor) in std::mem::take(&mut self.grants) {
            if g.active(now_ms) {
                kept.push((g, actor));
            } else if let Ok(ev) =
                MetaEvent::new(MetaKind::BreakGlassRevert, &actor, "ttl expired", now_ms)
            {
                reverts.push(ev.transition(Some(&format!("{:?}", g.mode)), None));
            }
        }
        self.grants = kept;
        reverts
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

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn engage_emits_a_meta_event_and_takes_effect() {
        let mut reg = BreakGlassRegistry::new();
        let ev = reg
            .engage(Mode::EmergencyBypass, "pager-42", "oncall", 0, 1000)
            .unwrap();
        assert_eq!(format!("{:?}", ev.kind), "BreakGlassEngage");
        // A would-hold call is forwarded while the grant is active.
        assert_eq!(reg.effective(Verdict::StepUp, 500), Verdict::Allow);
    }

    #[test]
    fn expired_grants_auto_revert_with_a_meta_event() {
        let mut reg = BreakGlassRegistry::new();
        reg.engage(Mode::EmergencyBypass, "pager", "oncall", 0, 1000)
            .unwrap();
        // After the TTL, the grant no longer applies and sweep yields a revert record.
        assert_eq!(reg.effective(Verdict::StepUp, 2000), Verdict::StepUp);
        let reverts = reg.sweep(2000);
        assert_eq!(reverts.len(), 1);
        assert_eq!(format!("{:?}", reverts[0].kind), "BreakGlassRevert");
        // Sweeping again yields nothing (already removed).
        assert!(reg.sweep(3000).is_empty());
    }

    #[test]
    fn a_reason_is_still_mandatory_through_the_registry() {
        let mut reg = BreakGlassRegistry::new();
        assert!(reg.engage(Mode::LockdownAll, "", "actor", 0, 1000).is_err());
    }
}
