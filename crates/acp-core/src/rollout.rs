//! Staged policy rollout with blast-radius preview (decision v3.4).
//!
//! A policy change should never go straight to the whole fleet. This models a staged rollout: a
//! blast-radius preview (which calls the new policy would newly block), a canary stage, then
//! widening percentages, with rollback to the previous stage. It composes with `posture` and the
//! `fleet` cohorts; here is the stage machine and the preview.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Preview,
    Canary,
    Partial(u8), // percentage
    Full,
}

/// The blast-radius preview: calls that would newly block under the candidate policy.
pub fn newly_blocked(current_allowed: &[String], candidate_blocked: &[String]) -> Vec<String> {
    let mut out: Vec<String> = candidate_blocked
        .iter()
        .filter(|c| current_allowed.contains(c))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The staged-rollout state machine. `advance` widens one step; `rollback` returns one step.
pub struct Rollout {
    pub stage: Stage,
}

impl Rollout {
    pub fn new() -> Self {
        Rollout {
            stage: Stage::Preview,
        }
    }

    pub fn advance(&mut self) {
        self.stage = match self.stage {
            Stage::Preview => Stage::Canary,
            Stage::Canary => Stage::Partial(50),
            Stage::Partial(p) if p < 100 => Stage::Full,
            _ => Stage::Full,
        };
    }

    pub fn rollback(&mut self) {
        self.stage = match self.stage {
            Stage::Full => Stage::Partial(50),
            Stage::Partial(_) => Stage::Canary,
            Stage::Canary => Stage::Preview,
            Stage::Preview => Stage::Preview,
        };
    }
}

impl Default for Rollout {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_shows_exactly_what_would_newly_block() {
        let current_allowed = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let candidate_blocked = vec!["b".to_string(), "d".to_string()];
        // Only 'b' was previously allowed and is now blocked; 'd' was not allowed before.
        assert_eq!(
            newly_blocked(&current_allowed, &candidate_blocked),
            vec!["b"]
        );
    }

    #[test]
    fn rollout_advances_through_stages_and_can_roll_back() {
        let mut r = Rollout::new();
        assert_eq!(r.stage, Stage::Preview);
        r.advance();
        assert_eq!(r.stage, Stage::Canary);
        r.advance();
        assert_eq!(r.stage, Stage::Partial(50));
        r.advance();
        assert_eq!(r.stage, Stage::Full);
        r.rollback();
        assert_eq!(r.stage, Stage::Partial(50), "rollback returns one stage");
    }
}
