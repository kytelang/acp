//! Default-deny posture maturity path (decision E6).
//!
//! Flipping a tenant straight to default-deny without knowing what it will break is how a
//! control gets switched off again the next morning. This models the staged path: a tenant
//! moves shadow -> partial -> default-deny, and default-deny can only be enabled once policy
//! coverage clears a threshold. Enabling it also produces the exact set of calls that would
//! newly block, so the operator sees the blast radius before committing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Nothing is enforced; everything is recorded as would-block.
    Shadow,
    /// Matched rules enforce; unmatched calls still pass.
    Partial,
    /// Unmatched calls are denied by default.
    DefaultDeny,
}

/// The result of asking to move to default-deny.
#[derive(Debug, Clone, PartialEq)]
pub enum Enable {
    /// Allowed. Carries the calls that would newly block so the operator can add exceptions.
    Ready { would_block: Vec<String> },
    /// Refused: coverage is below the required threshold.
    BlockedByCoverage { coverage: f64, required: f64 },
}

pub struct Posture {
    pub stage: Stage,
    pub required_coverage: f64,
}

impl Posture {
    pub fn new(required_coverage: f64) -> Self {
        Posture {
            stage: Stage::Shadow,
            required_coverage,
        }
    }

    /// Attempt to enable default-deny. `coverage` is the fraction of observed calls a rule
    /// matched; `unmatched_tools` are the currently-unmatched calls that would newly block.
    pub fn enable_default_deny(&mut self, coverage: f64, unmatched_tools: &[String]) -> Enable {
        if coverage < self.required_coverage {
            return Enable::BlockedByCoverage {
                coverage,
                required: self.required_coverage,
            };
        }
        self.stage = Stage::DefaultDeny;
        let mut would_block = unmatched_tools.to_vec();
        would_block.sort();
        would_block.dedup();
        Enable::Ready { would_block }
    }

    pub fn advance_to_partial(&mut self) {
        if self.stage == Stage::Shadow {
            self.stage = Stage::Partial;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_coverage_blocks_the_flip_to_default_deny() {
        let mut p = Posture::new(0.8);
        let got = p.enable_default_deny(0.5, &["fs.write".into()]);
        assert!(matches!(got, Enable::BlockedByCoverage { .. }));
        assert_eq!(p.stage, Stage::Shadow, "must not have flipped");
    }

    #[test]
    fn sufficient_coverage_flips_and_reports_the_blast_radius() {
        let mut p = Posture::new(0.8);
        p.advance_to_partial();
        let got = p.enable_default_deny(0.9, &["b".into(), "a".into(), "a".into()]);
        match got {
            Enable::Ready { would_block } => assert_eq!(would_block, vec!["a", "b"]),
            other => panic!("expected Ready, got {other:?}"),
        }
        assert_eq!(p.stage, Stage::DefaultDeny);
    }
}
