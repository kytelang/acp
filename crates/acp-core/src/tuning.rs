//! Classifier feedback / tuning loop (decision v2.2.2), advisory-only on the deny path.
//!
//! Classifiers improve from false-positive/negative feedback, but that feedback must never be able
//! to flip a policy deny: classifiers stay advisory where enforcement is concerned. This records
//! labelled feedback (what the classifier predicted vs the reviewer's ground truth) and reports
//! running precision/recall so accuracy is measured over time, and it exposes a single guard that
//! makes the advisory-only property explicit and testable.

#[derive(Debug, Default, Clone, Copy)]
pub struct Confusion {
    pub tp: u64,
    pub fp: u64,
    pub fn_: u64,
    pub tn: u64,
}

impl Confusion {
    pub fn precision(&self) -> f64 {
        let d = self.tp + self.fp;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    pub fn recall(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
}

#[derive(Debug, Default)]
pub struct TuningLog {
    c: Confusion,
}

impl TuningLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one piece of feedback: did the classifier fire (`predicted`), and was the class
    /// actually present (`actual`).
    pub fn feedback(&mut self, predicted: bool, actual: bool) {
        match (predicted, actual) {
            (true, true) => self.c.tp += 1,
            (true, false) => self.c.fp += 1,
            (false, true) => self.c.fn_ += 1,
            (false, false) => self.c.tn += 1,
        }
    }

    pub fn confusion(&self) -> Confusion {
        self.c
    }

    /// The advisory-only guard: feedback can inform classifier metrics but must never change the
    /// enforced verdict. Given a policy verdict and any classifier feedback, the verdict is
    /// returned unchanged. This exists so the property is asserted in code, not just documented.
    pub fn apply_advisory(policy_verdict: &str, _classifier_says_safe: bool) -> String {
        policy_verdict.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_and_recall_track_feedback() {
        let mut t = TuningLog::new();
        t.feedback(true, true); // tp
        t.feedback(true, false); // fp
        t.feedback(false, true); // fn
        let c = t.confusion();
        assert!((c.precision() - 0.5).abs() < 1e-9);
        assert!((c.recall() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn feedback_never_flips_an_enforced_deny() {
        // Even if the classifier now "thinks" the call is safe, a policy deny stays a deny.
        assert_eq!(TuningLog::apply_advisory("deny", true), "deny");
        assert_eq!(TuningLog::apply_advisory("allow", false), "allow");
    }
}
