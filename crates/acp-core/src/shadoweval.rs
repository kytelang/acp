//! Staged / shadow evaluation of classifier changes (decision D8).
//!
//! Before a new classifier version replaces the current one, it runs in shadow against live traffic
//! and we compare its firing rate to the incumbent, per class. Promotion is gated on that diff being
//! within tolerance, so a candidate that suddenly fires on twice as much traffic (or goes quiet) is
//! caught before it enforces anything. This uses counts only, never raw arguments.

use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, Copy)]
struct Pair {
    current_hits: u64,
    candidate_hits: u64,
    total: u64,
}

#[derive(Debug, Default)]
pub struct ShadowEval {
    by_class: BTreeMap<String, Pair>,
}

/// The per-class firing-rate difference between candidate and current.
#[derive(Debug, Clone, PartialEq)]
pub struct RateDiff {
    pub class: String,
    pub current_rate: f64,
    pub candidate_rate: f64,
    pub delta: f64,
}

impl ShadowEval {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one sample: did the current and candidate classifiers fire for `class`.
    pub fn observe(&mut self, class: &str, current_fired: bool, candidate_fired: bool) {
        let p = self.by_class.entry(class.to_string()).or_default();
        p.total += 1;
        if current_fired {
            p.current_hits += 1;
        }
        if candidate_fired {
            p.candidate_hits += 1;
        }
    }

    pub fn diffs(&self) -> Vec<RateDiff> {
        self.by_class
            .iter()
            .map(|(class, p)| {
                let cur = if p.total == 0 {
                    0.0
                } else {
                    p.current_hits as f64 / p.total as f64
                };
                let cand = if p.total == 0 {
                    0.0
                } else {
                    p.candidate_hits as f64 / p.total as f64
                };
                RateDiff {
                    class: class.clone(),
                    current_rate: cur,
                    candidate_rate: cand,
                    delta: (cand - cur).abs(),
                }
            })
            .collect()
    }

    /// Promotion is allowed only if every class's firing-rate delta is within `tolerance`.
    pub fn promotable(&self, tolerance: f64) -> bool {
        self.diffs().iter().all(|d| d.delta <= tolerance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_candidate_matching_the_incumbent_is_promotable() {
        let mut e = ShadowEval::new();
        for i in 0..100 {
            let fired = i % 3 == 0;
            e.observe("pii", fired, fired); // identical behaviour
        }
        assert!(e.promotable(0.05));
    }

    #[test]
    fn a_candidate_that_fires_far_more_is_gated() {
        let mut e = ShadowEval::new();
        for i in 0..100 {
            e.observe("secret", i % 10 == 0, i % 2 == 0); // 10% vs 50%
        }
        assert!(
            !e.promotable(0.10),
            "a large firing-rate divergence blocks promotion"
        );
        let d = &e.diffs()[0];
        assert!(d.delta > 0.10);
    }
}
