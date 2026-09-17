//! Privacy-safe classifier drift monitoring (decision D6).
//!
//! Classifiers silently rot: a new argument shape appears, a locale shifts, and the pii/secret
//! hit-rate drifts away from the rate measured at eval time. This monitor tracks per-class and
//! per-tool hit-rates using only counts, never raw arguments, and flags any class whose live
//! rate deviates from its baseline beyond a tolerance. It is the runtime companion to the D5
//! offline eval: the eval sets the baseline, this watches production against it.

use std::collections::HashMap;

#[derive(Debug, Default, Clone, Copy)]
struct Counter {
    hits: u64,
    total: u64,
}

impl Counter {
    fn rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.hits as f64 / self.total as f64
        }
    }
}

/// Live per-class hit-rate tracker. Baselines come from the eval report (D5).
#[derive(Debug, Default)]
pub struct DriftMonitor {
    baseline: HashMap<String, f64>,
    live: HashMap<String, Counter>,
    tolerance: f64,
}

/// A class whose live rate has drifted beyond tolerance from its baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct Drift {
    pub class: String,
    pub baseline: f64,
    pub live: f64,
    pub delta: f64,
}

impl DriftMonitor {
    /// `tolerance` is the absolute hit-rate deviation tolerated before a class is flagged.
    pub fn new(tolerance: f64) -> Self {
        DriftMonitor {
            baseline: HashMap::new(),
            live: HashMap::new(),
            tolerance,
        }
    }

    pub fn set_baseline(&mut self, class: &str, rate: f64) {
        self.baseline.insert(class.to_string(), rate);
    }

    /// Observe one classification for a class: `hit` is whether the classifier fired.
    /// No argument content is passed in, by design.
    pub fn observe(&mut self, class: &str, hit: bool) {
        let c = self.live.entry(class.to_string()).or_default();
        c.total += 1;
        if hit {
            c.hits += 1;
        }
    }

    pub fn live_rate(&self, class: &str) -> f64 {
        self.live.get(class).map(Counter::rate).unwrap_or(0.0)
    }

    /// Return every class whose live rate has drifted beyond tolerance. Classes with fewer than
    /// `min_support` observations are skipped so early noise does not page.
    pub fn drifts(&self, min_support: u64) -> Vec<Drift> {
        let mut out = Vec::new();
        for (class, base) in &self.baseline {
            let c = match self.live.get(class) {
                Some(c) if c.total >= min_support => c,
                _ => continue,
            };
            let live = c.rate();
            let delta = (live - base).abs();
            if delta > self.tolerance {
                out.push(Drift {
                    class: class.clone(),
                    baseline: *base,
                    live,
                    delta,
                });
            }
        }
        out.sort_by(|a, b| a.class.cmp(&b.class));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_that_holds_its_baseline_does_not_drift() {
        let mut m = DriftMonitor::new(0.15);
        m.set_baseline("pii", 0.5);
        for i in 0..10 {
            m.observe("pii", i % 2 == 0); // 50% hit-rate
        }
        assert!(m.drifts(5).is_empty());
    }

    #[test]
    fn a_collapsed_hit_rate_is_flagged() {
        let mut m = DriftMonitor::new(0.15);
        m.set_baseline("secret", 0.9);
        for _ in 0..20 {
            m.observe("secret", false); // classifier stopped firing
        }
        let d = m.drifts(5);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].class, "secret");
        assert!(d[0].delta > 0.15);
    }

    #[test]
    fn low_support_classes_are_not_flagged_yet() {
        let mut m = DriftMonitor::new(0.15);
        m.set_baseline("pii", 0.9);
        m.observe("pii", false); // only one sample
        assert!(m.drifts(5).is_empty(), "too little data to page");
    }
}
