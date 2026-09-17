//! Fail-open / deny-surge spike alerting (decision B3).
//!
//! Some conditions are only visible as a change in rate: a burst of fail-open decisions (the
//! evidence write is failing, so calls slip through), a surge of denies (a bad actor probing),
//! or a wave of approval timeouts. This is a sliding-window rate detector with a documented
//! baseline; it is pure and time-injected so an induced spike deterministically pages.

use std::collections::VecDeque;

/// Counts events in a rolling time window and compares the rate to a threshold.
#[derive(Debug)]
pub struct SpikeDetector {
    window_ms: u64,
    threshold: usize,
    events: VecDeque<u64>,
}

impl SpikeDetector {
    /// `threshold` is the maximum tolerated count within `window_ms` before the detector trips.
    pub fn new(window_ms: u64, threshold: usize) -> Self {
        SpikeDetector {
            window_ms,
            threshold,
            events: VecDeque::new(),
        }
    }

    pub fn record(&mut self, ts_ms: u64) {
        self.events.push_back(ts_ms);
    }

    fn evict(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&front) = self.events.front() {
            if front < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Count of events still inside the window as of `now_ms`.
    pub fn count(&mut self, now_ms: u64) -> usize {
        self.evict(now_ms);
        self.events.len()
    }

    /// True when the in-window count strictly exceeds the threshold: page.
    pub fn tripped(&mut self, now_ms: u64) -> bool {
        self.count(now_ms) > self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_induced_spike_over_threshold_pages() {
        let mut d = SpikeDetector::new(1_000, 3);
        for t in [10, 20, 30] {
            d.record(t);
        }
        assert!(!d.tripped(40), "3 within threshold of 3");
        d.record(40);
        assert!(d.tripped(50), "4 exceeds threshold");
    }

    #[test]
    fn old_events_fall_out_of_the_window() {
        let mut d = SpikeDetector::new(1_000, 2);
        d.record(0);
        d.record(100);
        d.record(200);
        assert!(d.tripped(300), "3 in window");
        // Advance past the window so the early events expire.
        assert_eq!(d.count(1_300), 0, "all evicted");
        assert!(!d.tripped(1_300));
    }
}
