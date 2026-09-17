//! Dead-man's-switch / liveness gap detection (decision B1).
//!
//! An attacker who wants to act un-governed does not have to defeat the policy engine: they
//! can kill or silence the proxy. This detector, run server-side over the evidence stream,
//! turns "the gate went quiet" into an alarm. Two failure shapes are caught:
//!   - a proxy stops heartbeating entirely (crash, kill, network cut);
//!   - a proxy keeps heartbeating but stops emitting decisions while traffic is known to flow
//!     (the gate was bypassed but the process left alive to look healthy).
//!
//! The logic is pure and time-injected so it is deterministic under test.

use std::collections::HashMap;

#[derive(Debug, Clone)]
struct Seen {
    last_heartbeat_ms: u64,
    last_decision_ms: u64,
}

/// Tracks per-proxy liveness. `expect_traffic` proxies are ones we believe are serving calls.
#[derive(Debug, Default)]
pub struct GapDetector {
    seen: HashMap<String, Seen>,
    expect_traffic: HashMap<String, bool>,
}

/// Why a proxy is flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    /// No heartbeat within the window: the proxy is silent.
    Silent { proxy: String, quiet_ms: u64 },
    /// Heartbeating, but no decisions while traffic is expected: possible bypass.
    DecisionStall { proxy: String, quiet_ms: u64 },
}

impl GapDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn heartbeat(&mut self, proxy: &str, ts_ms: u64) {
        // A brand-new entry has no observed decision yet (0), so a later decision timestamp is
        // free to set it. Seeding it to the heartbeat time would mask a never-deciding proxy.
        let e = self.seen.entry(proxy.to_string()).or_insert(Seen {
            last_heartbeat_ms: 0,
            last_decision_ms: 0,
        });
        e.last_heartbeat_ms = e.last_heartbeat_ms.max(ts_ms);
    }

    pub fn decision(&mut self, proxy: &str, ts_ms: u64) {
        let e = self.seen.entry(proxy.to_string()).or_insert(Seen {
            last_heartbeat_ms: 0,
            last_decision_ms: 0,
        });
        e.last_decision_ms = e.last_decision_ms.max(ts_ms);
    }

    /// Declare whether a proxy is currently expected to be serving governed traffic.
    pub fn expect_traffic(&mut self, proxy: &str, yes: bool) {
        self.expect_traffic.insert(proxy.to_string(), yes);
    }

    /// Return every proxy whose silence exceeds `window_ms` as of `now_ms`.
    pub fn scan(&self, now_ms: u64, window_ms: u64) -> Vec<Gap> {
        let mut out = Vec::new();
        for (proxy, s) in &self.seen {
            let hb_quiet = now_ms.saturating_sub(s.last_heartbeat_ms);
            if hb_quiet > window_ms {
                out.push(Gap::Silent {
                    proxy: proxy.clone(),
                    quiet_ms: hb_quiet,
                });
                continue;
            }
            let dec_quiet = now_ms.saturating_sub(s.last_decision_ms);
            let expects = *self.expect_traffic.get(proxy).unwrap_or(&false);
            if expects && dec_quiet > window_ms {
                out.push(Gap::DecisionStall {
                    proxy: proxy.clone(),
                    quiet_ms: dec_quiet,
                });
            }
        }
        out.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_silenced_proxy_is_flagged_within_the_window() {
        let mut d = GapDetector::new();
        d.heartbeat("p1", 1_000);
        assert!(d.scan(1_500, 1_000).is_empty(), "still fresh");
        match &d.scan(2_600, 1_000)[..] {
            [Gap::Silent { proxy, quiet_ms }] => {
                assert_eq!(proxy, "p1");
                assert_eq!(*quiet_ms, 1_600);
            }
            other => panic!("expected one silent gap, got {other:?}"),
        }
    }

    #[test]
    fn heartbeat_without_decisions_is_flagged_when_traffic_is_expected() {
        let mut d = GapDetector::new();
        d.expect_traffic("p1", true);
        d.heartbeat("p1", 5_000);
        d.decision("p1", 1_000); // last real decision long ago
                                 // Fresh heartbeat keeps it out of Silent, but the decision stall must fire.
        let gaps = d.scan(5_100, 1_000);
        assert!(
            matches!(gaps[..], [Gap::DecisionStall { .. }]),
            "got {gaps:?}"
        );
    }

    #[test]
    fn no_expected_traffic_means_no_decision_stall() {
        let mut d = GapDetector::new();
        d.heartbeat("p1", 5_000);
        d.decision("p1", 1_000);
        assert!(d.scan(5_100, 1_000).is_empty(), "idle proxy is fine");
    }
}
