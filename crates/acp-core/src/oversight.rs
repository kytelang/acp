//! Oversight-quality monitoring (gap G1): is human approval effective, or rubber-stamping?
//!
//! EU AI Act Article 14 requires human oversight of high-risk AI to be effective, not merely present.
//! ACP already records every approval decision with the approver, the request time and the decision
//! time, so it can measure oversight quality directly rather than assume it. This module scores each
//! approver for the classic rubber-stamp signals: approving nearly everything, deciding faster than a
//! human plausibly could have reviewed, and approving in bulk. It is pure: the store supplies the
//! decisions, the server persists a signed finding for anyone flagged.

use serde::{Deserialize, Serialize};

/// One resolved approval decision, as read from the approvals store.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub approver: String,
    pub approved: bool,
    pub created_ms: u64,
    pub resolved_ms: u64,
}

/// Thresholds for flagging. Defaults are deliberately conservative so a normal reviewer is never
/// flagged; tune per deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OversightConfig {
    /// Do not judge an approver with fewer than this many resolved decisions.
    pub min_decisions: u32,
    /// Flag if the fraction of decisions that were approvals is at or above this.
    pub approve_rate: f64,
    /// A decision resolved in less than this many milliseconds is "fast" (too fast to have reviewed).
    pub fast_ms: u64,
    /// Flag if the fraction of fast decisions is at or above this.
    pub fast_fraction: f64,
    /// The sliding window for bulk-approval detection.
    pub bulk_window_ms: u64,
    /// Flag if this many or more decisions fall within any single window.
    pub bulk_count: u32,
}

impl Default for OversightConfig {
    fn default() -> Self {
        OversightConfig {
            min_decisions: 5,
            approve_rate: 0.95,
            fast_ms: 5_000,
            fast_fraction: 0.8,
            bulk_window_ms: 60_000,
            bulk_count: 10,
        }
    }
}

/// The oversight profile of one approver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApproverOversight {
    pub approver: String,
    pub total: u32,
    pub approved: u32,
    pub approve_rate: f64,
    pub median_latency_ms: u64,
    pub fast_fraction: f64,
    pub max_in_window: u32,
    /// The specific weaknesses that tripped, in plain English. Empty means healthy.
    pub reasons: Vec<String>,
    pub flagged: bool,
}

fn median(mut v: Vec<u64>) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    }
}

/// The largest number of decisions that fall within any window of `window_ms`, by resolution time.
fn max_in_window(mut resolved: Vec<u64>, window_ms: u64) -> u32 {
    resolved.sort_unstable();
    let mut best = 0u32;
    let mut start = 0usize;
    for end in 0..resolved.len() {
        while resolved[end].saturating_sub(resolved[start]) > window_ms {
            start += 1;
        }
        best = best.max((end - start + 1) as u32);
    }
    best
}

/// Score every approver in `decisions` against `cfg`. Returns one profile per approver, flagged ones
/// carrying the reasons they tripped. Deterministic and sorted by approver for stable output.
pub fn analyze(decisions: &[Decision], cfg: &OversightConfig) -> Vec<ApproverOversight> {
    use std::collections::BTreeMap;
    let mut by: BTreeMap<String, Vec<&Decision>> = BTreeMap::new();
    for d in decisions {
        by.entry(d.approver.clone()).or_default().push(d);
    }
    let mut out = Vec::new();
    for (approver, ds) in by {
        let total = ds.len() as u32;
        let approved = ds.iter().filter(|d| d.approved).count() as u32;
        let approve_rate = approved as f64 / total as f64;
        let latencies: Vec<u64> = ds.iter().map(|d| d.resolved_ms.saturating_sub(d.created_ms)).collect();
        let fast = latencies.iter().filter(|l| **l < cfg.fast_ms).count() as u32;
        let fast_fraction = fast as f64 / total as f64;
        let miw = max_in_window(ds.iter().map(|d| d.resolved_ms).collect(), cfg.bulk_window_ms);
        let mut reasons = Vec::new();
        if total >= cfg.min_decisions {
            if approve_rate >= cfg.approve_rate {
                reasons.push(format!("approves {:.0}% of requests", approve_rate * 100.0));
            }
            if fast_fraction >= cfg.fast_fraction {
                reasons.push(format!("decides in under {}s on {:.0}% of cases", cfg.fast_ms / 1000, fast_fraction * 100.0));
            }
            if miw >= cfg.bulk_count {
                reasons.push(format!("approved {} within {}s", miw, cfg.bulk_window_ms / 1000));
            }
        }
        let flagged = !reasons.is_empty();
        out.push(ApproverOversight {
            approver,
            total,
            approved,
            approve_rate,
            median_latency_ms: median(latencies),
            fast_fraction,
            max_in_window: miw,
            reasons,
            flagged,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(approver: &str, approved: bool, created: u64, resolved: u64) -> Decision {
        Decision { approver: approver.into(), approved, created_ms: created, resolved_ms: resolved }
    }

    #[test]
    fn approve_all_and_fast_is_flagged() {
        // 20 approvals, each decided ~1s after request, spread 2s apart.
        let ds: Vec<Decision> = (0..20).map(|i| {
            let t = 1_000_000 + i as u64 * 2_000;
            d("alice", true, t, t + 1_000)
        }).collect();
        let r = analyze(&ds, &OversightConfig::default());
        let a = r.iter().find(|x| x.approver == "alice").unwrap();
        assert!(a.flagged, "accept-all + fast approver must be flagged");
        assert_eq!(a.approved, 20);
        assert!(a.reasons.iter().any(|s| s.contains("approves")));
        assert!(a.reasons.iter().any(|s| s.contains("under")));
    }

    #[test]
    fn mixed_decisions_with_normal_latency_not_flagged() {
        // 10 decisions, half denied, each taking ~30s, spread minutes apart.
        let ds: Vec<Decision> = (0..10).map(|i| {
            let t = 1_000_000 + i as u64 * 300_000;
            d("bob", i % 2 == 0, t, t + 30_000)
        }).collect();
        let r = analyze(&ds, &OversightConfig::default());
        let b = r.iter().find(|x| x.approver == "bob").unwrap();
        assert!(!b.flagged, "a careful reviewer must not be flagged; reasons={:?}", b.reasons);
    }

    #[test]
    fn below_min_decisions_is_never_flagged() {
        let ds = vec![d("carol", true, 1000, 1100), d("carol", true, 2000, 2100)];
        let r = analyze(&ds, &OversightConfig::default());
        assert!(!r[0].flagged, "too few decisions to judge");
    }

    #[test]
    fn thresholds_are_configurable() {
        // 6 approvals at 10s latency: not flagged under default (fast_ms=5s), flagged if fast_ms raised.
        let ds: Vec<Decision> = (0..6).map(|i| {
            let t = 1_000_000 + i as u64 * 100_000;
            d("dan", true, t, t + 10_000)
        }).collect();
        let mut cfg = OversightConfig::default();
        // default: approve_rate trips (100% >= 95%), so it's already flagged on rate. Use a strict
        // rate so only latency can flag, to isolate the latency threshold.
        cfg.approve_rate = 1.01; // impossible, so approve-rate never trips
        let r_default = analyze(&ds, &cfg);
        assert!(!r_default[0].flagged, "10s decisions are not fast under fast_ms=5s");
        cfg.fast_ms = 15_000; // now 10s counts as fast
        let r_loose = analyze(&ds, &cfg);
        assert!(r_loose[0].flagged, "raising fast_ms flags the same data");
    }
}
