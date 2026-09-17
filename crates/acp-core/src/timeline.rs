//! Cross-proxy forensic timeline + clock-skew alarm (decision F11).
//!
//! With hybrid logical clocks stamped on every record, a query spanning several proxies can return
//! one causally ordered timeline even though the proxies' wall clocks differ. This orders records
//! by their HLC encoding (which sorts causally) and, separately, alarms if the proxies' wall-clock
//! readings diverge beyond a bound, since large skew degrades the human-time interpretation.

/// A record reduced to what ordering needs: its HLC encoding and originating proxy/wall time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub hlc: String,
    pub proxy: String,
    pub wall_ms: u64,
}

/// Return the entries in a single causal order (by HLC encoding).
pub fn order(entries: &[TimelineEntry]) -> Vec<TimelineEntry> {
    let mut v = entries.to_vec();
    v.sort_by(|a, b| a.hlc.cmp(&b.hlc));
    v
}

/// True if any two proxies' wall-clock readings differ by more than `bound_ms`: raise a skew alarm.
pub fn skew_exceeds(entries: &[TimelineEntry], bound_ms: u64) -> bool {
    let (mut min, mut max) = (u64::MAX, u64::MIN);
    for e in entries {
        min = min.min(e.wall_ms);
        max = max.max(e.wall_ms);
    }
    entries.len() > 1 && max.saturating_sub(min) > bound_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(hlc: &str, proxy: &str, wall: u64) -> TimelineEntry {
        TimelineEntry {
            hlc: hlc.into(),
            proxy: proxy.into(),
            wall_ms: wall,
        }
    }

    #[test]
    fn entries_order_causally_across_proxies() {
        // Two proxies, HLC encoding sorts causally regardless of insertion order.
        let input = vec![
            e("0000000000000010:00000000:p2", "p2", 16),
            e("000000000000000a:00000000:p1", "p1", 10),
            e("000000000000000a:00000001:p1", "p1", 10),
        ];
        let ordered = order(&input);
        assert_eq!(ordered[0].proxy, "p1");
        assert_eq!(ordered[0].hlc, "000000000000000a:00000000:p1");
        assert_eq!(ordered[2].hlc, "0000000000000010:00000000:p2");
    }

    #[test]
    fn large_wall_clock_skew_alarms() {
        let ok = vec![e("a", "p1", 1000), e("b", "p2", 1200)];
        assert!(!skew_exceeds(&ok, 1000), "200ms within bound");
        let bad = vec![e("a", "p1", 1000), e("b", "p2", 9000)];
        assert!(skew_exceeds(&bad, 1000), "8s skew alarms");
    }
}
