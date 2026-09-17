//! Hybrid logical clock for cross-proxy causal ordering (decision D12/F11).
//!
//! Wall-clock timestamps alone cannot order records emitted by different proxies: their
//! clocks skew. An HLC pairs the best-known physical time with a logical counter so that
//! records gain a total, causally consistent order even across nodes, while staying close
//! to real time. The encoding sorts lexically in the same order it sorts causally, so a
//! plain string comparison over `encode()` yields the timeline.

/// A hybrid logical clock. `wall_ms` tracks physical time; `counter` breaks ties and absorbs
/// clock going backwards. `node` disambiguates equal (wall, counter) pairs across proxies.
#[derive(Debug, Clone)]
pub struct Hlc {
    node: String,
    wall_ms: u64,
    counter: u32,
}

/// A single stamp, cheap to compare and to encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub wall_ms: u64,
    pub counter: u32,
    pub node: String,
}

impl Hlc {
    pub fn new(node: impl Into<String>) -> Self {
        Hlc {
            node: node.into(),
            wall_ms: 0,
            counter: 0,
        }
    }

    /// Advance for a locally generated event at physical time `now_ms`.
    pub fn tick(&mut self, now_ms: u64) -> Stamp {
        if now_ms > self.wall_ms {
            self.wall_ms = now_ms;
            self.counter = 0;
        } else {
            // Clock did not advance (or went backwards): keep the max wall, bump the counter.
            self.counter += 1;
        }
        self.stamp()
    }

    /// Merge a stamp seen from another node, then advance for the local receive event.
    pub fn update(&mut self, remote: &Stamp, now_ms: u64) -> Stamp {
        let max_wall = self.wall_ms.max(remote.wall_ms).max(now_ms);
        if max_wall == self.wall_ms && max_wall == remote.wall_ms {
            self.counter = self.counter.max(remote.counter) + 1;
        } else if max_wall == self.wall_ms {
            self.counter += 1;
        } else if max_wall == remote.wall_ms {
            self.counter = remote.counter + 1;
        } else {
            self.counter = 0;
        }
        self.wall_ms = max_wall;
        self.stamp()
    }

    fn stamp(&self) -> Stamp {
        Stamp {
            wall_ms: self.wall_ms,
            counter: self.counter,
            node: self.node.clone(),
        }
    }
}

impl Stamp {
    /// Lexically sortable encoding: fixed-width hex of wall then counter, then node id.
    /// Sorting the encoded strings reproduces causal order.
    pub fn encode(&self) -> String {
        format!("{:016x}:{:08x}:{}", self.wall_ms, self.counter, self.node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_monotonic_even_when_wall_stalls() {
        let mut c = Hlc::new("p1");
        let a = c.tick(100);
        let b = c.tick(100); // clock did not move
        let d = c.tick(100);
        assert!(a.encode() < b.encode());
        assert!(b.encode() < d.encode());
        assert_eq!(b.counter, 1);
        assert_eq!(d.counter, 2);
    }

    #[test]
    fn tick_absorbs_a_backwards_clock() {
        let mut c = Hlc::new("p1");
        let a = c.tick(200);
        let b = c.tick(150); // NTP step back
        assert!(a.encode() < b.encode(), "must not go backwards");
        assert_eq!(b.wall_ms, 200);
    }

    #[test]
    fn update_orders_after_a_received_remote_event() {
        let mut p1 = Hlc::new("p1");
        let mut p2 = Hlc::new("p2");
        let sent = p1.tick(300);
        let recv = p2.update(&sent, 250); // p2's clock is behind
        assert!(sent.encode() < recv.encode(), "receive happens-after send");
        assert_eq!(recv.wall_ms, 300);
    }

    #[test]
    fn a_multi_node_timeline_sorts_by_encoding() {
        let mut p1 = Hlc::new("p1");
        let mut p2 = Hlc::new("p2");
        let e1 = p1.tick(10);
        let e2 = p2.update(&e1, 10); // caused by e1
        let e3 = p1.tick(11);
        let mut all = [e3.encode(), e1.encode(), e2.encode()];
        all.sort();
        assert_eq!(all, [e1.encode(), e2.encode(), e3.encode()]);
    }
}
