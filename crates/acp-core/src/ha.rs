//! Leader lease with fencing for an HA control plane (decision H1.1).
//!
//! A highly-available control plane must never have two active leaders writing at once. This is a
//! time-based lease with a monotonically increasing fencing token: only one holder can hold a valid
//! lease at a time, and every grant carries a strictly larger token, so a paused old leader that
//! wakes up is fenced out (its token is stale) even if it still believes it is the leader. Pure and
//! time-injected.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub holder: String,
    pub token: u64,
    pub expires_ms: u64,
}

#[derive(Debug, Default)]
pub struct LeaseManager {
    current: Option<Lease>,
    next_token: u64,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn valid(&self, now_ms: u64) -> Option<&Lease> {
        self.current.as_ref().filter(|l| now_ms < l.expires_ms)
    }

    /// Acquire leadership. Succeeds only when no valid lease is held; issues a strictly larger
    /// fencing token each time.
    pub fn acquire(&mut self, candidate: &str, now_ms: u64, ttl_ms: u64) -> Option<Lease> {
        if self.valid(now_ms).is_some() {
            return None;
        }
        self.next_token += 1;
        let lease = Lease {
            holder: candidate.to_string(),
            token: self.next_token,
            expires_ms: now_ms + ttl_ms,
        };
        self.current = Some(lease.clone());
        Some(lease)
    }

    /// Renew, only for the current holder presenting the current token.
    pub fn renew(&mut self, holder: &str, token: u64, now_ms: u64, ttl_ms: u64) -> bool {
        match self.valid(now_ms) {
            Some(l) if l.holder == holder && l.token == token => {
                self.current = Some(Lease {
                    holder: holder.to_string(),
                    token,
                    expires_ms: now_ms + ttl_ms,
                });
                true
            }
            _ => false,
        }
    }

    /// The fencing check a writer performs: is this (holder, token) the current valid leader? A
    /// stale token (a resumed old leader) is rejected.
    pub fn is_leader(&self, holder: &str, token: u64, now_ms: u64) -> bool {
        matches!(self.valid(now_ms), Some(l) if l.holder == holder && l.token == token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_candidate_holds_the_lease_at_a_time() {
        let mut m = LeaseManager::new();
        let a = m.acquire("node-a", 0, 1000).expect("a acquires");
        assert!(
            m.acquire("node-b", 500, 1000).is_none(),
            "b cannot acquire while a is valid"
        );
        assert!(m.is_leader("node-a", a.token, 500));
        assert!(!m.is_leader("node-b", 999, 500));
    }

    #[test]
    fn a_resumed_old_leader_is_fenced_by_the_token() {
        let mut m = LeaseManager::new();
        let a = m.acquire("node-a", 0, 1000).unwrap();
        // a's lease expires; b takes over with a larger token.
        let b = m
            .acquire("node-b", 1500, 1000)
            .expect("b acquires after expiry");
        assert!(b.token > a.token, "fencing token strictly increases");
        // a wakes up thinking it is still leader: it is fenced out.
        assert!(
            !m.is_leader("node-a", a.token, 1600),
            "stale leader is fenced"
        );
        assert!(m.is_leader("node-b", b.token, 1600));
    }

    #[test]
    fn only_the_holder_with_the_right_token_can_renew() {
        let mut m = LeaseManager::new();
        let a = m.acquire("node-a", 0, 1000).unwrap();
        assert!(m.renew("node-a", a.token, 500, 1000));
        assert!(
            !m.renew("node-b", a.token, 600, 1000),
            "wrong holder cannot renew"
        );
        assert!(
            !m.renew("node-a", 999, 600, 1000),
            "wrong token cannot renew"
        );
    }
}
