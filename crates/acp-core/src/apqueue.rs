//! Approver operations baseline: queue caps and reminders (decision M4.7).
//!
//! An approval queue that grows without bound under a step-up burst is a denial of service on the
//! humans. This caps the queue (rejecting new holds with a retry-after when full, so the proxy can
//! back-pressure rather than pile up) and tracks which holds are due for a reminder, so an ageing
//! approval is nudged rather than forgotten. Pure and time-injected.

#[derive(Debug, Clone)]
struct Held {
    id: String,
    created_ms: u64,
    last_reminded_ms: u64,
}

#[derive(Debug)]
pub struct ApprovalQueue {
    cap: usize,
    items: Vec<Held>,
}

/// Returned when the queue is full: how long the caller should wait before retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAfter {
    pub ms: u64,
}

impl ApprovalQueue {
    pub fn new(cap: usize) -> Self {
        ApprovalQueue {
            cap,
            items: Vec::new(),
        }
    }

    pub fn depth(&self) -> usize {
        self.items.len()
    }

    /// Age of the oldest pending hold, for queue-health telemetry (None if empty).
    pub fn oldest_age_ms(&self, now_ms: u64) -> Option<u64> {
        self.items
            .iter()
            .map(|h| now_ms.saturating_sub(h.created_ms))
            .max()
    }

    /// Enqueue a hold. When the queue is at capacity, reject with a retry-after (with jitter folded
    /// in by the caller) so a burst backs off instead of unbounded growth.
    pub fn enqueue(&mut self, id: &str, now_ms: u64, retry_ms: u64) -> Result<(), RetryAfter> {
        if self.items.len() >= self.cap {
            return Err(RetryAfter { ms: retry_ms });
        }
        self.items.push(Held {
            id: id.to_string(),
            created_ms: now_ms,
            last_reminded_ms: now_ms,
        });
        Ok(())
    }

    pub fn resolve(&mut self, id: &str) {
        self.items.retain(|h| h.id != id);
    }

    /// Ids whose last reminder is older than `interval_ms`; marks them reminded at `now_ms`.
    pub fn due_for_reminder(&mut self, now_ms: u64, interval_ms: u64) -> Vec<String> {
        let mut due = Vec::new();
        for h in &mut self.items {
            if now_ms.saturating_sub(h.last_reminded_ms) >= interval_ms {
                due.push(h.id.clone());
                h.last_reminded_ms = now_ms;
            }
        }
        due.sort();
        due
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_queue_caps_and_backs_off_when_full() {
        let mut q = ApprovalQueue::new(2);
        assert!(q.enqueue("a", 0, 500).is_ok());
        assert!(q.enqueue("b", 0, 500).is_ok());
        assert_eq!(
            q.enqueue("c", 0, 500),
            Err(RetryAfter { ms: 500 }),
            "full queue backs off"
        );
        q.resolve("a");
        assert!(
            q.enqueue("c", 0, 500).is_ok(),
            "space frees up after a resolve"
        );
    }

    #[test]
    fn ageing_holds_become_due_for_a_reminder_once_per_interval() {
        let mut q = ApprovalQueue::new(10);
        q.enqueue("a", 0, 500).unwrap();
        assert!(q.due_for_reminder(500, 1000).is_empty(), "not due yet");
        assert_eq!(
            q.due_for_reminder(1000, 1000),
            vec!["a"],
            "due after the interval"
        );
        assert!(
            q.due_for_reminder(1000, 1000).is_empty(),
            "not reminded twice in one interval"
        );
        assert_eq!(
            q.due_for_reminder(2000, 1000),
            vec!["a"],
            "due again next interval"
        );
    }
}
