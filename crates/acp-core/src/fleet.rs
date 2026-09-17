//! Fleet management for many proxies (decision F3).
//!
//! At scale there are many proxies, and policy/config must reach the right cohort (a canary group,
//! a region) without touching the others, while a proxy that stops heartbeating must surface as an
//! ungoverned surface. This is the registry that answers "which proxies are in cohort X" (for
//! targeted rollout) and "which proxies have gone silent" (for the alert).

use std::collections::HashMap;

#[derive(Debug, Clone)]
struct ProxyInfo {
    cohort: String,
    last_heartbeat_ms: u64,
}

#[derive(Debug, Default)]
pub struct FleetRegistry {
    proxies: HashMap<String, ProxyInfo>,
}

impl FleetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, proxy: &str, cohort: &str, ts_ms: u64) {
        self.proxies.insert(
            proxy.to_string(),
            ProxyInfo {
                cohort: cohort.to_string(),
                last_heartbeat_ms: ts_ms,
            },
        );
    }

    pub fn heartbeat(&mut self, proxy: &str, ts_ms: u64) {
        if let Some(p) = self.proxies.get_mut(proxy) {
            p.last_heartbeat_ms = p.last_heartbeat_ms.max(ts_ms);
        }
    }

    /// The proxies a cohort-targeted rollout should reach, and only those.
    pub fn targets(&self, cohort: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .proxies
            .iter()
            .filter(|(_, p)| p.cohort == cohort)
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v
    }

    /// Proxies whose last heartbeat is older than `window_ms`: ungoverned-surface alerts.
    pub fn ungoverned(&self, now_ms: u64, window_ms: u64) -> Vec<String> {
        let mut v: Vec<String> = self
            .proxies
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.last_heartbeat_ms) > window_ms)
            .map(|(id, _)| id.clone())
            .collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cohort_rollout_reaches_only_that_cohort() {
        let mut f = FleetRegistry::new();
        f.register("p1", "prod-eu", 0);
        f.register("p2", "prod-eu", 0);
        f.register("p3", "prod-us", 0);
        assert_eq!(f.targets("prod-eu"), vec!["p1", "p2"]);
        assert_eq!(f.targets("prod-us"), vec!["p3"]);
        assert!(f.targets("canary").is_empty());
    }

    #[test]
    fn a_silent_proxy_is_flagged_as_ungoverned() {
        let mut f = FleetRegistry::new();
        f.register("p1", "prod-eu", 1_000);
        f.register("p2", "prod-eu", 1_000);
        f.heartbeat("p1", 5_000);
        // At t=5500 with a 1000ms window, p1 (last=5000, 500ms ago) is fresh, p2 (last=1000) stale.
        assert_eq!(f.ungoverned(5_500, 1_000), vec!["p2"]);
    }
}
