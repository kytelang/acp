//! Egress / SSRF allowlisting for proxy dials and policy pulls (decision H0.6).
//!
//! The proxy makes outbound connections (to upstream tool servers) and the control plane pulls
//! policy from a git remote. Both are SSRF surfaces: a crafted target could point them at an
//! internal address (link-local metadata endpoints, loopback, private ranges). This is a
//! default-deny allowlist plus a hard block on obviously-internal destinations. It is pure and
//! host-based so it is unit-testable without a network.

/// An allowlist of permitted egress hosts. Empty means deny-all (fail closed).
#[derive(Debug, Default, Clone)]
pub struct EgressPolicy {
    allow: Vec<String>,
}

impl EgressPolicy {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn allow_host(mut self, host: &str) -> Self {
        self.allow.push(host.to_ascii_lowercase());
        self
    }

    /// True only if `host` is explicitly allowed and is not an obviously-internal target. The
    /// internal-target block applies even to allowlisted hosts, so a mistaken allow of "localhost"
    /// still cannot reach the metadata service.
    pub fn permits(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        if is_internal_target(&h) {
            return false;
        }
        self.allow.iter().any(|a| a == &h)
    }
}

/// Reject loopback, link-local (incl. the cloud metadata address), and private ranges.
pub fn is_internal_target(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h == "metadata" {
        return true;
    }
    // The cloud instance metadata endpoint, a classic SSRF pivot.
    if h == "169.254.169.254" || h.starts_with("169.254.") {
        return true;
    }
    if let Ok(v4) = h.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified();
    }
    if let Ok(v6) = h.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback() || v6.is_unspecified();
    }
    false
}


/// A direct-connection probe: whether a governed model/tool host was reachable WITHOUT going through
/// ACP. The egress canary (gap-closure, containment plane) dials each governed host directly and
/// records whether the connection succeeded; the network allowlist should make that impossible, so a
/// success means the host can reach a model or tool off-ACP (a containment breach).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub target: String,
    pub kind: String,
    pub reachable_directly: bool,
}

/// The canary verdict over a set of probes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryResult {
    /// Hosts reachable directly (bypass possible): the breaches that must page.
    pub breaches: Vec<String>,
    /// Hosts correctly refused a direct connection: containment holding.
    pub contained: Vec<String>,
}

impl CanaryResult {
    /// True when no governed host was reachable off-ACP.
    pub fn ok(&self) -> bool {
        self.breaches.is_empty()
    }
}

/// Evaluate probe results into a canary verdict. Any host reachable directly is a breach.
pub fn evaluate_probes(probes: &[Probe]) -> CanaryResult {
    let mut breaches = Vec::new();
    let mut contained = Vec::new();
    for p in probes {
        let line = format!("{} ({})", p.target, p.kind);
        if p.reachable_directly {
            breaches.push(line);
        } else {
            contained.push(line);
        }
    }
    breaches.sort();
    contained.sort();
    CanaryResult { breaches, contained }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_directly_reachable_host_is_a_breach() {
        let probes = vec![
            super::Probe { target: "api.openai.com:443".into(), kind: "model-api".into(), reachable_directly: true },
            super::Probe { target: "mcp.internal:8900".into(), kind: "mcp".into(), reachable_directly: false },
        ];
        let r = super::evaluate_probes(&probes);
        assert!(!r.ok());
        assert_eq!(r.breaches.len(), 1);
        assert_eq!(r.contained.len(), 1);
    }

    #[test]
    fn all_refused_means_contained() {
        let probes = vec![
            super::Probe { target: "api.anthropic.com:443".into(), kind: "model-api".into(), reachable_directly: false },
        ];
        assert!(super::evaluate_probes(&probes).ok());
    }

    use super::*;

    #[test]
    fn deny_by_default() {
        let p = EgressPolicy::new();
        assert!(!p.permits("api.example.com"), "empty allowlist denies all");
    }

    #[test]
    fn allowlisted_public_host_passes() {
        let p = EgressPolicy::new().allow_host("api.example.com");
        assert!(p.permits("api.example.com"));
        assert!(p.permits("API.EXAMPLE.COM"), "case-insensitive");
        assert!(!p.permits("evil.example.com"));
    }

    #[test]
    fn internal_targets_are_blocked_even_if_allowlisted() {
        let p = EgressPolicy::new()
            .allow_host("localhost")
            .allow_host("169.254.169.254")
            .allow_host("10.0.0.5");
        assert!(!p.permits("localhost"));
        assert!(
            !p.permits("169.254.169.254"),
            "metadata endpoint stays blocked"
        );
        assert!(!p.permits("10.0.0.5"), "private range stays blocked");
        assert!(!p.permits("127.0.0.1"));
    }
}
