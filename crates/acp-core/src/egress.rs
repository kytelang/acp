//! Egress / SSRF allowlisting for proxy dials and policy pulls (decision H0.6).
//!
//! The proxy makes outbound connections (to upstream tool servers) and the control plane pulls
//! policy from a git remote. Both are SSRF surfaces: a crafted target could point them at an
//! internal address (link-local metadata endpoints, loopback, private ranges). This is a
//! default-deny allowlist plus a hard block on obviously-internal destinations. It is pure and
//! host-based so it is unit-testable without a network.


use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

/// Signed egress identity (audit F2). At a single shared egress proxy the raw flow carries only a
/// workstation IP, not who is really making the call. The workstation-side agent signs a short-lived
/// assertion of the agent it runs and the human principal it acts for; the egress proxy verifies the
/// signature and freshness (optionally pinning the expected signer key) and attributes the flow to a
/// real principal instead of an IP. The counterpart of the gateway's per-agent virtual key (F1).

/// Clock-skew tolerance: an assertion issued up to this far in the future is still accepted.
const IDENT_SKEW_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressIdentity {
    pub agent: String,
    pub principal: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub issued_ms: u64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

fn ident_signing_value(agent: &str, principal: &str, groups: &[String], issued_ms: u64) -> Value {
    json!({"agent": agent, "principal": principal, "groups": groups, "issued_ms": issued_ms})
}

/// Sign an egress-identity assertion with the workstation agent's key.
pub fn issue_identity(signer: &dyn Signer, agent: &str, principal: &str, groups: &[String], now_ms: u64) -> EgressIdentity {
    let bytes = crate::canonical::canonical_bytes(&ident_signing_value(agent, principal, groups, now_ms));
    let sig = signer.sign(&bytes);
    EgressIdentity {
        agent: agent.to_string(),
        principal: principal.to_string(),
        groups: groups.to_vec(),
        issued_ms: now_ms,
        pubkey_hex: hex::encode(signer.public_key()),
        sig_hex: hex::encode(sig),
    }
}

impl EgressIdentity {
    /// Verify the signature and freshness. Fail-closed on any decode error.
    pub fn verify(&self, now_ms: u64, max_age_ms: u64) -> bool {
        if self.issued_ms > now_ms.saturating_add(IDENT_SKEW_MS) { return false; }
        if now_ms > self.issued_ms.saturating_add(max_age_ms) { return false; }
        let pk = match hex::decode(&self.pubkey_hex) { Ok(p) => p, Err(_) => return false };
        let sig = match hex::decode(&self.sig_hex) { Ok(s) => s, Err(_) => return false };
        let bytes = crate::canonical::canonical_bytes(&ident_signing_value(&self.agent, &self.principal, &self.groups, self.issued_ms));
        verify_ed25519(&pk, &bytes, &sig)
    }

    /// Verify AND require the signer key to equal a pinned public key (the trust root the proxy expects).
    pub fn verify_pinned(&self, pinned_pubkey_hex: &str, now_ms: u64, max_age_ms: u64) -> bool {
        self.pubkey_hex.eq_ignore_ascii_case(pinned_pubkey_hex) && self.verify(now_ms, max_age_ms)
    }

    /// Encode for an HTTP header (base64 of the JSON).
    pub fn encode(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(serde_json::to_vec(self).unwrap_or_default())
    }

    /// Decode from a header value (base64 JSON, tolerating an `acp ` / `Bearer ` scheme prefix).
    pub fn decode(s: &str) -> Option<EgressIdentity> {
        use base64::Engine;
        let s = s.trim();
        let s = s.strip_prefix("acp ").or_else(|| s.strip_prefix("Bearer ")).unwrap_or(s).trim();
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
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


#[cfg(test)]
mod egress_identity_tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    #[test]
    fn round_trips_and_verifies() {
        let signer = Ed25519Signer::from_seed(&[3u8; 32]);
        let id = issue_identity(&signer, "triage-agent", "alice@corp", &["eng".into()], 1_000_000);
        assert!(id.verify(1_000_500, 300_000));
        let hdr = id.encode();
        let back = EgressIdentity::decode(&format!("acp {hdr}")).unwrap();
        assert_eq!(back, id);
        assert!(back.verify(1_000_500, 300_000));
    }

    #[test]
    fn rejects_tamper_expiry_future_and_wrong_pin() {
        let signer = Ed25519Signer::from_seed(&[4u8; 32]);
        let id = issue_identity(&signer, "a", "bob", &[], 1_000_000);
        let mut bad = id.clone(); bad.principal = "eve".into();
        assert!(!bad.verify(1_000_100, 300_000));
        assert!(!id.verify(1_000_000 + 300_001, 300_000));
        assert!(!id.verify(500_000, 300_000));
        assert!(!id.verify_pinned("00ff", 1_000_100, 300_000));
        assert!(id.verify_pinned(&id.pubkey_hex, 1_000_100, 300_000));
    }
}
