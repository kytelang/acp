//! acp-server: policy store, approval broker, evidence ledger, and reporting.
//! Skeleton: axum wiring, sqlx ledger, Slack app, cedar-policy evaluation, and maud UI
//! land in M2-M4. Policy loading uses acp-policy (YAML -> Cedar).

fn main() {
    eprintln!("acp-server (skeleton) - policy load via acp-policy M2, ledger M3, approvals M4");
    let _ = acp_core::sign::NoopSigner;
    // Prove the policy compiler is reachable from the server binary.
    if let Ok(p) = acp_policy::parse_str("version: 1\ndefault: allow\nrules: []\n") {
        eprintln!(
            "policy parsed: version {}, {} rules",
            p.version,
            p.rules.len()
        );
    }
}
