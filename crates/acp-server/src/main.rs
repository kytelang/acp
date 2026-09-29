//! acp-server: the control-plane HTTP service (v1.1 seed, single-tenant).
//!
//! Serves the web approval inbox (M4.3), the current policy endpoint (M2.2), a read-only
//! evidence-verify endpoint, and a basic governance report. HTML is rendered with `maud`, which
//! auto-escapes, so attacker-controlled content in the inbox cannot inject markup (M4.5).
//! Multi-tenant Postgres, per-tenant keys, and SSO are the next layer (v1.1.1-1.1.3 / H1).

mod store;
mod mtls;
use std::sync::Arc;


mod state;
mod common;
mod handlers;
mod router;
mod serve;
mod auth;
mod config;
mod preflight;
mod tasks;
use state::AppState;
use config::Config;
use common::*;

/// C1: restore persisted liveness heartbeats and spike-event timestamps from the shared store into
/// the in-memory detectors, so a restart does not lose the dead-man's-switch or the alert state.

#[tokio::main]
async fn main() {
    acp_core::obs::init("acp-server");
    let Config { addr, approvals, policy_path, ledger, meta_ledger, registry, policy_store, break_glass_file, enrollment, store_url, cp_key, tls_ca, tls_cert, tls_key, break_glass_seed, oidc_jwks, oidc_issuer, oidc_audience, dev_auth, entra_tenant, entra_audience, report_token, scim_users_path, model_scanner_url, model_scan_block, webhook_url, webhook_secret, packs_feed_url, threat_feed_url, ticket_poll_url, slack_webhook_url, mlflow_url, retrieval_source, author_llm_url, author_llm_key, author_llm_model, snapshot_interval_ms, snapshot_frameworks, approval_sla_ms, node_id, lease_ttl_ms, entra_preflight, entra_test_token, console_dir, break_glass_key: _ } = crate::config::Config::from_args();

    // R7: real-Entra cutover preflight. Verifies the identity setup without starting the full server:
    // fetch the JWKS from the derived Entra/OIDC endpoint, confirm it parses and has keys, and (if a
    // sample token is given) run the full verification and print each claim check and the effective
    // capabilities. Exits 0 on success, 1 on any failure. Gated only on a customer tenant + token.
    if entra_preflight {
        crate::preflight::run(&entra_tenant, &entra_audience, &oidc_jwks, &oidc_issuer, &oidc_audience, &entra_test_token).await;
    }

    let policy = match policy_path {
        Some(p) => match std::fs::read_to_string(&p).ok().and_then(|src| {
            acp_core::policy::PolicyEngine::from_yaml(&src)
                .ok()
                .map(|e| (e.hash().to_string(), src))
        }) {
            Some(v) => Some(v),
            None => {
                tracing::error!("could not load policy {p}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    // H0.7: a tamper-evident meta-audit ledger for admin actions (policy/key/RBAC changes).
    let meta = meta_ledger.and_then(|path| {
        let key_path = format!("{path}.key");
        let signer: Box<dyn acp_core::sign::Signer + Send> = match std::fs::read(&key_path) {
            Ok(b) if b.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b);
                Box::new(acp_core::sign::Ed25519Signer::from_seed(&s))
            }
            _ => {
                let s = acp_core::sign::Ed25519Signer::generate();
                let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
                Box::new(s)
            }
        };
        // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE).
        let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_core::hsm::signer_from_env() {
            Some(Ok(hsm)) => { tracing::info!("meta-ledger signing with a PKCS#11 HSM"); hsm }
            Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
            None => signer,
        };
        match acp_core::ledger::Ledger::open(&path, signer) {
            Ok(l) => Some(std::sync::Mutex::new(l)),
            Err(e) => {
                tracing::error!("could not open meta-ledger {path}: {e}");
                None
            }
        }
    });

    let auth = crate::auth::build(dev_auth, &entra_tenant, &entra_audience, &oidc_jwks, &oidc_issuer, &oidc_audience).await;
    // Config-driven control-plane store (identity, endpoints; GRC later). The backend is chosen by
    // the --store URL (sqlite / postgres / mysql). Fail closed if it was requested but cannot connect.
    let store = match store_url {
        Some(u) => match crate::store::ControlStore::connect(&u).await {
            Ok(s) => {
                tracing::info!("control-plane store connected");
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::error!("cannot connect --store: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
        liveness: std::sync::Mutex::new(acp_core::liveness::GapDetector::new()),
        spikes: std::sync::Mutex::new(std::collections::HashMap::new()),
        meta,
        registry,
        policy_store,
        enrollment,
        store,
        cp_key,
        break_glass_file,
        break_glass_seed,
        auth,
        report_token,
        events: std::sync::Mutex::new(std::collections::VecDeque::new()),
        scim_users: load_scim_users(scim_users_path.as_deref()),
        node_id: node_id.unwrap_or_else(|| format!("node-{}", rand_hex(6))),
        lease_ttl_ms,
        model_scanner_url,
        model_scan_block,
        webhook_url,
        webhook_secret,
        packs_feed_url,
        threat_feed_url,
        ticket_poll_url,
        slack_webhook_url,
        mlflow_url,
        retrieval_source,
        author_llm_url,
        author_llm_key,
        author_llm_model,
        snapshot_interval_ms,
        snapshot_frameworks,
        approval_sla_ms,
        escalated: std::sync::Mutex::new(std::collections::HashSet::new()),
        lease: std::sync::Mutex::new((false, String::new(), 0)),
        console_dir,
    });
    crate::tasks::spawn_background(&state).await;
    let app = crate::router::build_router(state);
    let tls = match (tls_ca, tls_cert, tls_key) {
        (Some(ca), Some(cert), Some(key)) => Some((ca, cert, key)),
        _ => None,
    };
    crate::serve::run(app, &addr, tls).await;
}
