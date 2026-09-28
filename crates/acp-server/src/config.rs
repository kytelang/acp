//! Command-line configuration for the control-plane server: parse the process arguments (and a
//! few ACP_* environment variables) into one immutable Config, keeping argument handling out of main.

/// The parsed server configuration. One field per flag; owned and read-only after parsing.
pub(crate) struct Config {
    pub(crate) addr: String,
    pub(crate) approvals: Option<String>,
    pub(crate) policy_path: Option<String>,
    pub(crate) ledger: Option<String>,
    pub(crate) meta_ledger: Option<String>,
    pub(crate) registry: Option<String>,
    pub(crate) policy_store: Option<String>,
    pub(crate) break_glass_file: Option<String>,
    pub(crate) enrollment: Option<String>,
    pub(crate) store_url: Option<String>,
    pub(crate) cp_key: String,
    pub(crate) tls_ca: Option<String>,
    pub(crate) tls_cert: Option<String>,
    pub(crate) tls_key: Option<String>,
    pub(crate) break_glass_seed: Option<[u8; 32]>,
    pub(crate) oidc_jwks: Option<String>,
    pub(crate) oidc_issuer: Option<String>,
    pub(crate) oidc_audience: Option<String>,
    pub(crate) dev_auth: bool,
    pub(crate) entra_tenant: Option<String>,
    pub(crate) entra_audience: Option<String>,
    pub(crate) report_token: Option<String>,
    pub(crate) scim_users_path: Option<String>,
    pub(crate) model_scanner_url: Option<String>,
    pub(crate) model_scan_block: bool,
    pub(crate) webhook_url: Option<String>,
    pub(crate) webhook_secret: Option<String>,
    pub(crate) packs_feed_url: Option<String>,
    pub(crate) threat_feed_url: Option<String>,
    pub(crate) ticket_poll_url: Option<String>,
    pub(crate) slack_webhook_url: Option<String>,
    pub(crate) mlflow_url: Option<String>,
    pub(crate) retrieval_source: Option<String>,
    pub(crate) author_llm_url: Option<String>,
    pub(crate) author_llm_key: Option<String>,
    pub(crate) author_llm_model: Option<String>,
    pub(crate) snapshot_interval_ms: i64,
    pub(crate) snapshot_frameworks: Vec<String>,
    pub(crate) approval_sla_ms: i64,
    pub(crate) node_id: Option<String>,
    pub(crate) lease_ttl_ms: i64,
    pub(crate) entra_preflight: bool,
    pub(crate) entra_test_token: Option<String>,
}

impl Config {
    /// Parse `std::env::args()` into a Config. Exits the process (code 2) on an unknown option or a
    /// malformed value, matching the previous inline behaviour.
    pub(crate) fn from_args() -> Config {
        let args: Vec<String> = std::env::args().collect();
        let mut addr = "127.0.0.1:8787".to_string();
        let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
        let mut meta_ledger: Option<String> = None;
        let mut registry: Option<String> = None;
        let mut policy_store: Option<String> = None;
        let mut break_glass_file: Option<String> = None;
        let mut enrollment: Option<String> = None;
        let mut store_url: Option<String> = None;
        let mut cp_key = "acp-cp.key".to_string();
        let mut tls_ca: Option<String> = None;
        let mut tls_cert: Option<String> = None;
        let mut tls_key: Option<String> = None;
        let mut break_glass_seed: Option<[u8; 32]> = None;
        let mut oidc_jwks: Option<String> = None;
        let mut oidc_issuer: Option<String> = None;
        let mut oidc_audience: Option<String> = None;
        let mut dev_auth = false;
        let mut entra_tenant: Option<String> = None;
        let mut entra_audience: Option<String> = None;
        let mut report_token: Option<String> = std::env::var("ACP_REPORT_TOKEN").ok().filter(|s| !s.is_empty());
        let mut scim_users_path: Option<String> = None;
        let mut model_scanner_url: Option<String> = None;
        let mut model_scan_block = false;
        let mut webhook_url: Option<String> = None;
        let mut webhook_secret: Option<String> = None;
        let mut packs_feed_url: Option<String> = None;
        let mut threat_feed_url: Option<String> = None;
        let mut ticket_poll_url: Option<String> = None;
        let mut slack_webhook_url: Option<String> = None;
        let mut mlflow_url: Option<String> = None;
        let mut retrieval_source: Option<String> = None;
        let mut author_llm_url: Option<String> = None;
        let mut author_llm_key: Option<String> = None;
        let mut author_llm_model: Option<String> = None;
        let mut snapshot_interval_ms: i64 = 0;
        let mut snapshot_frameworks: Vec<String> = Vec::new();
        let mut approval_sla_ms: i64 = 0;
        let mut node_id: Option<String> = None;
        let mut lease_ttl_ms: i64 = 15_000;
        let mut entra_preflight = false;
        let mut entra_test_token: Option<String> = None;
        let mut it = args.iter().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--addr" => addr = it.next().cloned().unwrap_or(addr),
                "--approvals" => approvals = it.next().cloned(),
                "--policy" => policy_path = it.next().cloned(),
                "--ledger" => ledger = it.next().cloned(),
                "--meta-ledger" => meta_ledger = it.next().cloned(),
                "--registry" => registry = it.next().cloned(),
                "--policy-store" => policy_store = it.next().cloned(),
                "--enrollment" => enrollment = it.next().cloned(),
                "--store" => store_url = it.next().cloned(),
                "--report-token" => report_token = it.next().cloned(),
                "--scim-users" => scim_users_path = it.next().cloned(),
                "--model-scanner-url" => model_scanner_url = it.next().cloned(),
                "--model-scan-block" => model_scan_block = true,
                "--webhook-url" => webhook_url = it.next().cloned(),
                "--webhook-secret" => webhook_secret = it.next().cloned(),
                "--packs-feed-url" => packs_feed_url = it.next().cloned(),
                "--threat-feed-url" => threat_feed_url = it.next().cloned(),
                "--ticket-poll-url" => ticket_poll_url = it.next().cloned(),
                "--slack-webhook-url" => slack_webhook_url = it.next().cloned(),
                "--mlflow-url" => mlflow_url = it.next().cloned(),
                "--retrieval-source" => retrieval_source = it.next().cloned(),
                "--author-llm-url" => author_llm_url = it.next().cloned(),
                "--author-llm-key" => author_llm_key = it.next().cloned(),
                "--author-llm-model" => author_llm_model = it.next().cloned(),
                "--snapshot-interval-ms" => snapshot_interval_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                "--snapshot-frameworks" => snapshot_frameworks = it.next().map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default(),
                "--approval-sla-ms" => approval_sla_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
                "--node-id" => node_id = it.next().cloned(),
                "--lease-ttl-ms" => lease_ttl_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(15_000),
                "--cp-key" => { if let Some(v) = it.next() { cp_key = v.clone(); } }
                "--oidc-jwks" => oidc_jwks = it.next().cloned(),
                "--oidc-issuer" => oidc_issuer = it.next().cloned(),
                "--oidc-audience" => oidc_audience = it.next().cloned(),
                "--dev-auth" => dev_auth = true,
                "--entra-tenant" => entra_tenant = it.next().cloned(),
                "--entra-audience" => entra_audience = it.next().cloned(),
                "--entra-preflight" => entra_preflight = true,
                "--entra-test-token" => entra_test_token = it.next().cloned(),
                "--break-glass-file" => break_glass_file = it.next().cloned(),
                "--tls-ca" => tls_ca = it.next().cloned(),
                "--tls-cert" => tls_cert = it.next().cloned(),
                "--tls-key" => tls_key = it.next().cloned(),
                "--break-glass-key" => {
                    if let Some(h) = it.next() {
                        match hex::decode(acp_core::secret::resolve(h)) {
                            Ok(b) if b.len() == 32 => {
                                let mut s = [0u8; 32];
                                s.copy_from_slice(&b);
                                break_glass_seed = Some(s);
                            }
                            _ => {
                                tracing::error!("--break-glass-key must be a 32-byte hex seed");
                                std::process::exit(2);
                            }
                        }
                    }
                }
                other => {
                    tracing::warn!("unknown option '{other}'");
                    std::process::exit(2);
                }
            }
        }
        Config {
            addr, approvals, policy_path, ledger, meta_ledger, registry, policy_store, break_glass_file, enrollment, store_url, cp_key, tls_ca, tls_cert, tls_key, break_glass_seed, oidc_jwks, oidc_issuer, oidc_audience, dev_auth, entra_tenant, entra_audience, report_token, scim_users_path, model_scanner_url, model_scan_block, webhook_url, webhook_secret, packs_feed_url, threat_feed_url, ticket_poll_url, slack_webhook_url, mlflow_url, retrieval_source, author_llm_url, author_llm_key, author_llm_model, snapshot_interval_ms, snapshot_frameworks, approval_sla_ms, node_id, lease_ttl_ms, entra_preflight, entra_test_token,
        }
    }
}
