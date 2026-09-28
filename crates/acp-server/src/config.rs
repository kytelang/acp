//! Configuration for the control-plane server.
//!
//! Settings come from a `server.yaml` file (auto-discovered in the current working directory, or
//! pointed at with `--config <path>`) and from command-line flags, with flags overriding the file.
//! With no file and no flags the built-in defaults run the local demo. Keeping all of this here keeps
//! argument and file handling out of `main`.

use serde::Deserialize;

fn default_addr() -> String {
    "127.0.0.1:8787".to_string()
}
fn default_cp_key() -> String {
    "acp-cp.key".to_string()
}
fn default_lease_ttl() -> i64 {
    15_000
}
fn default_report_token() -> Option<String> {
    std::env::var("ACP_REPORT_TOKEN").ok().filter(|s| !s.is_empty())
}

/// The resolved server configuration. One field per flag / YAML key. `server.yaml` keys are the field
/// names below (snake_case); every key is optional and falls back to the default shown.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
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
    /// A 32-byte break-glass seed as hex (or an `env:VAR` / `file:PATH` secret reference). Decoded
    /// into `break_glass_seed` after parsing.
    pub(crate) break_glass_key: Option<String>,
    #[serde(skip)]
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
    #[serde(skip)]
    pub(crate) entra_preflight: bool,
    pub(crate) entra_test_token: Option<String>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            addr: default_addr(),
            approvals: None,
            policy_path: None,
            ledger: None,
            meta_ledger: None,
            registry: None,
            policy_store: None,
            break_glass_file: None,
            enrollment: None,
            store_url: None,
            cp_key: default_cp_key(),
            tls_ca: None,
            tls_cert: None,
            tls_key: None,
            break_glass_key: None,
            break_glass_seed: None,
            oidc_jwks: None,
            oidc_issuer: None,
            oidc_audience: None,
            dev_auth: false,
            entra_tenant: None,
            entra_audience: None,
            report_token: default_report_token(),
            scim_users_path: None,
            model_scanner_url: None,
            model_scan_block: false,
            webhook_url: None,
            webhook_secret: None,
            packs_feed_url: None,
            threat_feed_url: None,
            ticket_poll_url: None,
            slack_webhook_url: None,
            mlflow_url: None,
            retrieval_source: None,
            author_llm_url: None,
            author_llm_key: None,
            author_llm_model: None,
            snapshot_interval_ms: 0,
            snapshot_frameworks: Vec::new(),
            approval_sla_ms: 0,
            node_id: None,
            lease_ttl_ms: default_lease_ttl(),
            entra_preflight: false,
            entra_test_token: None,
        }
    }
}

impl Config {
    /// Load a `server.yaml` file. Exits (code 2) if it cannot be read or parsed.
    fn from_yaml(path: &str) -> Config {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("config: cannot read {path}: {e}");
                std::process::exit(2);
            }
        };
        match serde_yaml::from_str::<Config>(&text) {
            Ok(c) => {
                tracing::info!("loaded configuration from {path}");
                c
            }
            Err(e) => {
                eprintln!("config: invalid {path}: {e}");
                std::process::exit(2);
            }
        }
    }

    /// Resolve the effective configuration: start from `server.yaml` (an explicit `--config <path>`,
    /// else `./server.yaml` if present, else built-in defaults), then apply command-line flags on top
    /// so a flag always overrides the file. Exits (code 2) on an unknown option or a malformed value.
    pub(crate) fn from_args() -> Config {
        let args: Vec<String> = std::env::args().collect();

        // Find an explicit --config, else auto-discover ./server.yaml in the working directory.
        let mut cfg_path: Option<String> = None;
        {
            let mut it = args.iter().skip(1);
            while let Some(a) = it.next() {
                if a == "--config" {
                    cfg_path = it.next().cloned();
                }
            }
        }
        let path = cfg_path.or_else(|| {
            let p = "server.yaml";
            std::path::Path::new(p).exists().then(|| p.to_string())
        });
        let mut c = match path {
            Some(p) => Config::from_yaml(&p),
            None => Config::default(),
        };

        // Command-line flags override the file.
        let mut it = args.iter().skip(1);
        while let Some(a) = it.next() {
            match a.as_str() {
                "--config" => {
                    it.next();
                }
                "--addr" => {
                    if let Some(v) = it.next() {
                        c.addr = v.clone();
                    }
                }
                "--approvals" => c.approvals = it.next().cloned(),
                "--policy" => c.policy_path = it.next().cloned(),
                "--ledger" => c.ledger = it.next().cloned(),
                "--meta-ledger" => c.meta_ledger = it.next().cloned(),
                "--registry" => c.registry = it.next().cloned(),
                "--policy-store" => c.policy_store = it.next().cloned(),
                "--enrollment" => c.enrollment = it.next().cloned(),
                "--store" => c.store_url = it.next().cloned(),
                "--report-token" => c.report_token = it.next().cloned(),
                "--scim-users" => c.scim_users_path = it.next().cloned(),
                "--model-scanner-url" => c.model_scanner_url = it.next().cloned(),
                "--model-scan-block" => c.model_scan_block = true,
                "--webhook-url" => c.webhook_url = it.next().cloned(),
                "--webhook-secret" => c.webhook_secret = it.next().cloned(),
                "--packs-feed-url" => c.packs_feed_url = it.next().cloned(),
                "--threat-feed-url" => c.threat_feed_url = it.next().cloned(),
                "--ticket-poll-url" => c.ticket_poll_url = it.next().cloned(),
                "--slack-webhook-url" => c.slack_webhook_url = it.next().cloned(),
                "--mlflow-url" => c.mlflow_url = it.next().cloned(),
                "--retrieval-source" => c.retrieval_source = it.next().cloned(),
                "--author-llm-url" => c.author_llm_url = it.next().cloned(),
                "--author-llm-key" => c.author_llm_key = it.next().cloned(),
                "--author-llm-model" => c.author_llm_model = it.next().cloned(),
                "--snapshot-interval-ms" => {
                    c.snapshot_interval_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(c.snapshot_interval_ms)
                }
                "--snapshot-frameworks" => {
                    if let Some(v) = it.next() {
                        c.snapshot_frameworks = v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                    }
                }
                "--approval-sla-ms" => c.approval_sla_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(c.approval_sla_ms),
                "--node-id" => c.node_id = it.next().cloned(),
                "--lease-ttl-ms" => c.lease_ttl_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(c.lease_ttl_ms),
                "--cp-key" => {
                    if let Some(v) = it.next() {
                        c.cp_key = v.clone();
                    }
                }
                "--oidc-jwks" => c.oidc_jwks = it.next().cloned(),
                "--oidc-issuer" => c.oidc_issuer = it.next().cloned(),
                "--oidc-audience" => c.oidc_audience = it.next().cloned(),
                "--dev-auth" => c.dev_auth = true,
                "--entra-tenant" => c.entra_tenant = it.next().cloned(),
                "--entra-audience" => c.entra_audience = it.next().cloned(),
                "--entra-preflight" => c.entra_preflight = true,
                "--entra-test-token" => c.entra_test_token = it.next().cloned(),
                "--break-glass-file" => c.break_glass_file = it.next().cloned(),
                "--tls-ca" => c.tls_ca = it.next().cloned(),
                "--tls-cert" => c.tls_cert = it.next().cloned(),
                "--tls-key" => c.tls_key = it.next().cloned(),
                "--break-glass-key" => c.break_glass_key = it.next().cloned(),
                other => {
                    tracing::warn!("unknown option '{other}'");
                    std::process::exit(2);
                }
            }
        }

        // Decode the break-glass seed (a 32-byte hex value, or an env:/file: secret reference) once,
        // from either the YAML key or the --break-glass-key flag.
        if let Some(h) = &c.break_glass_key {
            match hex::decode(acp_core::secret::resolve(h)) {
                Ok(b) if b.len() == 32 => {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&b);
                    c.break_glass_seed = Some(s);
                }
                _ => {
                    tracing::error!("break-glass key must be a 32-byte hex seed");
                    std::process::exit(2);
                }
            }
        }

        c
    }
}
