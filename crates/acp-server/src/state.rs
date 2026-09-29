//! Shared application state for the control-plane HTTP service.
use crate::auth::Auth;

pub(crate) struct AppState {
    pub(crate) approvals: Option<String>,
    pub(crate) policy: Option<(String, String)>, // (hash, yaml body)
    pub(crate) ledger: Option<String>,
    // B1: server-side liveness of enrolled proxies (dead-man's-switch).
    pub(crate) liveness: std::sync::Mutex<acp_core::liveness::GapDetector>,
    // B3: fail-open/deny spike detectors, one per event kind.
    pub(crate) spikes: std::sync::Mutex<std::collections::HashMap<String, acp_core::anomaly::SpikeDetector>>,
    // H0.7: tamper-evident self-governance meta-audit log (None if not configured).
    pub(crate) meta: Option<std::sync::Mutex<acp_core::ledger::Ledger>>,
    pub(crate) registry: Option<String>,
    pub(crate) policy_store: Option<String>,
    pub(crate) enrollment: Option<String>,
    pub(crate) store: Option<std::sync::Arc<crate::store::ControlStore>>,
    pub(crate) cp_key: String,
    pub(crate) break_glass_file: Option<String>,
    pub(crate) break_glass_seed: Option<[u8; 32]>,
    pub(crate) auth: Option<Auth>,
    // E1: shared bearer token PEPs present when reporting heartbeats/events. None = open (dev).
    pub(crate) report_token: Option<String>,
    // E1/E3: bounded ring of recent governance events reported by PEPs, for the console feed.
    pub(crate) events: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    // A5: user->role-group directory surfaced over SCIM (id, email, groups). Loaded from
    // --scim-users JSON, or a demo default in the mocked-IdP dev setup.
    pub(crate) scim_users: Vec<(String, String, Vec<String>)>,
    // C1 (HA): this replica's node id, and the current leadership view (is_leader, holder, token).
    pub(crate) node_id: String,
    pub(crate) lease_ttl_ms: i64,
    // B3: optional model/artifact admission scanner. When set, model registration calls it and
    // refuses (block) or flags (default) on a bad verdict, storing a signed AI-BOM on a clean pass.
    pub(crate) model_scanner_url: Option<String>,
    pub(crate) model_scan_block: bool,
    // G4: optional outbound event webhook (HMAC-signed) for stakeholder notifications.
    pub(crate) webhook_url: Option<String>,
    pub(crate) webhook_secret: Option<String>,
    // G5: optional feed URLs the control plane polls for signed control packs / threat packs.
    pub(crate) packs_feed_url: Option<String>,
    pub(crate) threat_feed_url: Option<String>,
    // M2: optional ticket-resolution feed the control plane polls (pull complement to /tickets/callback).
    pub(crate) ticket_poll_url: Option<String>,
    // Named connector adapters: Slack notify delivery and MLflow model import.
    pub(crate) slack_webhook_url: Option<String>,
    pub(crate) mlflow_url: Option<String>,
    pub(crate) retrieval_source: Option<String>,
    pub(crate) author_llm_url: Option<String>,
    pub(crate) author_llm_key: Option<String>,
    pub(crate) author_llm_model: Option<String>,
    // M3: periodic framework-report snapshotting + delivery.
    pub(crate) snapshot_interval_ms: i64,
    pub(crate) snapshot_frameworks: Vec<String>,
    // M4: approval SLA escalation.
    pub(crate) approval_sla_ms: i64,
    pub(crate) escalated: std::sync::Mutex<std::collections::HashSet<String>>,
    pub(crate) lease: std::sync::Mutex<(bool, String, i64)>,
    pub(crate) console_dir: Option<String>,
}

