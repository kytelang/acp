//! Structured logging init shared by the long-running ACP services (P1-1).
//!
//! One call at the top of `main` gives every service leveled, timestamped logs that are filterable
//! and machine-parseable. Configuration is by environment, so operators tune it without a redeploy:
//!   - `ACP_LOG` or `RUST_LOG`: the level filter (e.g. `info`, `warn`, `acp_proxy=debug`). Default `info`.
//!   - `ACP_LOG_FORMAT=json`: emit one JSON object per line (for a log pipeline). Default: compact text.
//! Idempotent: a second call is a no-op, so tests and embedded uses do not panic.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialise the global tracing subscriber for `service`. Safe to call more than once.
pub fn init(service: &str) {
    let filter = std::env::var("ACP_LOG")
        .ok()
        .and_then(|v| EnvFilter::try_new(v).ok())
        .or_else(|| EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let json = std::env::var("ACP_LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    // `try_init` returns Err if a subscriber is already set; ignore so this is idempotent.
    let _ = if json {
        fmt()
            .with_env_filter(filter)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .try_init()
    } else {
        fmt().with_env_filter(filter).compact().try_init()
    };
    tracing::info!(service, "logging initialised");
}
