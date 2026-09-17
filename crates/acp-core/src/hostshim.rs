//! Host-shim for hosts that do not retry on step-up (decision X.5).
//!
//! ACP returns JSON-RPC error -32001 to mean "approval required, re-issue after approval". A
//! well-behaved MCP host retries; a host that does not would surface the step-up as a hard error.
//! The shim decides, for a given response, whether to wait and retry, give up gracefully, or pass
//! the response through. It is pure so the retry/backoff policy is testable without a host.

/// The JSON-RPC error code ACP uses for step-up.
pub const STEP_UP_CODE: i64 = -32001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimAction {
    /// Wait this long, then re-issue the call.
    Retry { after_ms: u64 },
    /// Step-up did not resolve within the attempt budget: surface a clear, graceful error.
    GiveUp,
    /// Not a step-up response: pass it straight through.
    PassThrough,
}

/// Decide what the shim should do. `attempt` is 0-based; `max_attempts` bounds the wait so a hold
/// that never resolves fails gracefully rather than hanging. `base_ms` grows with the attempt
/// (linear backoff); the caller folds in jitter.
pub fn handle(code: i64, attempt: u32, max_attempts: u32, base_ms: u64) -> ShimAction {
    if code != STEP_UP_CODE {
        return ShimAction::PassThrough;
    }
    if attempt >= max_attempts {
        return ShimAction::GiveUp;
    }
    ShimAction::Retry {
        after_ms: base_ms * (attempt as u64 + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_stepup_response_passes_through() {
        assert_eq!(handle(0, 0, 5, 500), ShimAction::PassThrough);
        assert_eq!(handle(-32600, 0, 5, 500), ShimAction::PassThrough);
    }

    #[test]
    fn stepup_retries_with_backoff_then_gives_up_gracefully() {
        assert_eq!(
            handle(STEP_UP_CODE, 0, 3, 500),
            ShimAction::Retry { after_ms: 500 }
        );
        assert_eq!(
            handle(STEP_UP_CODE, 1, 3, 500),
            ShimAction::Retry { after_ms: 1000 }
        );
        assert_eq!(
            handle(STEP_UP_CODE, 3, 3, 500),
            ShimAction::GiveUp,
            "bounded, no infinite wait"
        );
    }
}
