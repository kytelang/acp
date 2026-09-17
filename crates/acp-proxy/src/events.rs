//! Governance-event seam (decision D14).
//!
//! Every decision emits one canonical, redacted event. v0 ships a file (JSONL) sink; SIEM
//! (OCSF/CEF), OpenTelemetry, and notifier sinks plug into this same seam later. Events never
//! carry raw arguments (telemetry PII hygiene, gap L) -- only the args hash and the verdict.

use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct EventSink {
    file: File,
}

impl EventSink {
    pub fn open(path: &str) -> std::io::Result<EventSink> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(EventSink { file })
    }

    /// Emit one redacted governance event. Best-effort: a sink error never blocks a decision.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &mut self,
        agent: &str,
        session: &str,
        tool: &str,
        verdict: &str,
        rule_id: Option<&str>,
        impact: &str,
        outcome: &str,
    ) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let ev = json!({
            "ts_ms": ts, "type": "acp.decision",
            "agent": agent, "session": session,
            "tool": tool, "verdict": verdict, "rule_id": rule_id, "impact": impact,
            "outcome": outcome
        });
        let _ = writeln!(self.file, "{ev}");
        let _ = self.file.flush();
    }
}
