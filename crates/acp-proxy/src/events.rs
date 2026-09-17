//! Governance-event seam (decision D14 / F1 / F9).
//!
//! Every decision emits one canonical, redacted event that fans out to any number of sinks. v0
//! ships a JSONL file sink and an OTLP/HTTP (OpenTelemetry logs) sink; SIEM (OCSF/CEF) and
//! notifier sinks plug into the same `Sink` trait later. Events never carry raw arguments
//! (telemetry PII hygiene, gap L) -- only the verdict shape. OTel delivery is best-effort and
//! off the reactor; the evidence ledger remains the authoritative record.

use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

/// A redacted governance event.
pub struct Event<'a> {
    pub agent: &'a str,
    pub session: &'a str,
    pub tool: &'a str,
    pub verdict: &'a str,
    pub rule_id: Option<&'a str>,
    pub impact: &'a str,
    pub outcome: &'a str,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub trait Sink: Send + Sync {
    fn emit(&self, ev: &Event<'_>);
}

/// A JSONL file sink.
pub struct FileSink {
    file: Mutex<File>,
}

impl FileSink {
    pub fn open(path: &str) -> std::io::Result<FileSink> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            file: Mutex::new(file),
        })
    }
}

impl Sink for FileSink {
    fn emit(&self, ev: &Event<'_>) {
        let v = json!({
            "ts_ms": now_ms(), "type": "acp.decision",
            "agent": ev.agent, "session": ev.session,
            "tool": ev.tool, "verdict": ev.verdict, "rule_id": ev.rule_id,
            "impact": ev.impact, "outcome": ev.outcome
        });
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{v}");
            let _ = f.flush();
        }
    }
}

/// An OpenTelemetry (OTLP/HTTP JSON logs) sink. Events are posted off the reactor by a background
/// thread, so emit never blocks a decision. Delivery is best-effort (at-least-once on flush).
pub struct OtelSink {
    tx: Option<Sender<Value>>,
    handle: Option<JoinHandle<()>>,
}

impl OtelSink {
    pub fn new(endpoint: String) -> OtelSink {
        let (tx, rx) = mpsc::channel::<Value>();
        let handle = std::thread::spawn(move || {
            for record in rx {
                let envelope = json!({
                    "resourceLogs": [{
                        "resource": {"attributes": [attr("service.name", "acp-proxy")]},
                        "scopeLogs": [{"scope": {"name": "acp.governance"}, "logRecords": [record]}]
                    }]
                });
                let _ = http_post(&endpoint, &envelope.to_string());
            }
        });
        OtelSink {
            tx: Some(tx),
            handle: Some(handle),
        }
    }
}

/// A minimal, dependency-free HTTP/1.1 POST for OTLP/HTTP to a plain-http collector (the OTLP
/// default is http on :4318). https collectors are a fast-follow (needs TLS).
fn http_post(endpoint: &str, body: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("otel endpoint must be http://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(4318)),
        None => (authority, 4318u16),
    };
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    // Read (and discard) the response so the server processes the request before we close.
    let mut sink = Vec::new();
    let _ = stream.read_to_end(&mut sink);
    Ok(())
}

fn attr(key: &str, val: &str) -> Value {
    json!({"key": key, "value": {"stringValue": val}})
}

impl Sink for OtelSink {
    fn emit(&self, ev: &Event<'_>) {
        let record = json!({
            "timeUnixNano": (now_ms() as u128 * 1_000_000).to_string(),
            "severityText": "INFO",
            "body": {"stringValue": "acp.decision"},
            "attributes": [
                attr("tool", ev.tool),
                attr("verdict", ev.verdict),
                attr("outcome", ev.outcome),
                attr("impact", ev.impact),
                attr("rule_id", ev.rule_id.unwrap_or("")),
                attr("session", ev.session),
            ]
        });
        if let Some(tx) = &self.tx {
            let _ = tx.send(record); // best-effort; never blocks the decision
        }
    }
}

impl Drop for OtelSink {
    fn drop(&mut self) {
        // Close the channel so the worker drains and exits, then join (flush on shutdown).
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
