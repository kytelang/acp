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
    http_post_auth(endpoint, body, None, 4318)
}

/// A minimal, dependency-free HTTP/1.1 POST with an optional bearer token, used by both the OTLP
/// sink and the control-plane reporting sink. http:// only (https is a fast-follow, matching OTLP).
fn http_post_auth(endpoint: &str, body: &str, token: Option<&str>, default_port: u16) -> std::io::Result<()> {
    use std::io::Write as _;
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::other("report/otel endpoint must be http://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(default_port)),
        None => (authority, default_port),
    };
    use std::io::Read as _;
    let mut stream = std::net::TcpStream::connect((host, port))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut sink = Vec::new();
    let _ = stream.read_to_end(&mut sink);
    Ok(())
}

/// The central evidence reporter (gap E2): pushes each decision record to `<base>/evidence/ingest`
/// so the control plane can mirror the whole fleet's decisions into a re-verifiable central store.
/// Off the decision path (background thread); the server dedups by decision_id.
pub struct EvidenceReporter {
    tx: Option<Sender<Value>>,
    handle: Option<JoinHandle<()>>,
}

impl EvidenceReporter {
    pub fn new(base: String, pep: String, token: Option<String>) -> EvidenceReporter {
        let (tx, rx) = mpsc::channel::<Value>();
        let base = base.trim_end_matches('/').to_string();
        let handle = std::thread::spawn(move || {
            for rec in rx {
                let envelope = json!({"pep": pep, "records": [rec]});
                let url = format!("{base}/evidence/ingest");
                let _ = http_post_auth(&url, &envelope.to_string(), token.as_deref(), 8787);
            }
        });
        EvidenceReporter { tx: Some(tx), handle: Some(handle) }
    }
    pub fn push(&self, v: Value) {
        if let Some(tx) = &self.tx { let _ = tx.send(v); }
    }
}

impl Drop for EvidenceReporter {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

/// The control-plane approval reporter (gap F1): a step-up hold raised in the field is POSTed to
/// `<base>/approvals/register` so it appears in the console Approvals inbox and can be resolved
/// centrally. Off the decision path (background thread); registration is idempotent server-side.
pub struct ApprovalReporter {
    tx: Option<Sender<Value>>,
    handle: Option<JoinHandle<()>>,
}

impl ApprovalReporter {
    pub fn new(base: String, token: Option<String>) -> ApprovalReporter {
        let (tx, rx) = mpsc::channel::<Value>();
        let base = base.trim_end_matches('/').to_string();
        let handle = std::thread::spawn(move || {
            for record in rx {
                let url = format!("{base}/approvals/register");
                let _ = http_post_auth(&url, &record.to_string(), token.as_deref(), 8787);
            }
        });
        ApprovalReporter { tx: Some(tx), handle: Some(handle) }
    }
    pub fn register(&self, v: Value) {
        if let Some(tx) = &self.tx { let _ = tx.send(v); }
    }
}

impl Drop for ApprovalReporter {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

/// The control-plane reporting sink (gap E1/E3): each non-allow decision is posted to
/// `POST <base>/event/<verdict>` so the console can show the violation/deny stream and the spike
/// detector can page. Posting happens on a background thread; emit never blocks a decision.
pub struct ServerSink {
    tx: Option<Sender<Value>>,
    handle: Option<JoinHandle<()>>,
    proxy_id: String,
}

impl ServerSink {
    pub fn new(base: String, proxy_id: String, token: Option<String>) -> ServerSink {
        let (tx, rx) = mpsc::channel::<Value>();
        let base = base.trim_end_matches('/').to_string();
        let handle = std::thread::spawn(move || {
            for record in rx {
                let kind = record
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .unwrap_or("event")
                    .to_string();
                let url = format!("{base}/event/{kind}");
                let _ = http_post_auth(&url, &record.to_string(), token.as_deref(), 8787);
            }
        });
        ServerSink { tx: Some(tx), handle: Some(handle), proxy_id }
    }
}

impl Sink for ServerSink {
    fn emit(&self, ev: &Event<'_>) {
        // Only non-allow decisions are reported: denies, step-ups and shadow would-blocks are the
        // violation stream the console cares about. Allow-volume metrics are a separate rollup (F8).
        if ev.verdict == "allow" {
            return;
        }
        let record = json!({
            "kind": ev.verdict, "ts_ms": now_ms(), "proxy": self.proxy_id,
            "agent": ev.agent, "session": ev.session, "tool": ev.tool,
            "verdict": ev.verdict, "rule_id": ev.rule_id, "impact": ev.impact, "outcome": ev.outcome,
        });
        if let Some(tx) = &self.tx {
            let _ = tx.send(record); // best-effort; never blocks the decision
        }
    }
}

impl Drop for ServerSink {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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

/// Severity 0-10 for a verdict (CEF/OCSF convention).
fn severity(verdict: &str) -> u8 {
    match verdict {
        "deny" => 8,
        "step_up" => 6,
        "shadow" => 3,
        _ => 2,
    }
}

fn cef_escape_header(s: &str) -> String {
    s.replace('\\', "\\\\").replace('|', "\\|")
}
fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], " ")
}

/// A CEF (ArcSight Common Event Format) file sink for direct SIEM ingestion. Redacted: no args.
pub struct CefSink {
    file: Mutex<File>,
}
impl CefSink {
    pub fn open(path: &str) -> std::io::Result<CefSink> {
        Ok(CefSink {
            file: Mutex::new(OpenOptions::new().create(true).append(true).open(path)?),
        })
    }
}
/// The CEF line for an event, shared by the file and syslog sinks. Redacted: never carries args.
pub fn cef_line(ev: &Event<'_>) -> String {
    format!(
        "CEF:0|ACP|acp-proxy|1.0|{}|AI action {}|{}|act={} cs1={} cs1Label=tool cs2={} cs2Label=rule cs3={} cs3Label=impact suser={}",
        cef_escape_header(ev.verdict),
        cef_escape_header(ev.outcome),
        severity(ev.verdict),
        cef_escape_ext(ev.outcome),
        cef_escape_ext(ev.tool),
        cef_escape_ext(ev.rule_id.unwrap_or("")),
        cef_escape_ext(ev.impact),
        cef_escape_ext(ev.session),
    )
}

impl Sink for CefSink {
    fn emit(&self, ev: &Event<'_>) {
        let line = cef_line(ev);
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }
}

/// A syslog sink: sends each event as a CEF message over UDP to a SIEM collector (host:port). This
/// is direct network delivery, no file to tail. Fire-and-forget so it never blocks enforcement; a
/// dropped datagram is acceptable for the audit stream (the tamper-evident ledger is the source of
/// truth, this is the real-time feed). PRI 134 = local0.info.
pub struct SyslogSink {
    sock: std::net::UdpSocket,
    target: String,
}
impl SyslogSink {
    pub fn open(target: &str) -> std::io::Result<SyslogSink> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        Ok(SyslogSink { sock, target: target.to_string() })
    }
}
impl Sink for SyslogSink {
    fn emit(&self, ev: &Event<'_>) {
        let msg = format!("<134>{}", cef_line(ev));
        let _ = self.sock.send_to(msg.as_bytes(), &self.target);
    }
}

/// An OCSF (Open Cybersecurity Schema Framework) JSONL file sink. Minimal Application Activity
/// shape; redacted (no raw arguments).
pub struct OcsfSink {
    file: Mutex<File>,
}
impl OcsfSink {
    pub fn open(path: &str) -> std::io::Result<OcsfSink> {
        Ok(OcsfSink {
            file: Mutex::new(OpenOptions::new().create(true).append(true).open(path)?),
        })
    }
}
impl Sink for OcsfSink {
    fn emit(&self, ev: &Event<'_>) {
        let v = json!({
            "class_uid": 6003,                 // Application Activity
            "category_uid": 6,
            "activity_name": ev.outcome,
            "severity_id": (severity(ev.verdict) / 3).max(1),
            "time": now_ms(),
            "metadata": {"product": {"name": "acp-proxy", "vendor_name": "ACP"}, "version": "1.4.0"},
            "status": if ev.verdict == "allow" { "Success" } else { "Other" },
            "unmapped": {"tool": ev.tool, "verdict": ev.verdict, "rule_id": ev.rule_id,
                         "impact": ev.impact, "session": ev.session}
        });
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{v}");
            let _ = f.flush();
        }
    }
}

#[cfg(test)]
mod syslog_tests {
    use super::*;

    #[test]
    fn syslog_sink_delivers_a_cef_line_over_udp() {
        // Stand up a UDP listener, point the sink at it, emit, and read the datagram back.
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        listener.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let sink = SyslogSink::open(&addr).unwrap();
        let ev = Event {
            agent: "acp-client",
            tool: "charge_card",
            verdict: "deny",
            rule_id: Some("cap-charge"),
            impact: "high",
            outcome: "denied",
            session: "sess-1",
        };
        sink.emit(&ev);
        let mut buf = [0u8; 1024];
        let n = listener.recv(&mut buf).unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.starts_with("<134>CEF:0|ACP|acp-proxy|1.0|deny|"), "got: {got}");
        assert!(got.contains("cs1=charge_card"));
    }
}
