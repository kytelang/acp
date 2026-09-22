//! acp-intercept binary: the configuration-driven forward proxy. Point an agent, IDE or browser's
//! HTTP(S) proxy at it. Phase 2: enforce block/pass on HTTPS at CONNECT (by host, no decryption) and
//! fully inspect plain-HTTP bodies with the content engine. TLS body inspection (MITM) is phase 3.

use acp_core::content::{scan_text, ContentPolicy};
use acp_core::interception::{Action, EndpointRegistry};
use acp_intercept::mitm::{self, CaSigner};
use acp_intercept::{absolute_target, connect_target, content_length, parse_request_line};
use tokio_rustls::TlsConnector;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Cfg {
    registry: EndpointRegistry,
    content: ContentPolicy,
    client: reqwest::Client,
    ledger: Option<Mutex<acp_ledger::Ledger>>,
    ca: Option<Arc<CaSigner>>,
    connector: TlsConnector,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn record(cfg: &Cfg, host: &str, action: &str, verdict: &str, rule: &Option<String>) {
    if let Some(l) = cfg.ledger.as_ref() {
        let did = format!("intercept-{}-{}", now_ms(), host);
        let rec = serde_json::json!({
            "kind": "intercept", "host": host, "action": action, "verdict": verdict,
            "rule": rule, "ts_ms": now_ms(),
        });
        if let Ok(mut g) = l.lock() {
            let _ = g.append(&did, "intercept", &rec, None);
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_obs::init("acp-intercept");
    let args: Vec<String> = std::env::args().collect();
    // Subcommand: generate a CA to install on managed devices for TLS interception.
    if args.get(1).map(String::as_str) == Some("gen-ca") {
        let cert_out = args.get(2).cloned().unwrap_or_else(|| "acp-ca.pem".into());
        let key_out = args.get(3).cloned().unwrap_or_else(|| "acp-ca-key.pem".into());
        match mitm::generate_ca() {
            Ok((cert, key)) => {
                if std::fs::write(&cert_out, cert).is_err() {
                    tracing::error!("cannot write {cert_out}");
                    return std::process::ExitCode::from(1);
                }
                if acp_core::secret::write_key_secure(&key_out, key.as_bytes()).is_err() {
                    tracing::error!("cannot write {key_out}");
                    return std::process::ExitCode::from(1);
                }
                tracing::info!("wrote CA cert {cert_out} and key {key_out} (0600). Install {cert_out} as a trusted root on managed devices.");
                return std::process::ExitCode::SUCCESS;
            }
            Err(e) => {
                tracing::error!("gen-ca failed: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    }
    let mut addr = "127.0.0.1:8890".to_string();
    let mut rules: Option<String> = None;
    let mut ledger_path: Option<String> = None;
    let mut deny_topics: Vec<String> = Vec::new();
    let mut block_secrets = false;
    let mut ca_cert: Option<String> = None;
    let mut ca_key: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => addr = it.next().cloned().unwrap_or(addr),
            "--rules" => rules = it.next().cloned(),
            "--ledger" => ledger_path = it.next().cloned(),
            "--deny-topic" => { if let Some(v) = it.next() { deny_topics.push(v.clone()); } }
            "--block-secrets" => block_secrets = true,
            "--ca-cert" => ca_cert = it.next().cloned(),
            "--ca-key" => ca_key = it.next().cloned(),
            other => { tracing::warn!("unknown option '{other}'"); return std::process::ExitCode::from(2); }
        }
    }
    let registry = match rules.as_ref().map(|p| std::fs::read_to_string(p)) {
        Some(Ok(src)) => match EndpointRegistry::from_yaml(&src) {
            Ok(r) => r,
            Err(e) => { tracing::info!("{e}"); return std::process::ExitCode::from(1); }
        },
        _ => { tracing::error!("--rules <endpoints.yaml> is required"); return std::process::ExitCode::from(2); }
    };
    let ledger = match ledger_path.as_ref() {
        Some(p) => match acp_ledger::Ledger::open(p, Box::new(acp_core::sign::Ed25519Signer::generate())) {
            Ok(l) => Some(Mutex::new(l)),
            Err(e) => { tracing::error!("cannot open ledger {p}: {e}"); return std::process::ExitCode::from(1); }
        },
        None => None,
    };
    let ca = match (ca_cert.as_ref(), ca_key.as_ref()) {
        (Some(c), Some(k)) => {
            let cert = std::fs::read_to_string(c).unwrap_or_default();
            let key = std::fs::read_to_string(k).unwrap_or_default();
            match CaSigner::load(&cert, &key) {
                Ok(s) => { tracing::info!("TLS interception ENABLED (CA {c}); body-inspecting HTTPS endpoints are decrypted"); Some(Arc::new(s)) }
                Err(e) => { tracing::error!("cannot load CA: {e}"); return std::process::ExitCode::from(1); }
            }
        }
        _ => None,
    };
    let cfg = Arc::new(Cfg {
        registry,
        content: ContentPolicy { block_injection: true, block_secrets, redact_pii: true, denied_topics: deny_topics },
        client: reqwest::Client::new(),
        ledger,
        ca,
        connector: mitm::upstream_connector(),
    });

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => { tracing::error!("cannot bind {addr}: {e}"); return std::process::ExitCode::from(1); }
    };
    tracing::info!("forward proxy on {addr}; {} rule(s)", cfg.registry.endpoints.len());
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(cfg, sock).await {
                        tracing::error!("conn error: {e}");
                    }
                });
            }
            Err(e) => tracing::error!("accept error: {e}"),
        }
    }
}

async fn read_headers(sock: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((headers, leftover));
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    Ok((String::from_utf8_lossy(&buf).to_string(), Vec::new()))
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn write_status(sock: &mut TcpStream, code: u16, reason: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await
}

async fn handle(cfg: Arc<Cfg>, mut client: TcpStream) -> std::io::Result<()> {
    let (headers, leftover) = read_headers(&mut client).await?;
    let first = headers.lines().next().unwrap_or("");
    let Some((method, target)) = parse_request_line(first) else {
        return write_status(&mut client, 400, "Bad Request", "malformed request line").await;
    };

    if method == "CONNECT" {
        let Some((host, port)) = connect_target(&target) else {
            return write_status(&mut client, 400, "Bad Request", "bad CONNECT target").await;
        };
        let decision = cfg.registry.evaluate(&host, "", port);
        if decision.action == Action::Block {
            record(&cfg, &host, "block", "deny", &decision.rule_id);
            return write_status(&mut client, 403, "Forbidden", "blocked by endpoint policy").await;
        }
        // Phase 3: if TLS interception is enabled and this host needs the body, MITM it.
        if cfg.registry.should_decrypt(&host, port) {
            if let Some(ca) = cfg.ca.clone() {
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                let cfg2 = cfg.clone();
                let host2 = host.clone();
                let decide = |path: &str| {
                    let d = cfg2.registry.evaluate(&host2, path, port);
                    (d.action == Action::Block, d.action.needs_body(), d.rule_id.clone())
                };
                let cfg3 = cfg.clone();
                let inspect = |text: &str| {
                    let cv = scan_text(&cfg3.content, text);
                    if cv.block {
                        Some(cv.findings.iter().map(|f| f.kind.clone()).collect::<Vec<_>>().join(", "))
                    } else {
                        None
                    }
                };
                let outcome = mitm::intercept(&ca, &cfg.connector, client, &host, port, decide, inspect).await;
                let verdict = match outcome {
                    mitm::MitmOutcome::Blocked(_) => "block",
                    mitm::MitmOutcome::Forwarded => "inspect-allow",
                    mitm::MitmOutcome::HandshakeFailed(_) => "pinning-or-handshake-failed",
                    mitm::MitmOutcome::UpstreamFailed(_) => "upstream-failed",
                };
                record(&cfg, &host, "mitm", verdict, &decision.rule_id);
                return Ok(());
            }
        }
        // Phase 2: no MITM. A body-inspecting HTTPS host is tunnelled and flagged (inspection needs
        // phase 3). block/pass are fully enforced here.
        let verdict = if cfg.registry.should_decrypt(&host, port) { "tunnel-uninspected" } else { "tunnel" };
        record(&cfg, &host, "connect", verdict, &decision.rule_id);
        let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
            Ok(u) => u,
            Err(_) => return write_status(&mut client, 502, "Bad Gateway", "upstream unreachable").await,
        };
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    // Plain-HTTP absolute-form (e.g. "POST http://host/path HTTP/1.1").
    let Some((host, path, port)) = absolute_target(&target) else {
        return write_status(&mut client, 400, "Bad Request", "only CONNECT or absolute-form http:// supported").await;
    };
    let want = content_length(&headers);
    let mut body = leftover;
    while body.len() < want {
        let mut tmp = [0u8; 4096];
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    let decision = cfg.registry.evaluate(&host, &path, port);
    if decision.action == Action::Block {
        record(&cfg, &host, "block", "deny", &decision.rule_id);
        return write_status(&mut client, 403, "Forbidden", "blocked by endpoint policy").await;
    }
    if decision.action.needs_body() {
        let text = String::from_utf8_lossy(&body);
        let cv = scan_text(&cfg.content, &text);
        if cv.block {
            let kinds: Vec<String> = cv.findings.iter().map(|f| f.kind.clone()).collect();
            record(&cfg, &host, "inspect", "deny", &decision.rule_id);
            return write_status(&mut client, 403, "Forbidden", &format!("blocked by content firewall: {}", kinds.join(", "))).await;
        }
    }
    // Forward to origin.
    record(&cfg, &host, &format!("{:?}", decision.action), "allow", &decision.rule_id);
    let url = format!("http://{host}:{port}{path}");
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut req = cfg.client.request(m, &url);
    for line in headers.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("proxy-connection") || k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("content-length") {
                continue;
            }
            req = req.header(k, v.trim());
        }
    }
    if !body.is_empty() {
        req = req.body(body);
    }
    match req.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let bytes = resp.bytes().await.unwrap_or_default();
            let head = format!("HTTP/1.1 {code} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
            client.write_all(head.as_bytes()).await?;
            client.write_all(&bytes).await?;
            Ok(())
        }
        Err(_) => write_status(&mut client, 502, "Bad Gateway", "origin unreachable").await,
    }
}
