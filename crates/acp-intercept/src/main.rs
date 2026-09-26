//! acp-intercept binary: the configuration-driven forward proxy. Point an agent, IDE or browser's
//! HTTP(S) proxy at it. Phase 2: enforce block/pass on HTTPS at CONNECT (by host, no decryption) and
//! fully inspect plain-HTTP bodies with the content engine. TLS body inspection (MITM) is phase 3.

use acp_core::content::{scan_text, ContentPolicy};
use acp_core::interception::{Action, EndpointRegistry};
use acp_intercept::mitm::{self, CaSigner};
use acp_intercept::{absolute_target, connect_target, content_length, parse_request_line};
use tokio_rustls::TlsConnector;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Cfg {
    registry: RwLock<EndpointRegistry>,
    // A18: block dials to loopback/private/link-local/cloud-metadata (SSRF) unless explicitly allowed.
    allow_internal: bool,
    // A10: active break-glass grant (lockdown_all blocks all egress). Refreshed from the grant file.
    bg: RwLock<Option<acp_core::breakglass::BreakGlass>>,
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

/// Load and verify the break-glass grant file into a live grant (None when absent/invalid). With a
/// pinned key the grant must carry a valid signature by it (A10 / fail-closed on tamper).
fn load_grant(path: &str, pinned: Option<&[u8]>) -> Option<acp_core::breakglass::BreakGlass> {
    let src = std::fs::read_to_string(path).ok()?;
    let gf: acp_core::breakglass::GrantFile = serde_json::from_str(&src).ok()?;
    if !gf.verify(pinned) { return None; }
    gf.to_break_glass().map(|(bg, _actor)| bg)
}

/// True if an active break-glass grant should block egress to `host`. lockdown_all denies (scope
/// permitting); disable_enforce/emergency_bypass do not block interception traffic.
fn bg_blocks(cfg: &Cfg, host: &str) -> bool {
    let g = cfg.bg.read().unwrap();
    match g.as_ref() {
        Some(bg) if bg.active(now_ms()) && bg.mode == acp_core::breakglass::Mode::LockdownAll => {
            bg.scope.matches("", host, "")
        }
        _ => false,
    }
}

/// Fetch the interception rule registry from the control plane (GET <base>/intercept/rules). The
/// registry is derived server-side from the endpoints operators enrol via the console, so the
/// interceptor always governs the current set without editing a file on each workstation.
async fn fetch_registry(client: &reqwest::Client, base: &str) -> Result<EndpointRegistry, String> {
    let url = format!("{}/intercept/rules", base.trim_end_matches('/'));
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("control plane returned {}", resp.status()));
    }
    resp.json::<EndpointRegistry>().await.map_err(|e| e.to_string())
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
    let mut registry_url: Option<String> = None;
    let mut refresh_secs: u64 = 30;
    let mut ledger_path: Option<String> = None;
    let mut deny_topics: Vec<String> = Vec::new();
    let mut block_secrets = false;
    let mut ca_cert: Option<String> = None;
    let mut ca_key: Option<String> = None;
    let mut allow_internal = false;
    let mut bg_path: Option<String> = None;
    let mut bg_key_hex: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => addr = it.next().cloned().unwrap_or(addr),
            "--rules" => rules = it.next().cloned(),
            "--registry-url" => registry_url = it.next().cloned(),
            "--refresh-secs" => { if let Some(v) = it.next() { refresh_secs = v.parse().unwrap_or(30); } }
            "--ledger" => ledger_path = it.next().cloned(),
            "--deny-topic" => { if let Some(v) = it.next() { deny_topics.push(v.clone()); } }
            "--block-secrets" => block_secrets = true,
            "--ca-cert" => ca_cert = it.next().cloned(),
            "--ca-key" => ca_key = it.next().cloned(),
            "--allow-internal-egress" => allow_internal = true,
            "--break-glass-file" => bg_path = it.next().cloned(),
            "--break-glass-key" => bg_key_hex = it.next().cloned(),
            other => { tracing::warn!("unknown option '{other}'"); return std::process::ExitCode::from(2); }
        }
    }
    // The interception rules come from the control plane (--registry-url), derived from the
    // endpoints operators enrol via the console. --rules is the offline fallback / air-gapped source.
    let http = reqwest::Client::new();
    let load_file = || match rules.as_ref().map(|p| std::fs::read_to_string(p)) {
        Some(Ok(src)) => EndpointRegistry::from_yaml(&src).map_err(|e| e.to_string()),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("no --rules file".to_string()),
    };
    let registry = if let Some(base) = registry_url.as_ref() {
        match fetch_registry(&http, base).await {
            Ok(r) => { tracing::info!("fetched {} rule(s) from {base}", r.endpoints.len()); r }
            Err(fe) => match load_file() {
                Ok(r) => { tracing::warn!("registry fetch from {base} failed ({fe}); using --rules fallback"); r }
                Err(_) => { tracing::error!("cannot fetch rules from {base}: {fe}, and no --rules fallback"); return std::process::ExitCode::from(1); }
            },
        }
    } else {
        match load_file() {
            Ok(r) => r,
            Err(e) => { tracing::error!("--registry-url <server> or --rules <endpoints.yaml> is required ({e})"); return std::process::ExitCode::from(2); }
        }
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
    let bg_key: Option<Vec<u8>> = bg_key_hex.as_ref().and_then(|h| hex::decode(acp_core::secret::resolve(h)).ok());
    let bg_initial = bg_path.as_ref().and_then(|p| load_grant(p, bg_key.as_deref()));
    let cfg = Arc::new(Cfg {
        registry: RwLock::new(registry),
        allow_internal,
        bg: RwLock::new(bg_initial),
        content: ContentPolicy { block_injection: true, block_secrets, redact_pii: true, denied_topics: deny_topics },
        client: http.clone(),
        ledger,
        ca,
        connector: mitm::upstream_connector(),
    });

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => { tracing::error!("cannot bind {addr}: {e}"); return std::process::ExitCode::from(1); }
    };
    tracing::info!("forward proxy on {addr}; {} rule(s)", cfg.registry.read().unwrap().endpoints.len());
    // A10: refresh the break-glass grant so a lockdown engaged on the control plane takes effect here.
    if let Some(p) = bg_path.clone() {
        let cfg_bg = cfg.clone();
        let key = bg_key.clone();
        tracing::info!("break-glass grant watched at {p}");
        tokio::spawn(async move {
            loop {
                let g = load_grant(&p, key.as_deref());
                if let Ok(mut w) = cfg_bg.bg.write() { *w = g; }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }
    // Poll the control plane so newly enrolled or re-dispositioned endpoints take effect without a restart.
    if let Some(base) = registry_url.clone() {
        let cfg_r = cfg.clone();
        let http_r = http.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(refresh_secs)).await;
                match fetch_registry(&http_r, &base).await {
                    Ok(r) => {
                        let n = r.endpoints.len();
                        if let Ok(mut g) = cfg_r.registry.write() { *g = r; }
                        tracing::debug!("refreshed {n} rule(s) from {base}");
                    }
                    Err(e) => tracing::warn!("registry refresh failed: {e}"),
                }
            }
        });
    }
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
        if !cfg.allow_internal && acp_core::egress::is_internal_target(&host) {
            record(&cfg, &host, "ssrf-block", "deny", &None);
            return write_status(&mut client, 403, "Forbidden", "SSRF: internal target blocked").await;
        }
        if bg_blocks(&cfg, &host) {
            record(&cfg, &host, "break-glass", "deny", &None);
            return write_status(&mut client, 403, "Forbidden", "blocked by break-glass lockdown").await;
        }
        let decision = { cfg.registry.read().unwrap().evaluate(&host, "", port) };
        if decision.action == Action::Block {
            record(&cfg, &host, "block", "deny", &decision.rule_id);
            return write_status(&mut client, 403, "Forbidden", "blocked by endpoint policy").await;
        }
        // Phase 3: if TLS interception is enabled and this host needs the body, MITM it.
        if { cfg.registry.read().unwrap().should_decrypt(&host, port) } {
            if let Some(ca) = cfg.ca.clone() {
                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                let cfg2 = cfg.clone();
                let host2 = host.clone();
                let decide = |path: &str| {
                    let d = { cfg2.registry.read().unwrap().evaluate(&host2, path, port) };
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
        let verdict = if { cfg.registry.read().unwrap().should_decrypt(&host, port) } { "tunnel-uninspected" } else { "tunnel" };
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
    if !cfg.allow_internal && acp_core::egress::is_internal_target(&host) {
        record(&cfg, &host, "ssrf-block", "deny", &None);
        return write_status(&mut client, 403, "Forbidden", "SSRF: internal target blocked").await;
    }
    if bg_blocks(&cfg, &host) {
        record(&cfg, &host, "break-glass", "deny", &None);
        return write_status(&mut client, 403, "Forbidden", "blocked by break-glass lockdown").await;
    }
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
    let decision = { cfg.registry.read().unwrap().evaluate(&host, &path, port) };
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
