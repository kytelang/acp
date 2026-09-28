//! TLS interception (MITM) for body-inspecting rules (traffic-interception phase 3).
//!
//! For a CONNECT to a body-inspecting endpoint, instead of tunnelling opaquely, ACP terminates TLS
//! with the client using a leaf certificate for the destination host signed by the ACP CA (which the
//! organisation installs on managed devices), reads the decrypted HTTP request, inspects it with the
//! content engine, then re-originates TLS to the real upstream and relays the response.
//!
//! Honest limitations, stated rather than hidden:
//!   - HTTP/1.1 only. The client-facing TLS offers ALPN http/1.1; a client that insists on HTTP/2
//!     will fail the handshake, which we detect and report (not silently pass).
//!   - Certificate pinning. A client that pins the real server certificate rejects our leaf; the
//!     handshake fails and we record "pinning-or-handshake-failed" so the endpoint is visibly
//!     un-inspectable rather than quietly broken.
//!   - One inspected request per connection: we force Connection: close upstream, so keep-alive
//!     clients simply open a new connection (each inspected).

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Generate a self-signed ACP intercept CA. Returns (cert_pem, key_pem). Install the cert on managed
/// devices as a trusted root; keep the key secret (it can mint a certificate for any host).
pub fn generate_ca() -> Result<(String, String), String> {
    let mut params = CertificateParams::new(Vec::new()).map_err(|e| e.to_string())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "ACP Intercept CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Agent Control Plane");
    let key = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Mints per-host leaf certs signed by the loaded CA and caches the resulting rustls server configs.
pub struct CaSigner {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

impl CaSigner {
    pub fn load(ca_cert_pem: &str, ca_key_pem: &str) -> Result<CaSigner, String> {
        let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| format!("CA key: {e}"))?;
        let ca_params =
            CertificateParams::from_ca_cert_pem(ca_cert_pem).map_err(|e| format!("CA cert: {e}"))?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("CA rebuild: {e}"))?;
        Ok(CaSigner {
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// A rustls ServerConfig presenting a freshly-minted leaf for `host`, cached per host.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        if let Some(c) = self.cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut lp = CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        lp.distinguished_name.push(DnType::CommonName, host);
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf = lp
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| e.to_string())?;
        let leaf_der = leaf.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], key_der)
            .map_err(|e| e.to_string())?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let arc = Arc::new(cfg);
        self.cache
            .lock()
            .unwrap()
            .insert(host.to_string(), arc.clone());
        Ok(arc)
    }
}

/// A TLS connector that verifies the real upstream against the public web roots, ALPN http/1.1.
pub fn upstream_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cc = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports safe defaults")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cc.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cc))
}

/// The outcome of a MITM attempt, for evidence.
pub enum MitmOutcome {
    Blocked(String),
    Forwarded,
    HandshakeFailed(String),
    UpstreamFailed(String),
}

async fn read_headers<S: AsyncReadExt + Unpin>(s: &mut S) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
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

fn content_length(headers: &str) -> usize {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Intercept one CONNECT'd TLS connection. `decide` maps (path) to a verdict tuple
/// (block, needs_body, rule_id); `inspect` scans a body and returns Some(reason) to block.
/// Returns the outcome for evidence. The 200 Connection Established must already have been written.
pub async fn intercept<D, I>(
    ca: &CaSigner,
    connector: &TlsConnector,
    client_tcp: TcpStream,
    host: &str,
    port: u16,
    decide: D,
    inspect: I,
) -> MitmOutcome
where
    D: Fn(&str) -> (bool, bool, Option<String>),
    I: Fn(&str) -> Option<String>,
{
    let server_cfg = match ca.server_config_for(host) {
        Ok(c) => c,
        Err(e) => return MitmOutcome::HandshakeFailed(format!("leaf mint failed: {e}")),
    };
    let acceptor = TlsAcceptor::from(server_cfg);
    let mut client = match acceptor.accept(client_tcp).await {
        Ok(s) => s,
        // The client rejected our leaf: it pins the real cert or requires HTTP/2. Report, do not pass.
        Err(e) => return MitmOutcome::HandshakeFailed(format!("client TLS rejected (pinning or h2?): {e}")),
    };

    let (headers, leftover) = match read_headers(&mut client).await {
        Ok(h) => h,
        Err(e) => return MitmOutcome::HandshakeFailed(format!("read request: {e}")),
    };
    let first = headers.lines().next().unwrap_or("");
    let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();

    // Read the body per content-length.
    let want = content_length(&headers);
    let mut body = leftover;
    while body.len() < want {
        let mut tmp = [0u8; 4096];
        match client.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }

    let (block, needs_body, _rule) = decide(&path);
    if block {
        let _ = write_tls_status(&mut client, 403, "blocked by endpoint policy").await;
        return MitmOutcome::Blocked("endpoint policy".into());
    }
    if needs_body {
        let text = String::from_utf8_lossy(&body);
        if let Some(reason) = inspect(&text) {
            let _ = write_tls_status(&mut client, 403, &format!("blocked by content firewall: {reason}")).await;
            return MitmOutcome::Blocked(reason);
        }
    }

    // Re-originate TLS to the real upstream and forward the (unchanged) request with Connection: close.
    let sni = match ServerName::try_from(host.to_string()) {
        Ok(s) => s,
        Err(e) => return MitmOutcome::UpstreamFailed(format!("bad server name: {e}")),
    };
    let up_tcp = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(e) => {
            let _ = write_tls_status(&mut client, 502, "upstream unreachable").await;
            return MitmOutcome::UpstreamFailed(format!("connect: {e}"));
        }
    };
    let mut upstream = match connector.connect(sni, up_tcp).await {
        Ok(s) => s,
        Err(e) => {
            let _ = write_tls_status(&mut client, 502, "upstream TLS failed").await;
            return MitmOutcome::UpstreamFailed(format!("upstream TLS: {e}"));
        }
    };

    let mut req = String::new();
    req.push_str(first);
    req.push_str("\r\n");
    for line in headers.lines().skip(1) {
        if let Some((k, _)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("connection")
                || k.eq_ignore_ascii_case("proxy-connection")
                || k.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
        }
        req.push_str(line);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\n\r\n");
    if upstream.write_all(req.as_bytes()).await.is_err() {
        return MitmOutcome::UpstreamFailed("write request".into());
    }
    if !body.is_empty() && upstream.write_all(&body).await.is_err() {
        return MitmOutcome::UpstreamFailed("write body".into());
    }
    // Relay the response back to the client until the upstream closes.
    let _ = tokio::io::copy(&mut upstream, &mut client).await;
    let _ = client.shutdown().await;
    MitmOutcome::Forwarded
}

async fn write_tls_status<S: AsyncWriteExt + Unpin>(
    s: &mut S,
    code: u16,
    body: &str,
) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {code} Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(resp.as_bytes()).await?;
    s.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_produces_pems() {
        let (cert, key) = generate_ca().unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("PRIVATE KEY"));
    }

    #[test]
    fn ca_signs_a_leaf_and_builds_a_server_config() {
        let (cert, key) = generate_ca().unwrap();
        let signer = CaSigner::load(&cert, &key).unwrap();
        // Minting the same host twice returns the cached config (same Arc).
        let a = signer.server_config_for("api.claude.ai").unwrap();
        let b = signer.server_config_for("api.claude.ai").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
