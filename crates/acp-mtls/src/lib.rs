//! Mutual TLS between the proxy and the control server (decision H0.8 / SC-8).
//!
//! The link between an enrolled proxy and the control plane must be mutually authenticated: the
//! server presents a cert AND requires a client cert signed by the ACP CA, so a rogue client cannot
//! connect and a rogue server cannot impersonate. This builds the rustls configs that enforce that.
//! The transport (tokio) sits on top; these configs are the security-critical part and are testable
//! with an in-memory handshake.

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::BufReader;
use std::sync::Arc;

/// Ensure a crypto provider is installed (idempotent). Call before building configs.
pub fn ensure_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    rustls_pemfile::certs(&mut BufReader::new(pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn load_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, String> {
    rustls_pemfile::private_key(&mut BufReader::new(pem))
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no private key in PEM".to_string())
}

pub fn root_store(ca_pem: &[u8]) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(ca_pem)? {
        roots.add(c).map_err(|e| e.to_string())?;
    }
    Ok(roots)
}

/// Server config that REQUIRES a client cert signed by the ACP CA (mutual auth).
pub fn server_config(ca_pem: &[u8], server_cert_pem: &[u8], server_key_pem: &[u8]) -> Result<Arc<ServerConfig>, String> {
    ensure_provider();
    let roots = Arc::new(root_store(ca_pem)?);
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| e.to_string())?;
    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(load_certs(server_cert_pem)?, load_key(server_key_pem)?)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(cfg))
}

/// Client config that trusts the ACP CA and presents a client cert (mutual auth).
pub fn client_config(ca_pem: &[u8], client_cert_pem: &[u8], client_key_pem: &[u8]) -> Result<Arc<ClientConfig>, String> {
    ensure_provider();
    let cfg = ClientConfig::builder()
        .with_root_certificates(root_store(ca_pem)?)
        .with_client_auth_cert(load_certs(client_cert_pem)?, load_key(client_key_pem)?)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(cfg))
}
