//! H0.8/SC-8: a real mutual-TLS handshake. A client with a cert signed by the ACP CA completes the
//! handshake and the server sees its client certificate (mutual auth); a client with an untrusted
//! (rogue) cert is rejected. Uses rustls's in-memory connections, so no sockets or async are needed.

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection};

fn f(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Pump bytes between two connections until both finish (or an error occurs).
fn drive(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), rustls::Error> {
    for _ in 0..20 {
        let mut c2s = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut c2s).unwrap();
        }
        if !c2s.is_empty() {
            server.read_tls(&mut &c2s[..]).unwrap();
            server.process_new_packets()?; // server validates the client cert here
        }
        let mut s2c = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut s2c).unwrap();
        }
        if !s2c.is_empty() {
            client.read_tls(&mut &s2c[..]).unwrap();
            client.process_new_packets()?;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
        if c2s.is_empty() && s2c.is_empty() {
            break;
        }
    }
    Ok(())
}

#[test]
fn a_valid_client_completes_mutual_tls_and_the_server_sees_its_cert() {
    let server_cfg = acp_mtls::server_config(&f("ca.crt"), &f("server.crt"), &f("server.key")).unwrap();
    let client_cfg = acp_mtls::client_config(&f("ca.crt"), &f("client.crt"), &f("client.key")).unwrap();

    let mut client = ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_cfg).unwrap();
    drive(&mut client, &mut server).expect("valid mutual handshake completes");

    assert!(!client.is_handshaking() && !server.is_handshaking(), "handshake finished");
    // Mutual auth: the server received and accepted the client's certificate.
    assert!(server.peer_certificates().is_some(), "server must see the client cert (mutual auth)");
}

#[test]
fn a_rogue_client_cert_is_rejected() {
    let server_cfg = acp_mtls::server_config(&f("ca.crt"), &f("server.crt"), &f("server.key")).unwrap();
    // The rogue client presents a self-signed cert NOT signed by the ACP CA. It still trusts our CA
    // as a server root (so the server side of TLS proceeds), but its client cert must be refused.
    let client_cfg = acp_mtls::client_config(&f("ca.crt"), &f("rogue.crt"), &f("rogue.key")).unwrap();

    let mut client = ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_cfg).unwrap();
    let result = drive(&mut client, &mut server);
    assert!(result.is_err(), "an untrusted client cert must fail the mutual handshake");
}
