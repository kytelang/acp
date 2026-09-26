//! acp-intercept: the configuration-driven forward proxy (traffic-interception phase 2).
//!
//! Agents, IDEs and browsers on a managed device point their HTTP(S) proxy at this. For each request
//! it matches the destination against the endpoint registry (acp_core::interception) and either
//! governs it (block, or inspect the body with the content engine) or tunnels it. Phase 2 does the
//! no-MITM surfaces: it enforces block/pass on HTTPS at the CONNECT stage (by host, no decryption)
//! and fully inspects plain-HTTP bodies. TLS body inspection (MITM) is phase 3.
//!
//! The parsing helpers here are pure so the request handling is unit-testable without a socket.

pub mod mitm;
pub mod agent;

/// Parse an HTTP request line into (method, target). Returns None if malformed.
pub fn parse_request_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let _version = parts.next()?; // HTTP/1.1
    Some((method, target))
}

/// Parse a CONNECT target "host:port" into (host, port). Defaults to 443 if no port.
pub fn connect_target(target: &str) -> Option<(String, u16)> {
    if let Some((h, p)) = target.rsplit_once(':') {
        let port = p.parse().ok()?;
        if h.is_empty() {
            return None;
        }
        Some((h.to_string(), port))
    } else if !target.is_empty() {
        Some((target.to_string(), 443))
    } else {
        None
    }
}

/// Parse an absolute-form target "http://host[:port]/path" into (host, path, port).
pub fn absolute_target(target: &str) -> Option<(String, String, u16)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, path.to_string(), port))
}

/// Extract the Content-Length from raw header bytes (case-insensitive), or 0.
pub fn content_length(headers: &str) -> usize {
    for line in headers.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect() {
        assert_eq!(connect_target("api.claude.ai:443"), Some(("api.claude.ai".into(), 443)));
        assert_eq!(connect_target("host"), Some(("host".into(), 443)));
        assert_eq!(connect_target(":443"), None);
    }

    #[test]
    fn parses_absolute_form() {
        assert_eq!(absolute_target("http://api.openai.com/v1/chat"), Some(("api.openai.com".into(), "/v1/chat".into(), 80)));
        assert_eq!(absolute_target("http://h:8080/x"), Some(("h".into(), "/x".into(), 8080)));
        assert_eq!(absolute_target("http://host"), Some(("host".into(), "/".into(), 80)));
        assert!(absolute_target("https://x/y").is_none(), "only plain http here");
    }

    #[test]
    fn parses_request_line_and_content_length() {
        assert_eq!(parse_request_line("POST http://h/x HTTP/1.1"), Some(("POST".into(), "http://h/x".into())));
        assert!(parse_request_line("garbage").is_none());
        assert_eq!(content_length("Host: h\r\nContent-Length: 42\r\n"), 42);
        assert_eq!(content_length("Host: h\r\n"), 0);
    }
}
