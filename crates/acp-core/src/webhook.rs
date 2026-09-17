//! HMAC-signed webhook and inbound-signature verification for the connector fleet (F4/F10).
//!
//! Two directions share one primitive (HMAC-SHA256):
//!   - inbound: verify a Slack request signature so an approve/deny that arrives over a webhook is
//!     provably from Slack and not replayed (F4);
//!   - outbound: sign the events we emit (decision.made, approval.requested/resolved,
//!     policy.changed) so the receiver can verify authenticity and reject replays (F10).
//!
//! HMAC-SHA256 is implemented directly on the in-tree `sha2` so we add no crypto dependency and no
//! version friction. Comparison is constant-time to avoid a timing oracle.

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

/// HMAC-SHA256(key, msg). Standard construction, block size 64 for SHA-256.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Constant-time equality of two byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a Slack request signature (F4). Slack signs `v0:{timestamp}:{body}` and sends
/// `v0=<hex>` in `X-Slack-Signature`. Reject if the timestamp is outside the freshness window
/// (replay protection).
pub fn verify_slack(
    signing_secret: &[u8],
    timestamp_s: u64,
    body: &str,
    provided: &str,
    now_s: u64,
    max_skew_s: u64,
) -> bool {
    if now_s.abs_diff(timestamp_s) > max_skew_s {
        return false;
    }
    let base = format!("v0:{timestamp_s}:{body}");
    let mac = hmac_sha256(signing_secret, base.as_bytes());
    let expected = format!("v0={}", hex::encode(mac));
    ct_eq(expected.as_bytes(), provided.as_bytes())
}

/// Sign an outbound webhook body (F10). Returns a signature header value binding the timestamp so
/// a captured body cannot be replayed under a fresh timestamp.
pub fn sign_webhook(secret: &[u8], timestamp_s: u64, body: &str) -> String {
    let signed = format!("{timestamp_s}.{body}");
    let mac = hmac_sha256(secret, signed.as_bytes());
    format!("t={timestamp_s},v1={}", hex::encode(mac))
}

/// Verify an outbound-style webhook signature header on the receiver side.
pub fn verify_webhook(
    secret: &[u8],
    header: &str,
    body: &str,
    now_s: u64,
    max_skew_s: u64,
) -> bool {
    let mut ts = None;
    let mut v1 = None;
    for part in header.split(',') {
        if let Some(v) = part.strip_prefix("t=") {
            ts = v.parse::<u64>().ok();
        } else if let Some(v) = part.strip_prefix("v1=") {
            v1 = Some(v);
        }
    }
    let (ts, v1) = match (ts, v1) {
        (Some(t), Some(s)) => (t, s),
        _ => return false,
    };
    if now_s.abs_diff(ts) > max_skew_s {
        return false;
    }
    let expected = hex::encode(hmac_sha256(secret, format!("{ts}.{body}").as_bytes()));
    ct_eq(expected.as_bytes(), v1.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_a_known_answer() {
        // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn slack_signature_round_trips_and_rejects_replay() {
        let secret = b"slack-signing-secret";
        let body = "payload=%7B%22ok%22%3Atrue%7D";
        let sig = format!(
            "v0={}",
            hex::encode(hmac_sha256(
                secret,
                format!("v0:{}:{}", 1000, body).as_bytes()
            ))
        );
        assert!(
            verify_slack(secret, 1000, body, &sig, 1010, 300),
            "fresh + valid"
        );
        assert!(
            !verify_slack(secret, 1000, body, &sig, 2000, 300),
            "stale timestamp rejected"
        );
        assert!(
            !verify_slack(secret, 1000, "tampered", &sig, 1010, 300),
            "tampered body rejected"
        );
    }

    #[test]
    fn webhook_signature_round_trips_and_rejects_tamper_and_replay() {
        let secret = b"webhook-secret";
        let body = r#"{"event":"decision.made","verdict":"deny"}"#;
        let header = sign_webhook(secret, 5000, body);
        assert!(verify_webhook(secret, &header, body, 5010, 300), "valid");
        assert!(
            !verify_webhook(secret, &header, body, 9999, 300),
            "stale rejected"
        );
        assert!(
            !verify_webhook(secret, &header, r#"{"event":"x"}"#, 5010, 300),
            "tamper rejected"
        );
        assert!(
            !verify_webhook(b"wrong", &header, body, 5010, 300),
            "wrong secret rejected"
        );
    }
}
