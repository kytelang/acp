//! Resource limits for the interception path (decision D5 / gap J).
//!
//! A hostile agent or tool server must not be able to OOM or stall the proxy. v0 caps the
//! per-message size and fails closed on breach.

/// Maximum size of a single JSON-RPC message (one newline-delimited frame), in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Returns true if a frame is within the allowed size.
pub fn within_size(frame: &[u8]) -> bool {
    frame.len() <= MAX_MESSAGE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_cap_enforced() {
        assert!(within_size(b"{}"));
        assert!(within_size(&vec![b'a'; MAX_MESSAGE_BYTES]));
        assert!(!within_size(&vec![b'a'; MAX_MESSAGE_BYTES + 1]));
    }
}
