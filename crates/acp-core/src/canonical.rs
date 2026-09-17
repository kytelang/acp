//! Canonical byte encoding for records.
//!
//! v0 uses `serde_json::to_vec` over a `BTreeMap`-backed value so object keys are emitted in
//! a stable (sorted) order. This is a pragmatic stand-in for full RFC 8785 (JCS); decision
//! D3 calls for JCS, and swapping this function for a JCS crate is the only change needed.
use sha2::{Digest, Sha256};

/// Canonical bytes of any serialisable value (sorted keys, no insignificant whitespace).
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    // Round-trip through serde_json::Value so BTreeMap key ordering is applied.
    let v: serde_json::Value = serde_json::to_value(value).expect("serialisable");
    let sorted = sort_value(v);
    serde_json::to_vec(&sorted).expect("serialisable")
}

/// SHA-256 of the canonical bytes, hex-encoded (used for `args_hash`, ids, etc.).
pub fn sha256_hex<T: serde::Serialize>(value: &T) -> String {
    let mut h = Sha256::new();
    h.update(canonical_bytes(value));
    hex::encode(h.finalize())
}

fn sort_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            // BTreeMap sorts keys; recurse into values.
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, val)| (k, sort_value(val)))
                .collect();
            serde_json::to_value(sorted).expect("serialisable")
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sort_value).collect())
        }
        // JCS number handling (partial RFC 8785): an integer-valued float serialises as an
        // integer, so 1.0 and 1 canonicalise identically. Arbitrary-precision float formatting
        // remains a documented boundary.
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
                    if let Some(i) = n.as_i64() {
                        return serde_json::Value::Number(i.into());
                    }
                    return serde_json::Value::Number((f as i64).into());
                }
            }
            serde_json::Value::Number(n)
        }
        other => other,
    }
}

/// SHA-256 of raw bytes, hex-encoded (used for tool-binary fingerprints, D12/B5).
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
