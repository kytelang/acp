//! Argument redaction for a partner's data class (decision H0.5).
//!
//! Some tenants require that certain argument fields never leave the trust boundary in the clear,
//! not in a governance event, not in a support bundle. This redacts named fields and fields whose
//! value matches a sensitive class (pii/secret) before the value is shown anywhere, while leaving
//! the verifiable record's args hash untouched (the hash is over the original, so evidence still
//! verifies). Redaction is deterministic and pure.

use crate::classify::classify;
use serde_json::Value;

/// Redact a JSON arguments object: replace configured field names, and any string value that
/// classifies as a sensitive class, with a fixed marker. Recurses into nested objects/arrays.
pub fn redact_args(value: &Value, redact_fields: &[String]) -> Value {
    redact_inner(value, redact_fields)
}

const MARK: &str = "[redacted]";

fn redact_inner(value: &Value, fields: &[String]) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if fields.iter().any(|f| f == k) {
                    out.insert(k.clone(), Value::String(MARK.to_string()));
                } else {
                    out.insert(k.clone(), redact_inner(v, fields));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| redact_inner(v, fields)).collect())
        }
        Value::String(s) => {
            if classify(s).is_some() {
                Value::String(MARK.to_string())
            } else {
                value.clone()
            }
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn named_fields_are_redacted() {
        let v = json!({"amount": 100, "card_number": "4111111111111111", "note": "ok"});
        let r = redact_args(&v, &["card_number".to_string()]);
        assert_eq!(r["card_number"], json!("[redacted]"));
        assert_eq!(r["amount"], json!(100), "non-sensitive fields are kept");
        assert_eq!(r["note"], json!("ok"));
    }

    #[test]
    fn values_that_classify_as_sensitive_are_redacted_even_without_a_named_field() {
        let v = json!({"body": "contact jane@example.com about this"});
        let r = redact_args(&v, &[]);
        assert_eq!(
            r["body"],
            json!("[redacted]"),
            "pii value redacted by class"
        );
    }

    #[test]
    fn nested_structures_are_handled() {
        let v = json!({"outer": {"secret_token": "sk_live_abcd1234efgh5678", "keep": 1}, "list": ["plain"]});
        let r = redact_args(&v, &["secret_token".to_string()]);
        assert_eq!(r["outer"]["secret_token"], json!("[redacted]"));
        assert_eq!(r["outer"]["keep"], json!(1));
        assert_eq!(r["list"][0], json!("plain"));
    }
}
