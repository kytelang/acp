//! Coarse blast-radius heuristic (build spec 3.4). The proxy injects the score into the
//! Cedar `context` so one policy can gate on impact without enumerating tools. This is a
//! heuristic, not a guarantee, and is documented as such.

use crate::types::BlastRadius;
use serde_json::Value;

const DESTRUCTIVE: &[&str] = &["delete", "drop", "truncate", "remove", "wipe", "destroy"];
const AMOUNT_KEYS: &[&str] = &["amount_cents", "amount", "quantity", "count"];

/// Score a tool call from its name and arguments.
pub fn score(tool: &str, args: &Value) -> BlastRadius {
    let mut points = 0i32;

    if let Some(op) = args.get("operation").and_then(Value::as_str) {
        if DESTRUCTIVE.iter().any(|d| op.eq_ignore_ascii_case(d)) {
            points += 2;
        }
    }
    let tool_l = tool.to_ascii_lowercase();
    if DESTRUCTIVE.iter().any(|d| tool_l.contains(d)) {
        points += 1;
    }
    for k in AMOUNT_KEYS {
        if let Some(n) = args.get(*k).and_then(Value::as_f64) {
            points += if n > 10_000.0 {
                2
            } else if n > 0.0 {
                1
            } else {
                0
            };
        }
    }
    if let Some(t) = args.get("target").and_then(Value::as_str) {
        if t == "*" || t.eq_ignore_ascii_case("all") {
            points += 2;
        }
    }
    if ["to", "recipient", "external"]
        .iter()
        .any(|k| args.get(*k).is_some())
    {
        points += 2; // leaving the boundary (external recipient) is high-impact
    }

    match points {
        i32::MIN..=1 => BlastRadius::Low,
        2..=3 => BlastRadius::Medium,
        _ => BlastRadius::High,
    }
}
