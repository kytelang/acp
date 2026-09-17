//! C2 performance-regression gate (offline, std-time; criterion is not available in this build).
//!
//! These assert a committed per-operation budget for the hot allow-path. The budgets are
//! deliberately loose multiples of observed timings so normal machine variance never flakes,
//! but an accidental order-of-magnitude regression (an O(n) blow-up, a per-call recompile) trips
//! them. Treat a failure as "something got structurally slower", then re-baseline intentionally.

use acp_policy::{build_context, PolicyEngine};
use std::time::Instant;

fn engine() -> PolicyEngine {
    // A representative policy: a couple of rules with an arg matcher and a class check.
    PolicyEngine::from_yaml(
        "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when:\n      tool: \"payments.charge\"\n      arg:\n        amount_cents: { gt: 50000 }\n    verdict: deny\n  - id: pii\n    when:\n      tool: \"email.send\"\n      arg:\n        body: { contains_class: \"pii\" }\n    verdict: step_up\n    approvers: [\"sec\"]\n",
    )
    .unwrap()
}

#[test]
fn allow_path_decision_stays_within_budget() {
    let e = engine();
    let ctx = build_context("catalog.read", &serde_json::json!({"id": 7}), "prod");
    // Warm up so first-call effects do not skew the median.
    for _ in 0..200 {
        let _ = e.evaluate(ctx.clone());
    }
    let n = 2_000;
    let start = Instant::now();
    for _ in 0..n {
        let _ = e.evaluate(ctx.clone());
    }
    let per_call_us = start.elapsed().as_micros() as f64 / n as f64;
    // Committed budget: 4000 us/allow-decision. This is a debug-build structural-regression
    // gate, not a micro-benchmark bound: observed on this workspace is ~800 us/call, so 4000 us
    // gives ~5x headroom over machine variance while still catching an order-of-magnitude
    // regression (an O(n) blow-up or a per-call policy recompile). Re-baseline deliberately.
    assert!(
        per_call_us < 4000.0,
        "allow-path decision regressed to {per_call_us:.1} us/call (budget 4000 us)"
    );
}

#[test]
fn engine_build_stays_within_budget() {
    let src = "version: 1\ndefault: allow\nrules:\n  - id: r\n    when: { tool: \"t\" }\n    verdict: deny\n";
    let start = Instant::now();
    for _ in 0..50 {
        let _ = PolicyEngine::from_yaml(src).unwrap();
    }
    let per_build_ms = start.elapsed().as_millis() as f64 / 50.0;
    // ~1-2 ms observed in debug; 50 ms budget catches a structural regression in compile.
    assert!(
        per_build_ms < 50.0,
        "policy build regressed to {per_build_ms:.1} ms (budget 50 ms)"
    );
}
