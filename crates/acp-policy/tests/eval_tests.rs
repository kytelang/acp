//! M2 D9 soundness tests: enforcement, namespacing, typed guards, and verdict precedence.

use acp_core::types::Verdict;
use acp_policy::PolicyEngine;
use serde_json::json;

/// Build a namespaced context the way the proxy will: agent data only under `args`.
fn ctx(
    tool: &str,
    args: serde_json::Value,
    env: &str,
    derived: serde_json::Value,
) -> serde_json::Value {
    json!({ "tool": tool, "args": args, "env": env, "impact": "low",
            "principal_scopes": [], "derived": derived })
}

fn engine(y: &str) -> PolicyEngine {
    PolicyEngine::from_yaml(y).expect("engine")
}

#[test]
fn enforces_allow_and_deny() {
    let e = engine(
        "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when:\n      tool: \"payments.charge\"\n      arg:\n        amount_cents: { gt: 50000 }\n    verdict: deny\n",
    );
    // above threshold -> deny, naming the rule
    let d = e.evaluate(ctx(
        "payments.charge",
        json!({"amount_cents": 90000}),
        "prod",
        json!({}),
    ));
    assert_eq!(d.verdict, Verdict::Deny);
    assert_eq!(d.rule_id.as_deref(), Some("cap"));
    // below threshold -> falls through to default allow
    let a = e.evaluate(ctx(
        "payments.charge",
        json!({"amount_cents": 100}),
        "prod",
        json!({}),
    ));
    assert_eq!(a.verdict, Verdict::Allow);
}

#[test]
fn typed_guard_fails_closed_not_bypass() {
    let e = engine(
        "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when:\n      tool: \"payments.charge\"\n      arg:\n        amount_cents: { gt: 50000 }\n    verdict: deny\n",
    );
    // amount sent as a STRING must not silently bypass the numeric guard; it fails closed.
    let d = e.evaluate(ctx(
        "payments.charge",
        json!({"amount_cents": "90000"}),
        "prod",
        json!({}),
    ));
    assert_eq!(
        d.verdict,
        Verdict::Deny,
        "string-typed amount must not bypass to allow"
    );
}

#[test]
fn agent_cannot_spoof_derived_or_env() {
    // policy trusts the derived class flag and the injected env
    let e = engine(
        "version: 1\ndefault: allow\nrules:\n  - id: pii\n    when:\n      tool: \"email.send\"\n      arg:\n        body: { contains_class: \"pii\" }\n    verdict: deny\n  - id: prod-guard\n    when:\n      tool: \"db.wipe\"\n      env: { eq: \"prod\" }\n    verdict: deny\n",
    );
    // agent supplies an arg literally named body_class / env: must NOT trigger the trusted checks
    let spoof = e.evaluate(ctx(
        "email.send",
        json!({"body_class": "pii", "env": "prod"}),
        "dev",
        json!({}),
    ));
    assert_eq!(
        spoof.verdict,
        Verdict::Allow,
        "agent must not spoof derived/env namespace"
    );
    // when the PROXY sets the derived flag (injected), the deny fires
    let real = e.evaluate(ctx(
        "email.send",
        json!({"body": "x"}),
        "dev",
        json!({"body_class": "pii"}),
    ));
    assert_eq!(real.verdict, Verdict::Deny);
    // when env is genuinely prod (injected), the guard fires
    let real_env = e.evaluate(ctx("db.wipe", json!({}), "prod", json!({})));
    assert_eq!(real_env.verdict, Verdict::Deny);
}

#[test]
fn verdict_precedence_deny_over_step_up() {
    // two rules match the same call: one step_up, one deny -> deny wins
    let e = engine(
        "version: 1\ndefault: allow\nrules:\n  - id: soft\n    when:\n      tool: \"payments.charge\"\n    verdict: step_up\n    approvers: [\"a\"]\n  - id: hard\n    when:\n      tool: \"payments.charge\"\n      arg:\n        amount_cents: { gt: 50000 }\n    verdict: deny\n",
    );
    let big = e.evaluate(ctx(
        "payments.charge",
        json!({"amount_cents": 90000}),
        "prod",
        json!({}),
    ));
    assert_eq!(big.verdict, Verdict::Deny, "deny must outrank step_up");
    // a smaller charge only hits the step_up rule
    let small = e.evaluate(ctx(
        "payments.charge",
        json!({"amount_cents": 10}),
        "prod",
        json!({}),
    ));
    assert_eq!(small.verdict, Verdict::StepUp);
    assert_eq!(small.approvers, vec!["a".to_string()]);
}

#[test]
fn default_when_nothing_matches() {
    let e = engine("version: 1\ndefault: deny\nrules:\n  - id: allow-read\n    when:\n      tool: \"db.read\"\n    verdict: allow\n");
    assert_eq!(
        e.evaluate(ctx("db.read", json!({}), "prod", json!({})))
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        e.evaluate(ctx("something.else", json!({}), "prod", json!({})))
            .verdict,
        Verdict::Deny
    );
}

#[test]
fn hash_stable_and_changes_on_edit() {
    let a = PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap();
    let b = PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap();
    let c = PolicyEngine::from_yaml("version: 1\ndefault: deny\nrules: []\n").unwrap();
    assert_eq!(a.hash(), b.hash(), "same source -> same hash");
    assert_ne!(a.hash(), c.hash(), "edited source -> new hash");
}

#[test]
fn allow_path_latency_budget() {
    // M5.5: the common allow path must be well under the 10 ms p95 budget. This is a coarse
    // guard (a full criterion perf-regression gate is the hardening track); it catches gross
    // regressions in policy evaluation.
    let e = engine("version: 1\ndefault: allow\nrules:\n  - id: cap\n    when: { tool: \"payments.charge\", arg: { amount_cents: { gt: 50000 } } }\n    verdict: deny\n");
    let c = ctx("db.read", json!({"operation": "read"}), "prod", json!({}));
    let n = 2000;
    let start = std::time::Instant::now();
    for _ in 0..n {
        let _ = e.evaluate(c.clone());
    }
    let per = start.elapsed().as_secs_f64() * 1000.0 / n as f64;
    assert!(
        per < 5.0,
        "allow-path eval averaged {per:.3} ms, over budget"
    );
}
