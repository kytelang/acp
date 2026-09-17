use acp_policy::{compile_to_cedar, parse_str, validate};

const SAMPLE: &str = r#"
version: 1
default: allow
rules:
  - id: cap-spend
    when:
      tool: "payments.charge"
      arg:
        amount_cents: { gt: 50000 }
    verdict: step_up
    approvers: ["finance-approvers"]
  - id: no-pii
    when:
      tool: "email.send"
      arg:
        body: { contains_class: "pii" }
    verdict: deny
"#;

#[test]
fn compiles_with_namespacing() {
    let p = parse_str(SAMPLE).unwrap();
    validate(&p).unwrap();
    let cedar = compile_to_cedar(&p);
    assert!(cedar.contains("@verdict(\"step_up\")"));
    assert!(cedar.contains("context.args has amount_cents && context.args.amount_cents > 50000"));
    // data class must live in the un-spoofable derived namespace, never under context.args (D9)
    assert!(cedar.contains("context.derived.body_class == \"pii\""));
    assert!(!cedar.contains("context.args.body_class"));
}

#[test]
fn rejects_regex_matcher_in_v0() {
    let p = parse_str(
        "version: 1\ndefault: allow\nrules:\n  - id: r\n    when:\n      tool: \"*\"\n      arg:\n        x: { regex: \".*\" }\n    verdict: deny\n",
    )
    .unwrap();
    assert!(
        validate(&p).is_err(),
        "regex matcher must be rejected in v0"
    );
}
