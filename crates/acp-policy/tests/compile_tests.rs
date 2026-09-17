use acp_policy::{compile_to_cedar, parse_str};

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
  - id: allow-readonly
    when:
      tool: "*"
      arg:
        operation: { in: ["read", "get"] }
    verdict: allow
  - id: no-pii
    when:
      tool: "email.send"
      arg:
        body: { contains_class: "pii" }
    verdict: deny
"#;

#[test]
fn compiles_sample_to_expected_cedar() {
    let policy = parse_str(SAMPLE).expect("valid yaml");
    let cedar = compile_to_cedar(&policy);

    // step-up rule: forbid + annotations + guarded numeric comparison
    assert!(cedar.contains("@id(\"cap-spend\")"));
    assert!(cedar.contains("@verdict(\"step_up\")"));
    assert!(cedar.contains("@approvers(\"finance-approvers\")"));
    assert!(cedar.contains("forbid(principal, action, resource)"));
    assert!(cedar.contains("context.tool == \"payments.charge\""));
    assert!(cedar.contains("context.args has amount_cents && context.args.amount_cents > 50000"));

    // allow-readonly: permit, no tool condition for `*`, `in` list
    assert!(cedar.contains("@verdict(\"allow\")"));
    assert!(cedar.contains("permit(principal, action, resource)"));
    assert!(cedar.contains("context.args.operation in [\"read\", \"get\"]"));

    // contains_class lowers to the proxy-set class flag
    assert!(cedar.contains("context.args.body_class == \"pii\""));
}

#[test]
fn wildcard_tool_has_no_tool_condition() {
    let policy = parse_str(SAMPLE).unwrap();
    let cedar = compile_to_cedar(&policy);
    // the allow-readonly rule uses tool "*", so its when-block must not pin a tool.
    let readonly_block = cedar
        .split("@id(\"allow-readonly\")")
        .nth(1)
        .unwrap()
        .split("};")
        .next()
        .unwrap();
    assert!(!readonly_block.contains("context.tool"));
}
