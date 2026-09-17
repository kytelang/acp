// GENERATED from sample.yaml by 'acp policy-compile'. Do not edit by hand.
// Checked in so the YAML->Cedar mapping is reviewable.

@id("block-prod-deletes")
@verdict("step_up")
@approvers("oncall-platform")
@reason("Destructive prod DB operation")
forbid(principal, action, resource)
when {
    context.tool like "db.*" &&
    context.args has env && context.args.env == "prod" &&
    context.args has operation && context.args.operation in ["delete", "drop", "truncate"]
};

@id("cap-spend")
@verdict("step_up")
@approvers("finance-approvers")
forbid(principal, action, resource)
when {
    context.tool == "payments.charge" &&
    context.args has amount_cents && context.args.amount_cents > 50000
};

@id("no-pii-to-external")
@verdict("deny")
@reason("PII must not leave via the unmanaged email tool")
forbid(principal, action, resource)
when {
    context.tool == "email.send" &&
    context.args has body_class && context.args.body_class == "pii"
};

@id("allow-readonly")
@verdict("allow")
permit(principal, action, resource)
when {
    context.args has operation && context.args.operation in ["read", "get", "list", "search"]
};
