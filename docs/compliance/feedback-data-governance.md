# Feedback-loop data governance (D3)

The classifier tuning loop and the shadow-evaluation path look at argument content to judge whether
a classifier fired correctly. That makes the feedback corpus a second place where sensitive data can
accumulate, and it must be governed exactly like the primary argument store, not treated as a
convenient side dataset. This closes the shadow-PII-repo risk against the H0.5 and meta-audit
controls.

## The rule

Any corpus used for classifier feedback, tuning, or shadow evaluation is subject to the same regime
as `args_blob`:

- Retention: the same retention window and the same mandated floor; feedback data is not kept longer
  than the arguments it came from.
- BYOK and encryption: stored with the same encryption and customer-managed-key handling.
- RBAC: access limited to the same roles that may see raw arguments (`SeeArgs`); a tuning engineer is
  not a backdoor around redaction.
- Redaction: where a class label is enough, the corpus stores labels, not raw values (the tuning and
  shadow-eval modules already operate on counts and labels, not payloads).
- Meta-audit: creating, exporting, or deleting a feedback corpus is recorded in the tamper-evident
  meta-audit log, so its lifecycle is auditable.
- Consent and purpose: the purpose (improving classification) is captured, and any consent basis the
  customer relies on is propagated with the lineage record.

## Why this matters

Without this rule, a governance product could quietly become the largest un-governed store of the
very data it exists to protect. Stating and enforcing parity with the argument store is what keeps
the feedback loop from becoming that shadow repository.

## Status

The tuning and shadow-eval code already minimise exposure (labels and counts, not raw args). This
document fixes the governance parity; wiring the corpus lifecycle into the meta-audit log is the
remaining engineering leg.
