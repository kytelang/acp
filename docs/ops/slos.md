# Service level objectives and error budgets (v3.7)

The internal targets ACP operates to at enterprise volume. These are objectives with error budgets,
distinct from the contractual SLA in `docs/commercial/sla-and-continuity.md`.

## Objectives

- Decision latency: allow-path decision within the perf budget (see `docs/ops/perf-targets.md`),
  gated in CI by the perf-regression test.
- Evidence durability: every accepted decision is durably spooled before forward. The objective is
  zero lost decisions; a failure to spool fails the call closed rather than losing it.
- Verification: `acp verify` over the target ledger size within its documented time budget.
- Approval-resolution latency: p95 within the policy step-up TTL. This is human-bound, so its error
  budget accounts for approver response time, and breaches inform staffing and TTL tuning rather
  than paging engineers.
- Anchoring freshness: the newest signed tree head is anchored within the anchoring interval; the
  budget bounds how stale the external time reference may become.

## Error budgets

Each objective has a monthly error budget. When a budget is being consumed too fast, the response is
defined: for latency, investigate before shipping more features; for durability, treat as a
sev-high; for approval latency, revisit approver capacity and TTLs. The budgets and burn are shown
on the governance report so they are visible, not buried.

## Measurement

Every objective is measured from the verifiable log or the report, not from a separate telemetry
system that could disagree with the evidence. The number a customer sees is re-derivable from the
export.
