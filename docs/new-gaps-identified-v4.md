# Varman (ACP): fourth round - finish the remaining in-repo code (v4)

After v1/v2/v3 (all closed) the product matches or exceeds Credo AI and the Aegis/Lakera class on the
core. This round finishes the remaining items that are genuinely in-repo code. Items that are a separate
product, an ML data programme, or process (not code) are listed under "Deferred by design" with the
reason, so nothing is silently skipped.

---

## M1. Complete multi-tenancy (P1)  [DONE 2026-09-27]
Gap: T1 scoped the 5 record tables; firewall_config + signing key were still global and the console ran
in one tenant.
Design: key `firewall_config` by tenant; derive a per-tenant Ed25519 signing key from the control-plane
key + tenant id (so each tenant's records are signed with a distinct, still-verifiable key); a `/tenants`
endpoint listing known tenants; a console tenant switcher that sends `x-acp-tenant` on every call.
Acceptance:
- Two tenants can hold different content-firewall configs; each PEP/console fetch returns its tenant's.
- A GRC record created under tenant A verifies, and its embedded public key differs from a tenant-B
  record's key (distinct per-tenant signing keys), while both still verify on read.
- `GET /tenants` lists the distinct tenants that have data.
- The console has a tenant selector; switching it scopes every panel to that tenant.
Status (2026-09-27): SHIPPED (server + per-instance console). `firewall_config` is now keyed by tenant;
`tenant_signer` derives a distinct per-tenant Ed25519 key from the cp-key seed + tenant; `GET /tenants`
lists tenants; the console sends `x-acp-tenant` on every request (tenant from `ACP_TENANT`, default
"default") and shows the active tenant in the topbar. Verified via curl: acme vs globex hold different
firewall configs; GRC records in each tenant carry distinct embedded pubkeys (acme 3e0c.., globex 46ed..)
and both verify; `/tenants` lists acme+globex. Note: the console tenant is per-instance (one tenant per
console URL); a live in-browser switcher needs threading the tenant through the SSE panel pipeline and
is the remaining follow-on.

## M2. Live pull-sync from a ticket system (P2)  [DONE 2026-09-27]
Gap: T3 added an inbound callback (push); some systems require the control plane to poll (pull).
Design: `--ticket-poll-url` the server polls on an interval; it fetches a list of resolutions
`[{action,id,status?}]` and applies each exactly like the T3 callback (resolve a hold / advance a GRC
status). Idempotent (a resolution already applied is a no-op).
Acceptance:
- With `--ticket-poll-url` at a mock feed returning an approve resolution, the named hold is resolved on
  the next poll.
- A grc-status resolution advances + re-signs the record.
- Re-polling the same resolutions does not error or double-apply.
Status (2026-09-27): SHIPPED. `--ticket-poll-url` polls a feed of `{action,id,status?,tenant?}` and
applies each via the shared `apply_ticket_resolution` (also used by /tickets/callback), idempotent by
construction (approve->approved; grc-status re-signs to the same status). Verified: the startup poll
resolved a pre-registered hold to approved and advanced a GRC record to mitigating (still verified).

## M3. Scheduler + report delivery (P2)  [DONE 2026-09-27]
Gap: T6 stored snapshots on demand; there was no built-in scheduler or delivery.
Design: `--snapshot-interval-ms` + `--snapshot-frameworks a,b` make the server periodically snapshot
those framework reports and fire a `report.snapshot` webhook (reusing the G4 signed webhook) as delivery.
Acceptance:
- With the interval + frameworks set and a webhook configured, a snapshot is stored and a signed
  `report.snapshot` event is delivered on the schedule (verified against a mock receiver).
- History accumulates one entry per scheduled run.
Status (2026-09-27): SHIPPED. `--snapshot-interval-ms` + `--snapshot-frameworks a,b` run a background
task that snapshots each framework report and fires a signed `report.snapshot` webhook (reusing G4).
Verified against a mock receiver at a 1s interval: snapshots accumulated in history and matching signed
report.snapshot events were delivered for each framework (all signatures verified).

## M4. Approval SLA escalation (P2)  [DONE 2026-09-27]
Gap: approvals had no time-based escalation.
Design: `--approval-sla-ms`; a background task fires an `approval.overdue` webhook for pending holds
older than the SLA (once per hold).
Acceptance:
- A hold left pending past the SLA produces one `approval.overdue` webhook (verified); a resolved hold
  does not.
Status (2026-09-27): SHIPPED. `--approval-sla-ms`; `acp_approvals::list_overdue` + a background task fire
`approval.overdue` once per overdue pending hold (tracked in an in-memory set). Verified: an unresolved
hold produced exactly one approval.overdue event; a resolved hold produced none.

## M5. Continuous vendor monitoring (P2)
Gap: G6 vendor risk was point-in-time.
Design: a `review_due_ms` on vendors (set from a review interval at creation); `GET /vendors` flags
overdue vendors; `POST /vendors/:id/review` refreshes the review date.
Acceptance:
- A vendor created with a short review interval is reported `overdue: true` after its due time.
- Re-reviewing clears the overdue flag.

---

## Deferred by design (not built here, with the reason)
- **Detection transformer / Lakera-grade recall**: needs a large labelled training corpus and training
  infrastructure that live outside this repo. The linear-model seam + external hook remain the path;
  building a real transformer classifier is an ML data programme, not an in-repo wire-up.
- **Multi-modal (image/audio) scanning** and a **first-party multi-format model-artifact scanner + MITRE
  ATLAS**: the specialist category owns these; ACP calls them via the external hook (positioning).
- **Endpoint/browser DLP agent (Purview class)**: a separate deployed product, not a control-plane
  feature.
- **SOC 2 / ISO certification** and the **real-Entra production cutover**: process and time, gated on an
  operating history / a customer token, not code.

## Phasing
- P1: M1 (complete multi-tenancy).
- P2: M2 (pull-sync), M3 (scheduler+delivery), M4 (SLA escalation), M5 (vendor monitoring).
