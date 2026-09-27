# Varman (ACP): third-round gaps vs Credo AI and the Aegis/Lakera class (v3)

Follow-on to v1 (`docs/new-gaps-identified.md`) and v2 (`docs/new-gaps-identified-v2.md`), both closed.
This round is scale and enterprise-platform maturity. Each item has a design and verifiable acceptance
criteria. Priority: P1 first.

---

## T1. Multi-tenancy for the governance + registry data plane (P1)  [DONE 2026-09-27]
Gap: the control plane is single-tenant; a large org governing several business units cannot isolate
their data. Scope for this slice: the multi-record tables (grc_records, apps, agents, models, vendors).
Design: add a `tenant_id` column (default `default`) to those tables; the server resolves the tenant
per request from the `x-acp-tenant` header, else the authenticated principal's Entra tenant, else
`default`; every create stamps the tenant and every list/read is scoped to it. Cross-tenant reads return
nothing; a cross-tenant status/transition on another tenant's record is refused.
Acceptance:
- Creating a GRC record (and an app/agent/model/vendor) under tenant `A` and another under tenant `B`,
  then listing as `A`, returns only `A`'s records (verified via curl with `x-acp-tenant`).
- A get/transition on a `B`-owned record while acting as `A` is not found / refused.
- With no tenant header and no principal tenant, everything lands in `default` (no regression to the
  existing single-tenant behaviour and tests).
Status (2026-09-27): SHIPPED. `tenant_id` on grc_records/apps/agents/models/vendors; `tenant_of` resolves
the `x-acp-tenant` header, else the principal's Entra tenant, else `default`. Every create stamps it,
every list/get is scoped, and by-id transitions verify tenant ownership (cross-tenant -> no such record).
Verified via curl: acme sees only its GRC + apps, globex only its own, an acme transition on a globex
record is refused, and no-header lands in default. cpstore tests pass. (Console operates in the default
tenant until a tenant switcher is added; firewall_config + control singletons remain global by design.)

## T2. Load and throughput benchmark (P1)  [DONE 2026-09-27]
Gap: only a single-scan micro-latency (~70 us) is published; no concurrency / p99 figure.
Design: an offline benchmark (a test or a small harness) that drives the content-scan path (and,
optionally, the gateway) under concurrency and reports throughput (scans/sec) and p50/p95/p99 latency.
Publish the numbers and the method in the guide.
Acceptance:
- A benchmark runs the content-scan path across N concurrent workers and reports scans/sec plus
  p50/p95/p99 latency (a number, with the method).
- The numbers and how to reproduce them are published in the guide.
Status (2026-09-27): SHIPPED. `content_scan_throughput_and_percentiles` (ignored by default; run with
`cargo test -p acp-core --release -- --ignored --nocapture`) drives the scan path across 8 concurrent
workers (40k scans) and reports scans/sec + p50/p95/p99. Measured on the dev machine: ~690k scans/sec,
p50 6.5 us / p95 14 us / p99 25 us; published in guide chapter 15.

## T3. Bi-directional ticketing callback (P2)
Gap: events go out (G4 webhooks) but nothing comes back; Credo/ServiceNow buyers expect two-way sync.
Design: an inbound `POST /tickets/callback` (HMAC-verified with the webhook secret) that maps a ticket
resolution to an ACP action: resolve an approval hold (approve/deny) or advance a GRC record's status.
Acceptance:
- A signed callback that approves a held approval resolves that hold to `approved` (verified).
- A callback with a bad signature is rejected.
- A callback advancing a GRC record's status re-signs and the record still verifies.

## T4. Multilingual detection signatures (P2)
Gap: injection signatures and the toxicity lexicon are English-only.
Design: add non-English injection signatures (at least Spanish, French, German for the common
"ignore previous instructions" family) to `acp_core::content`; the external hook remains the path to
full multilingual ML.
Acceptance:
- A non-English injection phrase (for example the Spanish "ignora las instrucciones anteriores") is
  flagged as prompt-injection by the built-in engine.
- English detection is unchanged (the corpus gate still holds).

## T5. Collaboration: GRC comments (P2)
Gap: no comment threads / discussion on governance records.
Design: a `grc_comments(id, grc_id, author, body, created_ms)` table; `POST /grc/:id/comments` and
`GET /grc/:id/comments`; console shows a comment thread on a record. Author-controlled text is stored
and rendered as a value (escaped), never interpolated.
Acceptance:
- A comment posted to a record is stored and returned by the list endpoint with its author and time.
- Comments are scoped to their record (a different record returns none).

## T6. Scheduled report snapshots + history (P3)
Gap: reports are on-demand only; no history or scheduled capture.
Design: a `report_snapshots(id, framework, body_json, created_ms)` table; `POST /report/framework/:name/snapshot`
stores the current framework report; `GET /report/framework/:name/history` lists snapshots newest-first.
A cron calls the snapshot endpoint on a schedule.
Acceptance:
- Taking a snapshot stores the current framework report; the history endpoint lists it with a timestamp.
- Two snapshots produce two history entries in order.

---

## Deliberately still integrate-not-build
- Multi-modal (image/audio) scanning, a first-party multi-format model-artifact scanner + MITRE ATLAS,
  model bias/fairness/explainability dashboards, and an endpoint/browser DLP agent: delegated to the
  specialist category / called via the external hook, per `docs/positioning.md`.
- Certifications (SOC 2 / ISO) and the real-Entra production cutover are process/time, not code (C2).

## Suggested phasing
- P1: T1 (multi-tenancy slice), T2 (load benchmark).
- P2: T3 (ticketing callback), T4 (multilingual), T5 (comments).
- P3: T6 (scheduled snapshots).
