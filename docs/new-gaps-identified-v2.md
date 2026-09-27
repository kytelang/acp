# Varman (ACP): further gaps vs Credo AI and the Aegis/Lakera firewall class (v2)

Follow-on to `docs/new-gaps-identified.md` (all closed 2026-09-27). This round is depth-and-surfacing,
not capability-absence: the moat (per-action resource authz, signed evidence, kill-switch, attested
identity) already leads both categories. Each item has a design and concrete, verifiable acceptance
criteria. Priority: P1 first.

Key finding driving G1-G3: `acp-core` already has `usecase.rs` (gated lifecycle), `riskregister.rs`
(likelihood/impact/treatment) and `modelcard.rs` (joined cards), but none are wired into the server or
console; they collapse into free-form GRC records. Surfacing them is the highest value for lowest cost.

---

## G1. Enforced use-case lifecycle gates (P1) - surface `usecase.rs`  [DONE 2026-09-27]
Gap: Credo enforces multi-state, gated use-case workflows; ACP has the gate logic but does not enforce it.
Design: a GRC record of kind `use-case` carries a `stage` (proposed|assessed|approved|deployed|retired).
A new `POST /grc/:id/usecase/:stage` drives the transition through `acp_core::usecase`, refusing it
unless its gate is met: `assessed` requires the record to link an `assessment` GRC record; `approved`
requires a linked `attestation`. Re-signs on transition. Console shows the stage and only the valid next
actions.
Acceptance:
- A use-case record cannot advance to `assessed` without a linked assessment id (403/refused via curl);
  it advances once one is linked.
- It cannot advance to `approved` without a linked attestation; it advances once one is linked.
- The full path proposed -> assessed -> approved -> deployed -> retired succeeds when gates are met;
  each transition re-signs and `/grc` shows the record `verified: true`.
- The console use-case row shows the current stage and offers only the gated next transition(s).

## G2. Structured risk register (P1) - surface `riskregister.rs`  [DONE 2026-09-27]
Gap: risk is a free-form record; Credo has structured likelihood/impact scoring and treatment.
Design: a GRC kind `risk` whose body carries `{likelihood, impact (low|medium|high), treatment, owner,
status}`. `POST /grc/risk` computes `score = likelihood*impact` (each low=1/med=2/high=3, so 1..9) and a
severity band via `acp_core::riskregister::RiskItem`, storing them in the signed body and validating the
levels. Console renders a risk table with score + severity badge and a treatment lifecycle that re-signs.
Acceptance:
- Creating a risk with likelihood=high, impact=high returns and stores `score=9`, severity `critical`.
- An invalid level is rejected with a clear error.
- Advancing the status re-signs; `/grc` shows the record verified with the score preserved.
- The console risk table shows the score and a severity badge.
Status (2026-09-27): SHIPPED. Verified via curl: high/high -> 9 critical, low/medium -> 2 low, bad level
rejected, status transition re-signs and stays verified; console Risk register card + Add-risk modal.

## G3. Joined model cards (P1) - surface `modelcard.rs`  [DONE 2026-09-27]
Gap: model cards are free-form; Credo joins a card to its model, use-case and risk.
Design: a GRC kind `model-card` whose body references `{model_id, use_case_id, risk_id}`. On read the
server resolves each id (models row / GRC records) and reports which links resolve. Console shows the
joined card with links to the model, use-case and risk.
Acceptance:
- A model-card referencing a real `models` row + a real use-case + a real risk reports all three links
  resolved via `/grc` (a `links` object with resolved booleans).
- A dangling reference reports `resolved:false` for that link (never errors).
- The console model-card view shows the resolved model/use-case/risk.
Status (2026-09-27): SHIPPED. `POST /grc/model-card` (kind model-card, body references
model_id/use_case_id/risk_id); `grc_list` resolves each ref (models row / use-case GRC / risk GRC) and
returns a `links` object with per-link booleans (never errors on a dangling ref). Console Governance
view has a Model cards table with resolved link badges + a create modal. Verified via curl: all-valid ->
model/use_case/risk all true; a dangling model_id -> model:false, others true.

## G4. Stakeholder notifications on events (P1) - wire `webhook.rs` + `notify.rs`  [DONE 2026-09-27]
Gap: no task notifications, comment threads, or event fan-out; Credo's core loop is collaboration.
Design: server config `--webhook-url` (+ optional `--webhook-secret`). On GRC create, GRC status/stage
change, GRC assignment, and on violation events, the server POSTs a structured, HMAC-signed event via
`acp_core::webhook`/`notify` (user-controlled fields as JSON values only, never interpolated into markup).
Acceptance:
- With `--webhook-url` set, creating a GRC record POSTs a `grc.created` event to the webhook; recording
  a violation POSTs a `violation` event (verified against a mock receiver).
- Each request carries an HMAC-SHA256 signature header that the receiver verifies against the secret.
- A crafted tool name (e.g. containing markup) appears only as a JSON value in the payload, never
  interpolated (verified by inspecting the received body).
- Assigning a GRC record fires a `grc.assigned` event naming the assignee.
Status (2026-09-27): SHIPPED. Server `--webhook-url` + `--webhook-secret`; a `fire_webhook` helper
builds `{type, ts_ms, event}`, signs it with `acp_core::webhook::sign_webhook` (HMAC-SHA256, header
`x-acp-signature: t=..,v1=..`) and POSTs non-blocking. Wired on grc.created, grc.status, grc.assigned
and violation. Verified against a mock receiver: all three event types delivered, each signature
verifies, and crafted markup in a title/tool name appears only as a JSON value.

## G5. Pack + threat-feed breadth and an update channel (P2)  [DONE 2026-09-27]
Gap: only 3 built-in framework packs and a manual threat-pack load; Credo ships many jurisdictions with
continuously-updated policy intelligence.
Design: `--packs-feed-url` and `--threat-feed-url` the server polls on an interval; it fetches signed
packs, verifies them, and loads them (idempotent). Ship at least two more built-in framework packs
(e.g. SOC 2 and GDPR control mappings) in `acp_core::controls`/`pack`.
Acceptance:
- With `--packs-feed-url` pointed at a mock feed serving a signed pack, the server ingests it on refresh
  and `/packs` shows it `verified: true`; a tampered feed pack is rejected.
- `GET /packs/available` returns at least 5 built-in framework packs (3 original + 2 new).
- The new packs' controls appear via `/controls?framework=...`.
Status (2026-09-27): SHIPPED. Two new built-in framework packs (SOC 2, GDPR) in `controls`/`pack` (5
total). Server `--packs-feed-url` and `--threat-feed-url` poll on a 60s interval, verifying each signed
pack before loading. Verified: `/packs/available` returns 5 packs; SOC 2 controls surface via
`/controls?framework=soc2`; a feed serving 5 packs (one tampered) loads the 4 valid ones (verified:true)
and rejects the tampered one with a WARN.

## F1. Streaming (SSE) response gating (P1)  [DONE 2026-09-27]
Gap: the gateway gates only non-streaming responses; streamed chat responses relay ungated.
Design: when a response gate is active (content firewall, external hook or groundedness) and the upstream
streams, the gateway buffers the stream, runs `response_gate` on the accumulated text, then emits the
result (or a blocked event). When no gate is active, streaming stays passthrough (unchanged).
Acceptance:
- With a response gate active and the upstream streaming, a streamed response containing a blocked
  category is blocked (the client never receives the unsafe content).
- A clean streamed response is delivered when a gate is active.
- With no response gate configured, a streamed response is relayed passthrough (unchanged behaviour).
Status (2026-09-27): SHIPPED. When a response gate is active the gateway buffers the SSE stream,
gathers assistant text across `data:` events (`gather_sse_text`), runs `response_gate` and either emits
a blocked SSE event or replays the buffered stream; with no gate it stays chunk-by-chunk passthrough.
Verified e2e: an injected streamed response -> blocked SSE event; a clean streamed response -> all
deltas delivered; no gate -> injected stream relayed unchanged.

## F2. First-party toxicity signal (P2)  [DONE 2026-09-27]
Gap: injection/PII/secrets/groundedness are built; toxicity relies on the external hook or an ML model.
Design: a lightweight, on by flag toxicity lexicon scorer behind the existing `Scorer` seam in
`acp_core::content`, emitting a `toxicity` finding; blocks per policy. The external hook remains the path
to a stronger classifier.
Acceptance:
- With the toxicity scorer enabled, a clearly toxic phrase is flagged `toxicity` and blocked; benign
  text is not flagged.
- With it disabled (default), behaviour is unchanged.
- A unit test covers the lexicon precision on a small labelled set.
Status (2026-09-27): SHIPPED. `ContentPolicy.block_toxicity` + a `ToxicityScorer` lexicon behind the
Scorer seam (emits a `toxicity` finding, blocks per policy); off by default. Plumbed through
firewall_config (cpstore column + server GET/POST + PEP fetch) and the console Content firewall toggle.
Verified: unit test flags toxic only when enabled and leaves benign alone; config round-trips
block_toxicity. The external hook remains the path to a stronger ML classifier.

## F3. Surface runtime monitors in the console (P2) - `drift.rs`, `lineage.rs`  [DONE 2026-09-27]
Gap: classifier-drift and data-class lineage exist as libraries but are not surfaced.
Design: PEPs report per-class hit-rate counts (drift) and per-decision data-class lineage to the control
plane; the server aggregates and the console shows a drift panel (per-class live vs baseline) and a
lineage view (which data class reached which tool), counts only, never raw values.
Acceptance:
- A PEP reporting class hit-rate counts causes the console drift panel to show a per-class rate and flag
  any class beyond tolerance.
- The lineage view shows data-class-to-tool edges from reported counts, with no raw argument values.
Status (2026-09-27): SHIPPED. cpstore `drift_counts` + `lineage_edges`; server `POST/GET /monitor/drift`
(per-class live rate vs baseline, drifted flag via `acp_core::drift::DriftMonitor`) and
`POST/GET /monitor/lineage` (report-token gated ingest). The acp-proxy reports per-class drift + data-
class->tool lineage after each content scan (counts only, best-effort, reusing the report URL). Console
Monitors view shows the drift table (stable/drifted) and the lineage table. Verified via curl: secret
rate 0.30 vs baseline 0.90 -> drifted; pii holds; lineage edges accumulate.

## F4. Detection corpus scale + firewall latency benchmark (P2)  [DONE 2026-09-27]
Gap: the C3 corpus is a 45-example seed; there is no published firewall-path latency figure.
Design: grow the labelled corpus (target >= 200 examples across injection/PII/benign) and add a
criterion/bench (or a timed test) measuring content-scan latency; publish both in the guide.
Acceptance:
- The corpus has >= 200 labelled examples with stated provenance; the `corpus_gate` thresholds still hold.
- A latency measurement for a single content scan is produced and published in the guide (a number, with
  the method).
Status (2026-09-27): SHIPPED. Corpus grown to 213 labelled examples (86 injection / 37 PII / 90 benign);
the `corpus_gate` thresholds still hold (injection 1.00/1.00/0.00, PII precision 1.00 recall 0.92). A
`content_scan_latency_is_reported` test measures ~70 us/scan over the corpus (CI ceiling 2 ms); the
numbers and method are published in guide chapter 15.

## G6. Vendor risk questionnaire (P3)  [DONE 2026-09-27]
Gap: the vendor registry stores only a score; Credo runs vendor questionnaires/continuous monitoring.
Design: a vendor record carries a small structured questionnaire (data residency, sub-processors,
certifications, incident history) that computes into the risk score; console form + display.
Acceptance:
- A vendor created with questionnaire answers stores them and a computed risk score/band.
- The console vendor view shows the questionnaire and the computed band.
Status (2026-09-27): SHIPPED. `POST /vendors` accepts a `questionnaire` (data_residency, sub_processors,
certifications[], incidents) and computes a deterministic score + band (low/medium/high/critical),
storing both in the vendor's risk_json. Console vendor modal collects the questionnaire; the Vendors
table shows the risk band. Verified via curl: EU/2 subs/2 certs/0 incidents -> score 0 low; offshore/8
subs/no certs/2 incidents -> score 13 critical.

---

## Deliberately integrate-not-build (stated, not gaps)
- Multi-modal (image/audio) content scanning, first-party multi-format model-artifact scanning + MITRE
  ATLAS, and model bias/fairness/explainability dashboards: called via the external hook / delegated to
  the specialist category, per `docs/positioning.md`.

## Suggested phasing
- P1: G1, G2, G3 (surface governance depth), G4 (stakeholder notifications), F1 (streaming gating).
- P2: G5 (pack/threat breadth), F2 (toxicity), F3 (monitor surfacing), F4 (corpus+bench).
- P3: G6 (vendor questionnaire).
