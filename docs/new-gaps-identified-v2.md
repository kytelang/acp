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

## G2. Structured risk register (P1) - surface `riskregister.rs`
Gap: risk is a free-form record; Credo has structured likelihood/impact scoring and treatment.
Design: a GRC kind `risk` whose body carries `{likelihood:1-5, impact:1-5, treatment, owner, status}`.
The server computes a `score = likelihood*impact` and a severity band, stores them in the signed body,
and validates the 1-5 ranges. Console renders a risk table with score + severity badge and a treatment
lifecycle (open -> mitigating -> accepted/closed) that re-signs.
Acceptance:
- Creating a risk with likelihood=4, impact=5 returns and stores `score=20`, severity `critical`.
- Out-of-range likelihood/impact is rejected with a clear error.
- Advancing the treatment status re-signs; `/grc` shows the record verified with the score preserved.
- The console risk table shows the score and a severity badge.

## G3. Joined model cards (P1) - surface `modelcard.rs`
Gap: model cards are free-form; Credo joins a card to its model, use-case and risk.
Design: a GRC kind `model-card` whose body references `{model_id, use_case_id, risk_id}`. On read the
server resolves each id (models row / GRC records) and reports which links resolve. Console shows the
joined card with links to the model, use-case and risk.
Acceptance:
- A model-card referencing a real `models` row + a real use-case + a real risk reports all three links
  resolved via `/grc` (a `links` object with resolved booleans).
- A dangling reference reports `resolved:false` for that link (never errors).
- The console model-card view shows the resolved model/use-case/risk.

## G4. Stakeholder notifications on events (P1) - wire `webhook.rs` + `notify.rs`
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

## G5. Pack + threat-feed breadth and an update channel (P2)
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

## F1. Streaming (SSE) response gating (P1)
Gap: the gateway gates only non-streaming responses; streamed chat responses relay ungated.
Design: when a response gate is active (content firewall, external hook or groundedness) and the upstream
streams, the gateway buffers the stream, runs `response_gate` on the accumulated text, then emits the
result (or a blocked event). When no gate is active, streaming stays passthrough (unchanged).
Acceptance:
- With a response gate active and the upstream streaming, a streamed response containing a blocked
  category is blocked (the client never receives the unsafe content).
- A clean streamed response is delivered when a gate is active.
- With no response gate configured, a streamed response is relayed passthrough (unchanged behaviour).

## F2. First-party toxicity signal (P2)
Gap: injection/PII/secrets/groundedness are built; toxicity relies on the external hook or an ML model.
Design: a lightweight, on by flag toxicity lexicon scorer behind the existing `Scorer` seam in
`acp_core::content`, emitting a `toxicity` finding; blocks per policy. The external hook remains the path
to a stronger classifier.
Acceptance:
- With the toxicity scorer enabled, a clearly toxic phrase is flagged `toxicity` and blocked; benign
  text is not flagged.
- With it disabled (default), behaviour is unchanged.
- A unit test covers the lexicon precision on a small labelled set.

## F3. Surface runtime monitors in the console (P2) - `drift.rs`, `lineage.rs`
Gap: classifier-drift and data-class lineage exist as libraries but are not surfaced.
Design: PEPs report per-class hit-rate counts (drift) and per-decision data-class lineage to the control
plane; the server aggregates and the console shows a drift panel (per-class live vs baseline) and a
lineage view (which data class reached which tool), counts only, never raw values.
Acceptance:
- A PEP reporting class hit-rate counts causes the console drift panel to show a per-class rate and flag
  any class beyond tolerance.
- The lineage view shows data-class-to-tool edges from reported counts, with no raw argument values.

## F4. Detection corpus scale + firewall latency benchmark (P2)
Gap: the C3 corpus is a 45-example seed; there is no published firewall-path latency figure.
Design: grow the labelled corpus (target >= 200 examples across injection/PII/benign) and add a
criterion/bench (or a timed test) measuring content-scan latency; publish both in the guide.
Acceptance:
- The corpus has >= 200 labelled examples with stated provenance; the `corpus_gate` thresholds still hold.
- A latency measurement for a single content scan is produced and published in the guide (a number, with
  the method).

## G6. Vendor risk questionnaire (P3)
Gap: the vendor registry stores only a score; Credo runs vendor questionnaires/continuous monitoring.
Design: a vendor record carries a small structured questionnaire (data residency, sub-processors,
certifications, incident history) that computes into the risk score; console form + display.
Acceptance:
- A vendor created with questionnaire answers stores them and a computed risk score/band.
- The console vendor view shows the questionnaire and the computed band.

---

## Deliberately integrate-not-build (stated, not gaps)
- Multi-modal (image/audio) content scanning, first-party multi-format model-artifact scanning + MITRE
  ATLAS, and model bias/fairness/explainability dashboards: called via the external hook / delegated to
  the specialist category, per `docs/positioning.md`.

## Suggested phasing
- P1: G1, G2, G3 (surface governance depth), G4 (stakeholder notifications), F1 (streaming gating).
- P2: G5 (pack/threat breadth), F2 (toxicity), F3 (monitor surfacing), F4 (corpus+bench).
- P3: G6 (vendor questionnaire).
