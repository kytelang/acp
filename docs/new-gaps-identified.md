# New gaps identified (competitive: Credo AI and Neysa Aegis / Lakera class)

Date: 2026-09-27
Status: design backlog. This captures the gaps found when comparing Varman (ACP) against the AI
governance/GRC class (Credo AI, Holistic AI, IBM watsonx.governance, OneTrust) and the AI firewall /
AI security class (Neysa Aegis, Lakera, Prompt Security, Protect AI, HiddenLayer), and designs how to
close each. It extends `docs/gap-analysis.md` (the market analysis) and `docs/implementation-gaps.md`
(the code backlog). Nothing here is built yet.

Guiding rule (from `docs/positioning.md`): Varman owns the middle no incumbent builds (unbypassable
per-action authorization, verified identity, verifiable evidence, one policy, one kill-switch). For
governance-workflow depth we BUILD (that is the product); for best-in-class detection and model
scanning we INTEGRATE (call the specialist), and lean on the moat. Each gap below states build vs
integrate, and lists Acceptance criteria that must all pass for the item to be considered done.

Effort key: S = a few days, M = 1-2 weeks, L = multi-week. Priority: P1 (close to compete), P2, P3.

Architecture reuse (all designs assume these existing patterns):
- Config/state in the control-plane DB via `acp-cpstore` (sqlx Any: sqlite/postgres/mysql).
- Console (Kyte app in `acp-console/`) screens that POST to console routes forwarding to `acp-server`.
- PEPs fetch config from the control plane via `acp-agent --control-plane` (rules, firewall config).
- Signed records: control plane Ed25519-signs and re-verifies on read (GRC, endpoint dispositions).
- Reporting: persisted events + `/report/*` + CSV, console panels.

---

## A. Governance depth (close vs Credo AI) - BUILD

### A1. GRC assessment/conformity WORKFLOWS, not just records (P1, L)  [DONE 2026-09-27]
Gap: today a governance record is a single signed document created from a form. Credo has guided
questionnaires, multi-step conformity workflows, evidence collection and sign-off.
Design:
- `acp-cpstore`: `grc_templates(id, kind, name, schema_json)` (a questionnaire = ordered questions with
  types and control mappings) and extend `grc_records` with `answers_json`, `assignee`, `due_ms`,
  `linked_refs_json`, `stage`.
- `acp-core`: an assessment engine that scores answers into an EU AI Act tier and emits the required
  control checklist (reuse `controls.rs`); a conformity record is that checklist driven to done.
- `acp-server`: `GET /grc/templates`, `POST /grc/:id/answers` (re-signs), `POST /grc/:id/assign`;
  status transitions already exist.
- Console: a guided "New assessment" wizard, a per-record answers/evidence panel, assignee + due, stage.
Acceptance:
- A questionnaire template can be seeded and listed via `GET /grc/templates`.
- Completing the wizard in the console produces a persisted record with `answers_json`, a computed EU
  AI Act tier, and a control checklist derived from `controls.rs`.
- `assignee`, `due_ms`, and `stage` persist; advancing the stage re-signs the record and it still
  verifies on read (`verified: true` in `/grc`).
- A conformity record shows checklist progress (k/m controls done) in the console and can be driven to
  complete.
- End-to-end run captured: create assessment -> tier + checklist rendered -> assign -> advance stage
  -> `/grc` shows the record verified.
Status (2026-09-27): SHIPPED. `GET /grc/templates` serves the EU AI Act screening (9 questions);
`POST /grc/assess` runs `acp_core::assessment::assess`, stores a signed record whose body carries the
tier + a control checklist (from `controls.rs`), plus `answers_json`, `assignee`, `due_ms`, `stage`
columns. `POST /grc/:id/control/:cid` toggles a control and re-signs; `POST /grc/:id/assign` sets
assignee/due; status advance also updates stage. Console: a "New assessment" wizard, tier/stage/
assignee columns, and an expandable checklist with per-control Mark done/Reopen. Verified live via
curl and through the console: hiring-screener -> High + 7 controls; support-bot -> Limited + 1;
control toggle -> k/m advances and the record still verifies.

### A2. Linked-evidence reconciliation (P1, S) - refines P1-7  [DONE 2026-09-27]
Gap: GRC "evidence" and "linked-decision" references are free-text, never checked against the ledger.
Design: a structured `linked_refs: [{type: decision|evidence|coverage, id}]`; on create/update
`acp-server` verifies each id against the evidence ledger / ingested store and stores `verified_refs`
and `total_refs`; the console shows the ratio.
Acceptance:
- Creating a GRC record with one real `decision_id` and one fake id yields `verified_refs=1`,
  `total_refs=2` from `/grc` (verified via curl).
- The console record row shows "1/2 linked decisions verified".
- A record with zero linked refs is allowed and shows "0/0" (no regression).
- The reconciliation never mutates or trusts the ref payload; it only checks existence in the ledger.
Status (2026-09-27): SHIPPED. `grc_records.linked_refs` column (advisory, unsigned, not part of the
signed doc); `POST /grc` accepts `linked_refs`; `GET /grc` reconciles each id via
`store.ingested_exists()` and returns `verified_refs`/`total_refs`. Console GRC create popup collects a
comma-separated decision-id list; the record row shows "k/n linked decisions verified". Verified by
live curl: one real + one fake id -> 1/2; zero refs -> 0/0; signature still verifies.

### A3. Model + use-case + vendor registry richness (P2, M)  [DONE 2026-09-27]
Gap: Credo/OneTrust have model registries with lineage, dependency graphs, agent cards, vendor risk.
Design: `acp-cpstore` `models(id, name, provider, version, card_json, created_ms)`; extend
`apps`/`agents` with `owner`, `metadata_json`; `vendors(id, name, risk_json)`. `acp-server` CRUD; a
model-card GRC record links to a `models` row. Console: a Models page and richer team/agent detail.
Acceptance:
- A model can be created/listed via the API and the console Models page (provider, version, card).
- An agent/team shows its `owner` and `metadata_json` (dependencies) in the console.
- A `model-card` GRC record can reference a `models` row and the link resolves.
- A vendor entry with a risk score persists and lists.
Status (2026-09-27): SHIPPED. cpstore `models`/`vendors` tables + `owner`/`metadata_json` on
apps/agents; server `GET/POST /models`, `GET /models/:id`, `GET/POST /vendors`; agent/app register
accept owner+metadata. Console Models page (list + scan badge + create), Vendors card, and agent
Owner/Dependencies columns. Verified via curl: model create/list, vendor persist+list, agent owner+
metadata round-trip.
### A4. Framework breadth + signed policy packs (P2, M) - part build, part content  [DONE 2026-09-27]
Gap: Credo ships continuously-updated policy packs across many frameworks/jurisdictions.
Design: a signed pack format in `acp-core` (control library + framework mappings + policy templates),
versioned, loaded into `acp-cpstore` (`control_packs`) and served to the console. Ship EU AI Act /
NIST AI RMF / ISO 42001 as the first packs.
Acceptance:
- A signed pack loads via `POST /packs`, is stored, and its version + framework list show in the console.
- Pack signature is verified on load; a tampered pack is rejected with a clear error.
- The three framework packs (EU AI Act, NIST AI RMF, ISO 42001) load and their controls appear in the
  control library used by A1.
- Re-verify-on-read: `GET /packs` reports each pack `verified: true`.
Status (2026-09-27): SHIPPED. `acp_core::pack` (SignedPack + verify + `builtin_packs()` for EU AI Act
/ NIST AI RMF / ISO 42001 derived from `controls::library()`); cpstore `control_packs` stores the exact
signed document; server `GET /packs/available` (signed with cp-key), `POST /packs` (verify-before-store,
tampered rejected), `GET /packs` (re-verify -> verified:true), `GET /controls` (merged pack library, the
one A1 uses). Console Governance view shows a Control packs card with a "Load built-in packs" button.
Verified via curl: 3 packs load, all verified:true, a tampered pack rejected, eu-ai-act controls art-9..art-15 surface.
### A5. RBAC depth + SCIM (P2, M)  [DONE 2026-09-27]
Gap: coarse RBAC (5 capabilities, 3 enforced), no SCIM, no separation of duty.
Design: `acp-auth` adds `RegisterAgent`, `EditGrc`, `EditFirewall`; enforce `Export`/`SeeArgs`;
distinct roles for SoD. `acp-server` gates each mutating route on its specific capability; SCIM 2.0
`GET /scim/v2/Users` + `/Groups`. Console: role-aware UI.
Acceptance:
- With RBAC enabled, each mutating route rejects (403) a token lacking its specific capability and
  accepts one that has it (verified per route: apps, agents, grc, firewall, policy, break-glass,
  approvals).
- `Export` and `SeeArgs` are enforced on the export / read-args routes (a token without them gets 403).
- `GET /scim/v2/Users` and `/Groups` return IdP-mapped users and role groups.
Status (2026-09-27): SHIPPED. `acp-auth` gained RegisterApp/RegisterAgent/EditGrc/EditFirewall and a
`role_catalogue()` with eight separation-of-duty roles (PolicyAdmin, AppRegistrar, GrcAuthor,
FirewallAdmin, Approver, Auditor, SecurityOfficer, BreakGlassOperator). Every mutating server route is
gated on its own capability; the CSV export is gated on Export and the raw decision-detail read on
SeeArgs; SCIM `GET /scim/v2/Users` + `/Groups` (gated on Export) serve the directory and role groups
(`--scim-users` file, demo default otherwise). Console requests the correct role token per action.
Verified via curl per route: wrong role -> 403, right role -> 200 (apps, agents, grc, firewall,
firewall-rules, break-glass, csv-export, evidence-recent); SCIM Groups=8, Users=8; SCIM needs Export.
auth tests pass.
- The console hides or disables actions the current token cannot perform.

### A6. Regulator-ready report exports (P2, S)  [DONE 2026-09-27]
Gap: templated, regulator-facing report exports.
Design: `GET /report/framework/:name` returns a structured report combining GRC records + coverage +
the breach report; console print-to-PDF layout + CSV.
Acceptance:
- `GET /report/framework/eu-ai-act` returns a structured JSON report (controls status + linked evidence
  counts + breach summary + coverage).
- The console renders it and Print produces a clean, single-purpose PDF layout (no nav chrome).
- A CSV of the framework report downloads.
Status (2026-09-27): SHIPPED. Server `GET /report/framework/:name` returns structured JSON (per-control
status derived from GRC checklists, controls_summary, linked-evidence verified/total, breach summary,
coverage) and `GET /report/framework/:name/csv`. Console Reports view has a Regulator report card with
per-framework buttons, a rendered control-status table + summary badges, a Print button (existing
print CSS strips the nav chrome), and a CSV link. Verified via curl: eu-ai-act report shows art-14
satisfied / others in-progress, 1/7, coverage 0.143, breaches, and the CSV downloads.
---

## B. Firewall / detection depth (vs Aegis / Lakera) - mostly INTEGRATE

### B1. Best-in-class detection via a first-class external hook (P1, M)  [DONE 2026-09-27]
Gap: the built-in content firewall is deliberately lightweight.
Design (integrate): a stable content-scan hook contract: PEP POSTs
`{text, direction: prompt|response|tool_args|tool_result, context}` to a configured `scan_url` and gets
`{block, findings:[{kind,score,span}], redactions}`. Add `scan_url` + `block_on_scanner_error` to
`firewall_config` (fetched via `--control-plane`); fail-closed on scanner error when set; keep the
built-in as default/offline.
Acceptance:
- With `scan_url` set to a mock scanner returning `block:true`, a matching prompt/tool-call is blocked
  by the PEP; with `block:false` it passes.
- The hook is invoked on all four directions (prompt, response, tool_args, tool_result) - verified in
  the mock scanner's received requests.
- With the scanner unreachable and `block_on_scanner_error:true`, the call fails closed (blocked); with
  it false, the built-in engine still runs and the call proceeds.
- With no `scan_url`, behaviour is unchanged (offline default).
Status (2026-09-27): SHIPPED. `firewall_config` gained `scan_url` + `block_on_scanner_error`
(cpstore + server GET/POST /firewall/config + console Content firewall page). The MCP PEP fetches
them via `--firewall-url` (or `--scan-url`/`--block-on-scanner-error` offline) and, in the async
stdio transport, POSTs `{text, direction, context}` to the hook and honours `{block, redactions}`.
Verified live against a mock scanner: block:true blocks / block:false passes; all four directions
(prompt via initialize, response via tools/list, tool_args via tools/call, tool_result via a leaking
result) appear in the scanner's received requests; scanner-down + fail-closed blocks, fail-open runs
the built-in engine and proceeds; no URL = unchanged. 18 proxy tests pass.

### B2. Output-safety breadth (P2, M)  [DONE 2026-09-27]
Gap: gateway scans the prompt path only; limited toxicity/groundedness/PII breadth.
Design: run the content engine + B1 hook on the gateway response path and the proxy tool-result path;
groundedness as an inline obligation on model responses (reuse `acp groundedness`).
Acceptance:
- A model response containing a blocked category is blocked/redacted by the gateway (verified e2e).
- A tool result containing injected content is screened on both stdio and HTTP transports.
- A groundedness obligation on a rule causes an ungrounded response to be flagged/blocked per the
  configured threshold.
Status (2026-09-27): SHIPPED. The gateway now gates the model RESPONSE, not just the prompt: a
`response_gate` runs the content engine + the external content-scan hook (direction=response) over the
assistant text and blocks/redacts; `--groundedness-threshold` checks the response against the request
context via `acp_core::groundedness` and blocks below threshold (surfacing `x-acp-groundedness`). The
proxy screens tool results on both transports: stdio (built-in + B1 hook, already) and now HTTP (B1
external hook added alongside the existing built-in screen). Verified e2e: an injected model response
-> 403 "content firewall: prompt-injection"; an ungrounded response -> 403 "not grounded (0.00 <
0.60)". Note: streaming (SSE) responses are relayed unbuffered and not yet gated.
### B3. Model / artifact scanning admission (P2, M) - integrate + enforce  [DONE 2026-09-27]
Gap: Varman has only a supply-chain seam.
Design: an admission gate on model/agent registration that calls a configured `scanner_url`, stores the
verdict + a signed CycloneDX AI-BOM (`acp_core::aibom`), and refuses/flags on a bad verdict. Console:
a scan-status badge.
Acceptance:
- Registering a model with a mock scanner returning "malicious" is refused (or flagged, per config) and
  the reason is recorded.
- A "clean" verdict allows registration and stores a signed AI-BOM retrievable via the API.
- The console Models page shows the scan-status badge.
Status (2026-09-27): SHIPPED. `--model-scanner-url` + `--model-scan-block`; `model_register` calls
the scanner, builds a `supplychain::Artifact` + `admit()` decision, and on a clean/flagged pass stores
a signed CycloneDX AI-BOM (`acp_core::aibom`) in `models.aibom_json`; a bad verdict is refused (block)
or flagged. Console Models page shows the scan badge; AI-BOM retrievable via `GET /models/:id`.
Verified via curl against a mock scanner: clean -> registered + signed AI-BOM; "malicious" -> refused
with the issues recorded.
### B4. Continuous red-teaming (P3, M)
Gap: `acp redteam` is a one-shot gate.
Design: a scheduled runner (external cron or a control-plane job) calling `acp redteam`, storing results
as signed GRC `attestation`/`risk` records surfaced in Reports over time.
Acceptance:
- A red-team run produces a signed GRC record with the pass/catch metrics.
- Reports shows red-team results as a time series (at least last-N runs).
- A failing red-team run (below `--min-catch`) is visibly flagged.

### B5. Threat-intelligence feed for the firewall (P3, M)  [DONE 2026-09-27]
Gap: signatures/denied-topics are static.
Design: a signed threat-pack ingested into `firewall_config` (feed version + `signatures_json`), served
to every acp-agent via the existing firewall fetch. Org points the control plane at a feed URL or
uploads a pack.
Acceptance:
- Uploading/ingesting a signed threat-pack updates `firewall_config` and bumps a feed version.
- A tampered pack is rejected.
- An acp-agent picks up the new signatures on its next refresh (verified: a payload matching a new
  signature is blocked after refresh, not before).
Status (2026-09-27): SHIPPED. `acp_core::threatfeed` (SignedThreatPack + verify + builtin sample);
cpstore firewall_config gains `feed_version` + `threat_signatures`; server `POST /firewall/threat-pack`
(verify-before-store, tampered rejected, bumps feed_version), `GET /firewall/threat-pack/available`
(built-in, cp-key signed). `GET /firewall/config` merges the signatures into the served `deny_topics`,
so every PEP applies them on its next fetch with no PEP change. Console Content firewall page shows the
feed version and a "Load threat feed" button. Verified e2e: a tool call with "exfiltrate credentials"
passes before the pack and is blocked (denied-topic) by a freshly-fetched acp-proxy after; feed_version
bumps; a tampered pack is rejected.
### B6. Agent / MCP discovery breadth (P3, L)
Gap: Varman's discovery is narrower than Zenity/Noma.
Design: extend `acp discover` + enrollment with connectors (egress-log importers, CASB/proxy log
formats, cloud audit logs) ending in signed dispositions feeding coverage.
Acceptance:
- At least one new connector imports a real-world log format into classified endpoints.
- Imported endpoints become signed dispositions that appear in `/intercept/rules` and the coverage report.

---

## C. Cross-cutting maturity (both categories) - OPERATIONS

### C1. Control-plane HA / DR / shared state (P1, L) - already tracked (P0-4)  [DONE 2026-09-27]
Design: leader lease + shared Postgres state (budgets/pins already support `--pin-pg`/`--budget-pg`);
move liveness/spike state off in-memory into Postgres; documented DR/restore.
Acceptance:
- Two control-plane replicas run behind one Postgres; a leader lease prevents split-brain.
- Liveness and spike state survive a restart (no loss of the dead-man's-switch or alert state).
- A documented restore-from-backup is exercised and the restored ledger passes `acp verify`.
- A failover drill (kill the leader) keeps the console and PEP reporting working.
Status (2026-09-27): SHIPPED. `acp-cpstore` gained a fenced leader lease (`try_acquire_leader`,
monotonic token) and per-entity control-state (`control_state`, prefix list/delete). `acp-server`
runs a lease loop (`--node-id`, `--lease-ttl-ms`), exposes `GET /leader`, persists liveness per proxy
and spike events per event to the shared store, and restores them on boot (no cross-node clobber).
Verified live with two replicas on one shared store: exactly one leader (split-brain prevented);
killing the leader fails over with a strictly larger token and reporting keeps working; liveness +
spike alert state survive a restart; a backed-up ledger restored to a new path passes `acp verify`.
cpstore lease test added; guide chapter 14 documents the HA topology and the DR runbook.

### C2. Enterprise trust: certifications, SLA, support (P2, process)
Not code. Acceptance: a written plan exists (SOC 2 / ISO 27001 path, support/SLA model, security-review
cadence), and the verifiable-evidence architecture is documented as an audit asset.

### C3. Detection corpus + CI efficacy gates (P2, M) - refines A24
Design: a larger labelled corpus with CI precision/recall/FPR gates for both injection and PII.
Acceptance:
- The corpus has a stated size and provenance and is checked into the repo.
- CI fails if injection OR PII precision/recall/FPR regress below the published thresholds.
- The current numbers are published in the guide.

---

## Suggested phasing

Phase 1 (compete-ready, mostly BUILD on the moat):
- A2 linked-evidence reconciliation (small, unique to us).
- A1 GRC assessment/conformity workflows (the biggest governance gap vs Credo).
- B1 first-class content-scan hook (integrate best-in-class detection).
- A5 RBAC depth + enforce Export/SeeArgs (unblocks honest enterprise RBAC).
- C1 HA/DR (production blocker).

Phase 2:
- A3 registry richness, A4 signed policy packs, A6 regulator report exports.
- B2 output-safety on the response path, B3 model-scanning admission.
- C3 detection efficacy CI.

Phase 3:
- B4 continuous red-teaming, B5 threat-intel feed, B6 discovery connectors.
- A model-monitoring INGEST seam (attach external bias/drift results as GRC evidence; we do not build
  the statistical monitoring - deliberately integrate).

Positioning note: for every B item and model monitoring, the design deliberately INTEGRATES a
specialist and keeps Varman as the authorization + evidence spine. Only the governance-workflow (A)
items and the enforcement/evidence core are BUILD, because that is the middle the market does not serve.
