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
integrate.

Effort key: S = a few days, M = 1-2 weeks, L = multi-week. Priority: P1 (close to compete), P2, P3.

Architecture reuse (all designs assume these existing patterns):
- Config/state in the control-plane DB via `acp-cpstore` (sqlx Any: sqlite/postgres/mysql).
- Console (Kyte app in `acp-console/`) screens that POST to console routes forwarding to `acp-server`.
- PEPs fetch config from the control plane via `acp-agent --control-plane` (rules, firewall config).
- Signed records: control plane Ed25519-signs and re-verifies on read (GRC, endpoint dispositions).
- Reporting: persisted events + `/report/*` + CSV, console panels.

---

## A. Governance depth (close vs Credo AI) - BUILD

### A1. GRC assessment/conformity WORKFLOWS, not just records (P1, L)
Gap: today a governance record is a single signed document created from a form. Credo has guided
questionnaires, multi-step conformity workflows, evidence collection and sign-off.
Design:
- `acp-cpstore`: `grc_templates(id, kind, name, schema_json)` (a questionnaire = ordered questions with
  types and control mappings) and extend `grc_records` with `answers_json`, `assignee`, `due_ms`,
  `linked_refs_json` (evidence/decision ids), `stage`.
- `acp-core`: a small assessment engine that scores answers into an EU AI Act tier and emits the
  required-control checklist (reuse `controls.rs`); a conformity record is the checklist driven to done.
- `acp-server`: `GET /grc/templates`, `POST /grc/:id/answers` (re-signs), `POST /grc/:id/assign`,
  status transitions already exist. Validate `linked_refs` against the ledger (closes P1-7 too).
- Console: a guided "New assessment" wizard (question steps -> tier + checklist), per-record answer/
  evidence panel, assignee + due date, a stage badge.
Reuse: signed-record + re-verify pattern; the status controls already shipped.

### A2. Linked-evidence reconciliation (P1, S) - refines P1-7
Gap: GRC "evidence" and "linked-decision" references are free-text, never checked against the ledger.
Design: define a structured `linked_refs: [{type: decision|evidence|coverage, id}]` on the record;
on create/update, `acp-server` verifies each id exists in the evidence ledger / ingested store and
records a `verified_refs` count; the console shows "3/3 linked decisions verified". Makes GRC
paperwork provably tied to runtime evidence, which no competitor does.

### A3. Model + use-case + vendor registry richness (P2, M)
Gap: Credo/OneTrust have model registries with lineage, dependency graphs, agent cards, third-party
vendor AI risk. Varman has apps/agents only.
Design:
- `acp-cpstore`: `models(id, name, provider, version, card_json, created_ms)`, extend `apps`/`agents`
  with `owner`, `metadata_json` (lineage, dependencies); `vendors(id, name, risk_json)`.
- `acp-server`: CRUD routes; a model-card is a GRC `model-card` record linked to a `models` row.
- Console: a Models page and richer Team/Agent detail (owner, dependencies). Agent cards already exist
  conceptually via registration; add the metadata fields.

### A4. Framework breadth + signed policy packs (P2, M) - part build, part content
Gap: Credo ships continuously-updated policy packs across many jurisdictions/frameworks.
Design: a **signed pack** format (`acp-core`): a control library + framework mappings + policy
templates, Ed25519-signed, versioned, loaded into `acp-cpstore` (`control_packs` table) and served to
the console. Ship EU AI Act / NIST AI RMF / ISO 42001 as the first packs; the format lets an org add
its own or subscribe to updates. This is mostly content plus a small loader; reuse the signed-record
verify pattern for pack authenticity.

### A5. RBAC depth + SCIM (P2, M)
Gap: coarse RBAC (5 capabilities, only 3 enforced), no SCIM provisioning, no separation of duty.
Design (also A2/A16/A23 in implementation-gaps):
- `acp-auth`: add capabilities `RegisterAgent`, `EditGrc`, `EditFirewall`; enforce `Export`/`SeeArgs`
  on the read/export routes; distinct roles for SoD (policy author != agent registrar != approver).
- `acp-server`: gate each mutating route on its specific capability; a `GET /scim/v2/Users` +
  `/Groups` SCIM 2.0 endpoint mapping roles from the IdP.
- Console: role-aware UI (hide actions the token cannot perform).

### A6. Regulator-ready report exports (P2, S)
Gap: templated, branded, regulator-facing report exports.
Design: extend the Reports view with framework-scoped report generation (`GET /report/framework/:name`
-> a structured EU AI Act / NIST / ISO report combining the GRC records + coverage + the breach report),
downloadable as CSV today and a print-to-PDF layout; a templated HTML print stylesheet in the console.

---

## B. Firewall / detection depth (vs Aegis / Lakera) - mostly INTEGRATE

### B1. Best-in-class detection via a first-class external hook (P1, M)
Gap: the built-in content firewall is deliberately lightweight; Aegis/Lakera/Prompt Security ship
stronger, continuously-updated, multilingual, evasion-hardened detection.
Design (integrate, do not rebuild): define a stable **content-scan hook contract**: the PEP POSTs
`{text, direction: prompt|response|tool_args|tool_result, context}` to a configured scanner URL and
gets `{block: bool, findings: [{kind, score, span}], redactions}`. Wire it on all PEPs behind the
central firewall config (`scan_url` field added to `firewall_config`, fetched via `--control-plane`),
fail-closed on scanner error when `block_on_scanner_error` is set. Ship reference adapters for a
generic HTTP scanner; document Lakera/Prompt Security integration. Keep the lightweight built-in as the
default/offline path.

### B2. Output-safety breadth (P2, M)
Gap: gateway scans the prompt path only; limited toxicity/groundedness/PII breadth.
Design: run the content engine (and the B1 hook) on the **response** path in the gateway and the proxy
tool-result path (partly done for tool results); add groundedness as an inline obligation on model
responses (reuse `acp groundedness`); expand PII entity coverage via the external hook rather than
rebuilding a classifier.

### B3. Model / artifact scanning admission (P2, M) - integrate + enforce
Gap: Protect AI/HiddenLayer scan model files; Varman has only a supply-chain seam.
Design: an **admission gate** on model/agent registration: `acp-server` calls a configured scanner
(`scanner_url`) with the model reference, stores the verdict + a signed CycloneDX AI-BOM
(`acp_core::aibom` exists), and refuses registration (or flags) on a bad verdict. Console: a scan
status badge on the Models page. Varman calls the scanner; it does not build one.

### B4. Continuous red-teaming (P3, M)
Gap: `acp redteam` is a one-shot gate, not a continuous programme.
Design: a scheduled red-team runner (a control-plane job or external cron calling `acp redteam`) whose
results are stored as signed GRC `attestation`/`risk` records and surfaced in Reports over time. Reuse
the GRC record + report pattern; the scheduling can be external (documented) to avoid a scheduler in
the control plane.

### B5. Threat-intelligence feed for the firewall (P3, M)
Gap: no managed/updated threat feed; signatures/denied-topics are static.
Design: a **signed threat-pack** ingested into `firewall_config` (new `signatures_json` / feed version),
served to every acp-agent via the existing `--control-plane` firewall fetch. An org points the control
plane at a feed URL (or uploads a pack from the console). Reuses the firewall-config fetch+refresh
already built; the feed itself is content, optionally subscribed.

### B6. Agent / MCP discovery breadth (P3, L)
Gap: Zenity/Noma discover across many SaaS agent platforms; Varman's discovery is narrower.
Design: extend `acp discover` + enrollment with connectors (egress-log importers, CASB/proxy log
formats, cloud audit logs) that end in signed dispositions feeding coverage. Connector-per-source;
integrate rather than rebuild each platform's telemetry.

---

## C. Cross-cutting maturity (both categories) - OPERATIONS

### C1. Control-plane HA / DR / shared state (P1, L) - already tracked (P0-4)
Design: leader lease + shared Postgres state (budgets/pins already support `--pin-pg`/`--budget-pg`);
move liveness/spike state off in-memory into Postgres; documented DR/restore (WAL streaming, warm
standby) already drafted in the guide. This is the top production blocker.

### C2. Enterprise trust: certifications, SLA, support (P2, process)
Not code: SOC 2 / ISO 27001 path, support model, security review. Track separately; note that the
verifiable-evidence architecture is an asset for audits.

### C3. Detection corpus + CI efficacy gates (P2, M) - refines A24
Design: a larger labelled corpus for the content classifier with precision/recall/FPR CI gates for
both injection and PII, so the built-in floor is measured and does not regress. Publish the numbers.

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
