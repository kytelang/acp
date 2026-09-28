# Design and acceptance criteria: feature gaps, console parity, UI-first docs

This is the build spec for what remains. It folds three things into one plan:
1. the feature gaps from the second-opinion review (grounded in `docs/roadmap-tier-analysis.md`),
2. **console parity**: no feature is done until it is operable from the console, and
3. **UI-first documentation**: the guide teaches the console path first; curl is a secondary,
   clearly-labelled aside for automation only.

Every item below carries a design sketch, the console surface it must add, its documentation
requirement, and testable acceptance criteria. Nothing here needs a new crate.

## 0. Principles (apply to every item)

- **Console-first.** A feature that can only be driven by an API call is not complete. Each feature
  ships a console page or card, wired over the existing SSE + RouteHandler pattern.
- **UI-first docs.** For any task that has a console page, the guide shows the console steps first. A
  curl example may appear only under an explicit "API (for automation and CI)" aside, never as the
  primary instruction.
- **No new crates.** Everything lands as a module in the five-crate layout: `acp-core` (engine, GRC,
  monitors, policy, ledger), `acp-server` (control plane + store), `acp-gateway`, `acp-cli`,
  `acp-agent`. See section 1.
- **Evidence-backed.** Every governance action writes a signed record to the ledger, so the console
  and the reports derive from verifiable evidence, not a separate mutable table.

## 1. Crate layout (done)

The workspace was consolidated from 23 crates to **5**: `acp-core`, `acp-server`, `acp-gateway`,
`acp-cli`, `acp-agent`. Single-consumer and thin third-party wrappers became modules in their one
consumer; optional heavy backends (HSM, Postgres) are cargo features on `acp-core`; the redundant
`acp-verify` was dropped in favour of `acp verify` / `acp verify-pack`. A new capability must be a
module in one of these five, not a new crate, unless it is a genuinely reusable, separately-shippable
unit (none of the gaps below are).

## 2. Cross-cutting workstream A: console parity

**Rule.** Every operator-facing capability is reachable from the console. API-only is allowed only for
machine integrations, which are named explicitly below.

**Current state.** Existing features are surfaced (panels exist for approvals, evidence, violations,
reports, apps, agents, models, endpoints, policy, firewall, GRC, kill-switch, health, monitors,
vendors, risk, control packs, red-team, drift, lineage). The console is broadly complete for what
ships today.

**API-only by design (no console surface required):** SCIM provisioning (`/scim/*`, an IdP integration),
the inbound reporting/webhook/ticket callbacks (`/event`, `/heartbeat`, `/tickets/*`), and the
evidence-ingest endpoint. These are machine-to-machine and stay API-only.

**Acceptance (workstream A).**
- Every feature in section 4 ships with a console page or card before it is marked done.
- A reviewer can perform each feature's primary flow end to end in the console with no curl.
- The console page reads its data over SSE from a server endpoint and re-scopes with the tenant
  selector.
- Any capability deliberately left API-only appears in the "API-only by design" list above with a
  one-line reason.

## 3. Cross-cutting workstream B: UI-first documentation

**Rule.** The guide documents the console path first for any console-available task. curl is demoted to
a clearly-labelled "API (for automation and CI)" aside.

**Current state (curl audit of the guide).** curl is concentrated where a console page already exists:
`16-setup` (10), `11-containment` (6), `14-operations` (3), `08-identity` (2), `12-grc` (2). Tasks such
as registering an app or agent, transitioning a GRC record, registering an endpoint and engaging
break-glass all have console pages, yet are taught with curl.

**Acceptance (workstream B).**
- No guide chapter teaches a console-available task with curl as the primary method.
- Each remaining curl block is under an "API (for automation and CI)" heading or inline aside, and only
  for tasks that are genuinely automation-first (CI gates, `acp` CLI, webhook receivers).
- Each feature added in section 4 is documented console-first in its chapter, with screenshots or a step
  list, before any API note.
- A doc lint (grep for `curl ` outside an "API" aside) passes in CI, or a documented allowlist explains
  each permitted occurrence.

## 4. Feature gaps

Ordered by the recommended build sequence. Effort key: S = 1 to 2 weeks, M = 3 to 6 weeks, L = a
quarter or more.

### G1. Oversight-quality monitoring  (review #5, S)  [DONE 2026-09-28]

**Design.** A monitor over the approval records that scores each approver for rubber-stamping:
approve-rate near 100 percent, sub-threshold decision latency (for example under 5 seconds), and bulk
approvals in a short window. Emit a signed "oversight-weakness" finding per flagged approver. Lives in
`acp_core` (a new `oversight` module reading the approvals store) plus a server endpoint and a console
card. Maps to EU AI Act Article 14 (effective human oversight).

**Console.** A card on the Approvals (or Governance) page: a table of approvers with approve-rate,
median decision time, bulk-approval count, and a "weakness" badge; a threshold config.

**Docs.** A short section in `12-grc` (or `14-operations`) shown via the console card; no curl.

**Acceptance.**
- Given seeded approvals where one approver approves 20 of 20 within 2 seconds each, that approver is
  flagged and a signed finding is written to the ledger.
- An approver with mixed decisions and normal latency is not flagged.
- The thresholds (rate, latency, window) are configurable and the config change is itself audited.
- The console card lists flagged approvers and refreshes over SSE.

### G2. Least-privilege policy synthesis  (review #1, M, discounted)  [DONE 2026-09-28]

**Design.** Extend the existing `acp learn` (which today emits a coarse review policy from shadow
traffic) into minimal allow-only synthesis: from observed decisions, propose the smallest rule set that
permits exactly what was seen (per subject, resource, operation and argument class) and denies the rest,
emitted as the model-v2 DSL that compiles to Cedar. Surface the proposal as a diff against the live
policy and require human sign-off before it is signed and deployed.

**Console.** A "Suggested policy" panel on the Policy page: the proposed rules, a diff against the
current policy, the would-block list, and Approve/Reject. Approve signs and deploys via the existing
policy-store deploy path.

**Docs.** Rewrite the relevant part of `02-policy` to lead with the console proposal flow; keep the
`acp learn` CLI as the automation aside.

**Acceptance.**
- From a shadow ledger, the synthesiser proposes a policy that allows every observed action and denies a
  held-out unobserved action, verified by replaying both through the engine.
- The proposal is shown as a diff in the console and cannot deploy without an explicit human approval,
  which is recorded in the ledger.
- The deployed policy is signed and verifies with `acp verify`.

### G3. Plain-English policy authoring with verification  (review #2, M)

**Design.** A compliance user types a rule in natural language ("no agent may send customer data outside
the EU"). An LLM drafts the model-v2 DSL; the Cedar analyzer plus generated test cases show exactly what
the draft allows and blocks before deploy. The LLM call goes through the gateway (governed). The
verification step is mandatory and non-skippable.

**Console.** An "Author from description" box on the Policy page: text in, proposed rule + a generated
allow/deny test matrix out, then Approve to deploy.

**Docs.** New section in `02-policy`, console-first.

**Acceptance.**
- A natural-language rule produces a compilable DSL draft.
- The console shows a table of concrete example requests with allow/deny outcomes for the draft before
  deploy.
- Deploy is blocked until the author confirms the matrix; the confirmation and the source description
  are recorded with the signed policy.
- A draft that fails to compile or contradicts an existing higher-priority rule is reported, not
  deployed.

### G4. Post-market monitoring report  (review #9, S)

**Design.** Generate an Article 72 style monitoring plan and periodic report from runtime data already
collected: drift counts, block rates, violations, incidents, red-team results. A server endpoint
assembles the report; it is signed and snapshotted like the existing framework reports.

**Console.** A "Post-market monitoring" card on the Reports page: current period metrics, trend, and
Generate/Download (with a signed snapshot and history).

**Docs.** Extend `12-grc` reports section, console-first.

**Acceptance.**
- The report is generated purely from stored runtime data (no manual entry) and is signed.
- A snapshot is stored with history, and the CSV/download works from the console.
- Re-verifying a downloaded snapshot with the public key succeeds.

### G5. Serious-incident workflow  (review #8, M)

**Design.** Take an incident from detection to a case to root cause to a regulator report (EU AI Act
Article 73). A detected violation or alert can be promoted to an incident case; the case draws its
timeline and evidence from the ledger, tracks the reporting deadline, and produces a signed report.

**Console.** An Incidents page: open cases, their state (detected, investigating, root-caused,
reported), the deadline clock, linked evidence, and Generate report.

**Docs.** New chapter section, console-first; the ledger is the evidence source.

**Acceptance.**
- A violation can be promoted to an incident case from the console.
- The case timeline is assembled from ledger records, not hand-entered.
- A reporting-deadline countdown is shown and an overdue case is flagged.
- The generated report is signed and lists the evidence record ids it draws from.

### G6. Output-side DLP  (review #12, S)

**Design.** The response direction is already scanned for injection and tool-result poisoning. Add
first-class output DLP: detect PII, secrets and system-prompt leakage in responses, block or redact per
policy, and report separately from input findings. Extends `acp_core::content` scanning already wired on
the response path in `acp-agent` and the gateway.

**Console.** An "Output DLP" section on the Content firewall page: toggles (PII, secrets, prompt-leak),
recent output findings.

**Docs.** Extend `10-content-firewall`, console-first for the toggles.

**Acceptance.**
- A response containing a secret or PII is blocked or redacted per the configured mode, and the finding
  is recorded distinctly from input findings.
- System-prompt-leak patterns in a response are detected.
- Toggling the controls in the console changes enforcement on the next request with no restart.

### G7. Permission-aware retrieval  (review #3, M)

**Design.** At RAG retrieval time, enforce that the agent only receives documents the acting human may
see. A retrieval PEP path checks each candidate document's access against the delegated principal before
it reaches the model, and records the filtering decision.

**Console.** A "Retrieval policy" surface (likely under Policy or a new Data page): document-source to
access-rule mapping, and a recent-filtered-documents view.

**Docs.** New section, console-first.

**Acceptance.**
- Given a corpus with per-document ACLs, a retrieval for user U returns only U-visible documents; a
  document U cannot see is filtered and the filtering is recorded.
- The decision references the verified delegated principal, not a claim from the request.

### G8. Multi-agent delegation chains  (review #4, M)

**Design.** Extend the single-hop `Delegation` to a chain: when agent A calls agent B for user U,
authorize each hop against the whole chain (U to A to B), with rights that can only narrow along the
chain, and record the full chain in the ledger.

**Console.** A "Delegations" view: active chains, their scopes, and expiry; and chain context on
evidence records.

**Docs.** Extend `08-identity` delegation section, console-first.

**Acceptance.**
- A call by B on behalf of A on behalf of U is authorized against the chain; a right not held by A
  cannot be exercised by B (narrowing enforced).
- The ledger record for the action shows the full U to A to B chain.
- An expired hop anywhere in the chain fails closed.

### G9. Agent-memory protection  (review #6, M)

**Design.** Govern writes to agent persistent memory or a vector store: scan the content being persisted
(reusing the content engine) so a poisoned tool result or document cannot plant instructions the agent
later acts on, and record every memory write in the ledger for later incident tracing.

**Console.** A "Memory writes" view under Monitors: recent writes, any that were blocked or flagged.

**Docs.** New section, console-first.

**Acceptance.**
- A memory write containing injection-style content is blocked or flagged and recorded.
- A benign write is allowed and recorded.
- An incident can be traced from a later action back to the memory write that seeded it, via the ledger.

### G10. Fundamental-rights impact assessment (FRIA)  (review #7, S)

**Design.** An Article 27 FRIA template as a GRC record kind, linked to the use-case registry and any
DPIA. Reuses the existing assessment/checklist machinery.

**Console.** A FRIA wizard on the Governance page, like the existing assessment wizard.

**Docs.** Extend `12-grc`, console-first.

**Acceptance.**
- A FRIA record can be created and worked through the console, linked to a use-case, and signed.
- Its completion state feeds the framework report and coverage.

### G11. Transparency obligations and C2PA  (review #10, M)

**Design.** Add enforcement obligations "disclose AI interaction" and "label generated content," and
C2PA content-credential stamping of generated media, with proof of disclosure recorded in the ledger.

**Console.** Obligation toggles on the Policy page; a transparency-events view.

**Docs.** New section, console-first.

**Acceptance.**
- A response subject to the disclose obligation carries the disclosure and the event is recorded.
- Generated media is C2PA-stamped and the stamp verifies.

### G12. More regulatory content packs (DPDP, UK)  (review #15, S)

**Design.** Add India's DPDP Act and the UK approach as signed, versioned content packs alongside the
existing five, via the existing pack mechanism.

**Console.** They appear in the existing Control packs card; no new page.

**Docs.** Note the new packs in `12-grc`.

**Acceptance.**
- The DPDP and UK packs load, verify by signature, and produce framework reports like the existing packs.

### G13. Local semantic groundedness model  (review #13, M)

**Design.** Bundle a small local NLI model behind the existing groundedness provider seam (the lexical
baseline stays as the zero-dependency floor; Azure or AWS remain opt-in).

**Console.** Surfaced through the existing groundedness threshold control.

**Acceptance.**
- The NLI backend loads locally and scores groundedness; the lexical baseline remains available and is
  the default when the model is absent.
- The efficacy gate over the corpus meets a published threshold.

### G14. Transformer injection detector  (review #14, L)

**Design.** A small fine-tuned model run via ONNX behind the existing scan seam, with the current
signatures plus logistic regression as a fast first stage. Drop-in behind the `Scorer` interface.

**Acceptance.**
- The ONNX detector runs as a second stage and raises corpus recall above the published C3 threshold
  without breaking the latency gate.

### G15. Bias and performance harness  (review #11, L)

**Design.** A harness that runs fairness and quality tests against a customer's deployed model and stores
the results as signed evidence linked to the model card.

**Console.** A "Model tests" section on the Models page: run, results, trend.

**Acceptance.**
- A test run against a model produces fairness and quality metrics stored as a signed record linked to
  the model card, shown on the console.

### G16. Browser DLP extension  (review #16, L)

**Design.** An inline DLP and policy browser extension for staff using consumer AI tools. A separate
deployed product with its own lifecycle; discovery already finds the usage, this controls it.

**Acceptance.**
- The extension enforces a policy on a consumer AI site and reports events to the control plane.
- (Scoped as a distinct roadmap product, not part of the five-crate core.)

### G17. Continuous red-teaming of customer agents  (review #17, M)

**Design.** Turn the existing red-team corpus into a scheduled attack service against a customer's own
agents, with results filed as signed evidence, rather than only testing the built-in detector.

**Console.** Extend the existing Red-team card with target config and scheduled-run history.

**Acceptance.**
- A scheduled run attacks a configured customer agent endpoint and files signed results visible on the
  console.

### G18. Self-service auditor portal  (review #18, M)

**Design.** Scoped, read-only access where an external auditor selects a time window, downloads a signed
evidence pack, and verifies it with the public key alone, without customer staff involvement.

**Console.** An auditor role and a minimal auditor view: pick window, download pack, see the verify
command.

**Acceptance.**
- An auditor-role token can only read and download evidence for the granted window.
- The downloaded pack verifies with `acp verify-pack` on a clean machine.

### G19. Public trust page  (review #19, S)

**Design.** A published, verifiable summary of the controls in force that the customer's own clients can
check against the signed ledger.

**Console.** A "Publish trust summary" action; the published page is static and verifiable.

**Acceptance.**
- The published summary reflects the current controls and links to a verifiable proof derived from the
  ledger.

## 5. Build order and effort

| Order | Item | Effort | Why here |
| --- | --- | --- | --- |
| 1 | G1 oversight monitoring | S | Data already stored; unique; Art. 14. Cheapest high-value win. |
| 2 | G2 least-privilege synthesis | M (discounted) | Extends `acp learn`; biggest adoption unlock. |
| 3 | G3 plain-English authoring | M | Pairs with G2; reuses the Cedar analyzer. |
| 4 | G4 post-market report | S | Runtime data exists; strong GRC credibility. |
| 5 | G5 serious-incident workflow | M | Turns evidence into the Art. 73 report. |
| 6 | G6 output DLP | S | Extends the existing response-scan path. |
| 7 | G10, G12 | S each | Cheap GRC breadth (FRIA, DPDP/UK packs). |
| 8 | G7, G8, G9 | M each | Mid-effort Tier-1 depth. |
| 9 | G11, G17, G18, G19 | S to M | Transparency, red-team-as-service, auditor portal, trust page. |
| 10 | G13, G14, G15, G16 | M to L | ML and endpoint programmes; behind existing seams; not "weeks". |

Cross-cutting workstreams A (console parity) and B (UI-first docs) are not a phase: each feature above
carries its console surface and its console-first documentation as acceptance criteria, and the existing
guide's curl-for-console-tasks is cleaned up as those chapters are touched.
