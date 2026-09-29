# Varman plan: Vue console in acp-server, and exhaustive act conformance

Status: planned. This plan covers three decisions taken on 2026-09-28:

1. Replace the Kyte/datastar console (`acp-console`) with a Vue 3 console served by `acp-server`
   itself, so the product ships as two deliverables: the server (control plane plus console) and the
   firewall (agent). Vue is chosen for a mature, form-friendly framework; KYX limitations cost real
   time (see `kyte/docs/KYX-PARSER-FIXES-PLAN.md`).
2. Move governance from its EU-AI-Act-centric, ~4-controls-per-act stub to exhaustive
   conformance: each covered act carries its complete normative obligation set, assessed and
   reported control by control (see Part B).
3. Record that the content firewall is a gateway-only capability, not a per-workstation one. No build
   work now; this plan only records the decision and the doc and console consequences.

The Vue app must reproduce the existing console's information architecture and look (same sidebar,
views, dark and light theme), use TailwindCSS for styling and Lucide for icons, and keep the same
scaffold and view layout as the datastar console.

---

## Part A: Vue console embedded in acp-server

### A.0 Target architecture

- New Vue 3 project at `acp/console/` (Vite, TypeScript, TailwindCSS, `lucide-vue-next`, Vue Router,
  Pinia for state). Built assets go to `acp/console/dist/`.
- `acp-server` serves the built SPA. Add a static-file layer to the axum router (either `tower-http`
  `ServeDir` with an `index.html` SPA fallback, or `rust-embed` to bake `dist/` into the binary for a
  single-file deploy). The JSON API is unchanged. This drops the separate `acp-console` process; the
  deploy becomes `acp-server` plus `acp-agent`.
- Because the SPA is same-origin with the API, it calls `acp-server` endpoints directly. The old
  console's proxy handlers (the `/agent/config/save` to `/agent-config/:group` forwarders, and the rest
  under `src/Features/Dashboard/*/handler.ky`) are not needed; the Vue store calls the real endpoints
  with the `x-acp-tenant` header and a bearer token. This is a net simplification.

### A.1 Data layer (replace the SSE panel mechanism)

The datastar console pushes about 35 HTML fragments over one `/sse/metrics` stream every 2 seconds.
In Vue, replace this with a small typed API client plus a store:

- An `api.ts` client: base URL is same-origin (empty base) in the embedded build, `x-acp-tenant`
  header on every request, and the dev-token flow for writes (GET `/auth/dev-token?role=<Role>` then
  `Authorization: Bearer`) with the real forwarded bearer taking precedence when present. Roles used:
  AppRegistrar, PolicyAdmin, FirewallAdmin, GrcAuthor, Approver, Auditor, BreakGlassOperator.
- A Pinia store per domain (report, identity, policy, firewall, grc, evidence, monitors, agentconfig).
  Poll on a 2 second interval for the live views (or open a native `EventSource` on `/sse/metrics` if we
  keep an SSE endpoint; polling is simpler and the API is cheap). Each old `...Panel` maps to exactly one
  read method and one JSON DTO, so the shapes are already defined; port them to TypeScript interfaces.
- Read endpoints to port (from the console spec): `/report`, `/apps`, `/agents`, `/models`, `/vendors`,
  `/packs`, `/redteam/runs`, `/report/framework/{name}` and `/csv` and `/pack`, `/grc` and
  `/grc/{id}/comments`, `/monitor/drift`, `/monitor/lineage`, `/policy-store`, `/policy-store/rules`,
  `/agent-config/{group}`, `/approvals/pending`, `/report/post-market`, `/policy/suggest`, `/trust`,
  `/audit/pack`, `/oversight`, `/evidence/recent`, `/events/recent`, `/evidence/ingested`,
  `/firewall/config`, `/firewall/rules`, `/report/violations` and `/violations.csv`, `/break-glass`,
  `/endpoints`, `/verify`, `/liveness`, `/alerts`, `/meta-audit`, `/groups`, `/tenants`,
  `/principal/groups`, `/policy-store/signed`.
- Write endpoints to port: `/approvals/{id}/approve|deny`, `/policy-store/deploy`, `/policy/author`,
  `/oversight/scan`, `/oversight/config`, `/incident/promote`, `/redteam/run`, `/redteam/target`,
  `/models/{id}/fairness`, `/break-glass/engage|clear`, `/endpoints/register`, `/apps`, `/agents`,
  `/agents/{id}/deactivate`, `/agents/{id}/auto-assess`, `/grc`, `/grc/assess`, `/grc/risk`,
  `/grc/model-card`, `/grc/{id}/assign`, `/grc/{id}/control/{cid}`, `/grc/{id}/status`,
  `/grc/{id}/usecase/{stage}`, `/agent-config/{group}`, `/groups`, `/models`, `/vendors`,
  `/vendors/{id}/review`, `/packs` (with `/packs/available`), `/firewall/config`, `/firewall/rules`,
  `/firewall/rules/{id}/delete`, `/firewall/threat-pack` (with `/firewall/threat-pack/available`).

### A.2 Layout, navigation and theme (faithful reproduction)

- App shell: top navbar (56px) with the Varman brand and a "live" pulse pill and a theme toggle;
  a 236px sidebar plus a `1fr` content area (`max-width` around 1080px). Vue Router with one route per
  view; the sidebar highlights the active route with the accent left rail.
- Sidebar groups and items, in this exact order (label, route, Lucide icon):
  - Governance: Overview (`layout-dashboard`), Approvals (`hand`), Oversight (`eye`),
    Evidence (`scroll-text`), Violations (`alert-triangle`), Reports (`clipboard-list`).
  - Identity: Teams (`package`), Agents (`bot`), Models (`brain`), AI Endpoints (`globe`).
  - Policy: Policy (`lock`), Content firewall (`shield`), Agent config (`laptop`).
  - Compliance: Governance (`file-text`).
  - Emergency: Kill-switch (`octagon-alert`).
  - Health: Integrity (`shield-check`), Monitors (`line-chart`).
  (Lucide names are suggestions; pick the closest glyphs. The point is real icons via `lucide-vue-next`,
  which removes the KYX icon problem entirely.)
- Theme: port the exact CSS custom properties as CSS variables and drive Tailwind from them (Tailwind
  `theme.extend.colors` referencing `var(--...)`, or a small `@layer base` with the variables). The
  toggle flips a `data-theme`/`.light` class on the root and persists to `localStorage['acp-theme']`.
  Values to port verbatim:
  - Dark (`:root`): `--bg #0a0e1a`, `--panel #111726`, `--panel2 #0d1320`, `--line #1e2740`,
    `--line2 #28324f`, `--txt #e5eaf5`, `--dim #8892ab`, `--muted #5c6685`, `--accent #6366f1`,
    `--ok #10b981`, `--warn #f59e0b`, `--bad #ef4444`,
    `--sidebar linear-gradient(180deg,#0c1120,#0a0e1a)`, `--topbar #0d1320`.
  - Light (`.light`): `--bg #eef1f7`, `--panel #ffffff`, `--panel2 #f4f6fb`, `--line #e2e7f0`,
    `--line2 #d3dae7`, `--txt #161d2e`, `--dim #586182`, `--muted #9098ad`,
    `--sidebar linear-gradient(180deg,#ffffff,#f4f6fb)`, `--topbar #ffffff`. Accent, ok, warn, bad are
    not overridden in light.
- Component library (Vue components, Tailwind-styled, mirroring the datastar classes): Card (header
  with title, right-aligned subtitle, optional CTA; body with x-scroll), StatTile and StatGrid, Table
  (uppercase muted headers), Badge (ok, bad, warn, ver variants), Button (primary, ok, no-outline, plus
  a compact in-table size and a stacked equal-width action column), Field and Row form primitives,
  Tabs (accent-filled segmented control, for the Policy page), Modal (backdrop plus centred dialog,
  with a wide variant), VerdictBar (allow, step-up, shadow, deny segments), and the framework-report
  and firewall-status blocks. The `@media print` rule that hides the sidebar and topbar for PDF export
  must be kept.

### A.3 Views to build (parity with the datastar console)

Build to the view-by-view inventory already captured for the current console. In priority order:

1. Shell, sidebar, theme, router, api client, one Pinia store, and the Overview view (posture and
   verdict bar) end to end. This proves the data path and the look.
2. Read-heavy views: Approvals, Evidence, Violations, Reports (including the regulator report buttons
   and the CSV and signed-pack downloads), Oversight, Monitors, Health, Teams, Agents, Models,
   Endpoints, Kill-switch.
3. Form-heavy views (where Vue pays off most): Policy (deployed-rules tab plus a Monaco or CodeMirror
   YAML editor, author-from-description, deploy), Content firewall (config plus rules), Agent config
   (group registration plus the group dropdown plus the per-capability editor with load and save), and
   the GRC page with its modals (New assessment, Record, Risk, Model card) and inline record actions.
4. The modals: app, agent, model, vendor, endpoint, grc, assess (the nine screening checkboxes), risk,
   model card, kill. Two-way binding and load-into-form are trivial in Vue, which fixes the datastar
   limitation where the Agent config editor could not populate its own fields.

Note the GRC "New assessment" modal must become framework-aware once Part B lands (a framework
selector, not EU-AI-Act-only). Design the assess modal now to take a framework parameter.

### A.3b Screen quality: cleaner than the current CRUD lists

The user's critique is that the current screens do not cleanly implement the requirements around
policy, firewall rules, guard and governance; several are naive lists. The Vue rebuild is the chance to
fix this. Informed by how Credo AI and Holistic AI surface governance (validate against live docs), the
target screens are:

- **Governance workspace (not a flat record list).** The GRC page becomes an AI-system registry as the
  hub: a list of AI systems with owner, lifecycle stage, jurisdictions, risk tier and compliance
  coverage; drilling into a system opens its workspace with tabs for assessments (per regulation),
  controls and evidence, tasks, risks, model card and reports. This replaces the flat `GRC_KINDS` list
  with a system-centred workflow, which is what makes a governance UX feel complete rather than CRUD.
- **Compliance / reporting centre.** A dedicated area to pick a subject (a system or the org) and a
  regulation or jurisdiction, see the controls coverage (satisfied, gap) with the crosswalk, and
  generate or download the signed report (B0.4). This is where "UK org, UK report" lives.
- **Policy screen.** A clear model-v2 editor: the rule table showing subject (agent, app, group),
  object (resource), operation and verdict and obligations; the verification matrix (allow or deny per
  example request) before deploy; the observe or enforce mode control; the signed deploy history and
  the currently enforced version and hash. Author-from-description and least-privilege suggestion stay.
- **Firewall screen.** The category-based policy model from C.2 (per-application policy, per-category
  action and threshold, allow and deny lists, custom rules) plus the detections dashboard from C.4,
  framed as gateway scope.
- **Guard screen.** Guard is thin today; give it a real screen: the guarded tool servers, their
  upstreams and pinned keys, and the reject-uninstrumented-calls status, configurable per the group or
  agent config model.
- Across all screens: use the shared component set (cards, tables, badges, tabs, modals) consistently,
  show empty states and freshness and verification state, and prefer a drill-down workspace over a wide
  flat table where an object has sub-objects.

### A.4 Serving and retirement

- Add the static layer to `acp-server` and a build step (`acp/console` Vite build) wired into the
  release packaging. Decide embed (`rust-embed`, single binary) versus `ServeDir` (assets beside the
  binary); embed is the cleaner deploy for a two-binary product.
- A config or flag for the served base path if needed; default to `/`.
- Once parity is verified, delete `acp/acp-console` (the Kyte console) and drop its build from CI.
- Update the guide: chapter 17 (console reference) and the setup runbook to describe one server that
  serves the console, not a separate console process.

### A.5 Acceptance criteria (Part A)

- `acp-server` serves the Vue console at its address (for example `http://127.0.0.1:8787/`), with the
  JSON API unchanged, on one port and one process.
- Every view listed in the console inventory is present and functional against a live control plane,
  including the writes (register, deploy, save firewall, save agent config, resolve approvals,
  break-glass, GRC create and transitions, downloads).
- Dark and light themes match the current console's palette; Lucide icons render on every nav item and
  card header (no entity or emoji hacks).
- The Agent config editor loads a group's stored config into its fields and saves changes back
  (the datastar version could not load into the form).
- `acp-console` is removed and the deploy is two binaries.

---

## Part B0: target GRC data model and reporting architecture

This section is the design the user called out as the biggest gap: reporting is weak, GRC data is
maintained naively (a flat list of signed records keyed by `GRC_KINDS`), and a concrete need like "a UK
org generates a compliance report against UK regulation" has no clean path today. The target model
below is informed by how mature AI governance platforms (Credo AI, Holistic AI) structure governance
and reporting. Note on provenance: live web research was blocked in this environment, so the
competitive references here are from working knowledge as of early 2026 and should be validated against
the current Credo AI and Holistic AI product docs before build.

### B0.1 The problem with the current model

Today GRC is a flat table of signed records of nine kinds (`assessment`, `conformity`, `risk`,
`model-card`, `use-case`, `attestation`, `aibom`, `fria`, `incident`). There is no first-class "AI
system / use case" object that ties everything together, no jurisdiction concept, no control crosswalk,
and reporting is a per-framework rollup computed on the fly. That cannot answer "show me, for this AI
system, its compliance posture against the regulation that applies to my jurisdiction, with the
evidence, as a signed report an auditor accepts."

### B0.2 The target GRC object model (relational, use-case centred)

Make the **AI system / use case** the hub object, and hang everything off it. Objects and key fields:

- **AiSystem (use case)**: the central registry entry. Fields: id, name, owner, business domain,
  purpose, lifecycle stage (intake, development, staging, production, retired), deployment jurisdictions
  (a set, for example `["uk","eu"]`), the applicable regulation set (derived from jurisdiction plus
  context, overridable), risk tier per regulation, linked models, linked agents/endpoints, data classes
  processed, affected populations, and status. This is what the current `use-case` and `assessment`
  kinds should become: one durable object with a lifecycle, not one record per event.
- **RegulationProfile (policy pack)**: a regulation or framework and the machinery to assess against
  it: its controls (via the control library), its screening question set, its tiering strategy, its
  obligations, its report template, and the jurisdictions it applies to. Examples: eu-ai-act, uk-ai,
  nist-ai-rmf, iso-42001, iso-23894, colorado-ai-act, nyc-ll144, gdpr, dpdp-2023. This generalises the
  EU-only `assessment.rs` into a pluggable profile (see Part B3).
- **Assessment**: an AiSystem assessed against one RegulationProfile: the screening answers, the
  resulting risk tier or conformity determination, and the generated controls checklist. An AiSystem
  has one assessment per applicable regulation, re-runnable and versioned.
- **Control** and **ControlMapping (crosswalk)**: the control library (Part B) plus a crosswalk that
  records which single underlying obligation satisfies controls across multiple frameworks, so evidence
  collected once counts everywhere. This is the key to multi-jurisdiction reporting: satisfy a data
  governance control once, report it under EU AI Act Art. 10, ISO 42001 8.1, and NIST MAP at the same
  time.
- **Evidence (artifact)**: a piece of proof bound to one or more controls: source (the signed ledger,
  an uploaded document, a signed attestation, a fairness test result, a red-team run), a hash, a
  freshness timestamp, a verification state, and who attested it. Evidence is the atom reports are built
  from; it must carry freshness so a report can flag stale evidence.
- **Task**: a unit of work to close a control gap: owner, due date, status. The conformity checklist
  becomes tasks with owners, not just booleans.
- **RiskRegister entry**: a risk (likelihood x impact, treatment, status) linked to an AiSystem.
- **ModelCard**, **Vendor / third party**, **Finding / incident**: as today but linked to AiSystems.
- **Report**: a generated, signed, versioned document for a subject (an AiSystem or the whole org)
  against a RegulationProfile, using that profile's template. See B0.4.
- **Roles / stakeholders**: a RACI per AiSystem (owner, approver, assessor, auditor), driving sign-off
  and the SLA escalation that already exists.

Storage: this is more than the current KV state and flat GRC rows. Model it in the control-plane store
(the sqlx backend) with proper tables and foreign keys: `ai_systems`, `assessments`, `controls`,
`control_mappings`, `evidence`, `tasks`, `risks`, `reports`, plus join tables. Keep the per-record
Ed25519 signing for anything an auditor relies on (assessments, evidence attestations, reports).

### B0.3 Jurisdiction and the control crosswalk (how one org gets its own report)

- An org sets its **jurisdictions** (and each AiSystem can override). From jurisdiction plus context
  (does it make employment decisions, is it a general-purpose model, does it process biometric data),
  derive the **applicable regulation set**. A UK org gets the UK regulatory expectations profile; an EU
  org gets EU AI Act; a Colorado employer using hiring AI gets Colorado AI Act plus (if in NYC) LL144;
  most get ISO 42001 and NIST as voluntary frameworks.
- The **crosswalk** maps controls across frameworks so a single evidence set produces a report for
  whichever regulation the org selects. This is exactly the Credo AI and Holistic AI model: assess and
  collect once, report against many. Implement it as `control_mappings` rows (control A in framework X
  is equivalent to or satisfies control B in framework Y) plus a resolver that, given a target
  regulation, gathers the satisfying evidence via the crosswalk.
- Result: "UK org generates a compliance report against UK regulation" becomes: select the AiSystem (or
  org), select the UK regulation profile, and render its report template against the crosswalked
  evidence. No bespoke code per org.

### B0.4 Reporting architecture (the core deliverable)

A report is `(subject) x (RegulationProfile) x (template) -> rendered + signed + versioned`, where the
subject is an AiSystem or the whole org.

- **Report templates per regulation.** Each RegulationProfile owns a template describing sections and
  what evidence binds where. Concrete templates to build (start with the ones the user needs):
  - EU AI Act technical documentation (Annex IV) and record-keeping (Art. 12): system description,
    risk classification, the Art. 9 to 15 controls with status and evidence, data governance, human
    oversight, accuracy and robustness, post-market monitoring, the conformity declaration.
  - UK regulation report: the UK is principles-based (safety, transparency, fairness, accountability,
    contestability) with sector regulators rather than a single act, so the UK template is a
    principles-mapped report plus any sector-regulator expectations, with the same evidence binding.
  - NIST AI RMF profile report (govern, map, measure, manage) and ISO/IEC 42001 Statement of
    Applicability and ISO/IEC 23894 risk report.
  - Colorado AI Act (developer and deployer duties, impact assessment) and NYC LL144 bias-audit report.
- **Report contents (common skeleton).** System description and metadata, risk classification for that
  regulation, controls status table (satisfied, in progress, gap) with linked evidence and its
  freshness and verification state, breach and incident summary from the ledger, a conformity or
  readiness statement, named sign-off (attested by a role, tying into the existing approval and SLA
  machinery), and provenance: version, content hash, Ed25519 signature. Build on the existing signed
  JSON-LD compliance pack (`/report/framework/:name/pack`) rather than replacing it: generalise it from
  a framework rollup to a template-driven, subject-scoped, signed report.
- **Export formats.** Signed JSON-LD (machine-verifiable, `acp verify-pack`), PDF (print stylesheet for
  the human and board-facing version), and CSV for the controls table. Keep the print-to-PDF path.
- **Report lifecycle.** Draft, under review, signed, superseded. Store report snapshots (the schema
  already has snapshot support) so a point-in-time report is reproducible and versioned. Schedule
  periodic report generation and delivery (the M3 snapshot loop already exists for framework reports;
  extend it to the report objects).
- **Evidence freshness and attestation.** A report must show when each piece of evidence was last
  verified and by whom, and flag stale or unverified evidence, so a signed report is honest about its
  own currency. This is a differentiator versus a naive rollup.
- **Report types beyond compliance.** Also support an executive or board risk report (posture across
  all AiSystems, top risks, open incidents), a transparency report or model card for external
  publication, and the auditor evidence pack that already exists. These are different templates over
  the same object model.

### B0.5 Acceptance criteria (Part B0)

- There is a first-class AiSystem registry; an AI system is registered once and carries jurisdictions,
  lifecycle, linked models and agents, and one assessment per applicable regulation.
- A UK org can select an AI system (or the org), pick the UK regulation profile, and generate a signed,
  versioned UK compliance report from the same evidence that an EU org would use to generate an EU AI
  Act report; the crosswalk means the evidence is entered once.
- A report shows the controls status, the bound evidence with freshness and verification state, the
  breach and incident summary, a named sign-off, and a verifiable signature; it exports as signed
  JSON-LD, PDF, and CSV.
- Evidence is a first-class object bound to controls with freshness; stale or unverified evidence is
  flagged in the report.
- The flat `GRC_KINDS` records are migrated onto the relational model (AiSystem plus assessments plus
  evidence plus tasks plus risks), with the per-record signing preserved.

### B0.6 Refinements from Credo AI and Holistic AI (researched, sourced below)

Web research on the two leaders validated the model above and sharpened these points. Fold them in:

- **Two linked spines, not one.** Separate a typed **Asset** spine (model, agent, dataset, pipeline,
  API, app, vendor-supplied component) from the **UseCase** spine (the business application, which is
  what a regulation attaches to), with a many-to-many link. One use case spans several assets; one asset
  serves several use cases. Naive models conflate "model" with "use case"; do not. Regulation and risk
  tiering attach to the UseCase; technical evidence and testing attach to Assets.
- **Rich typed metadata, dual ownership, version history on the object.** Holistic exposes it plainly:
  each asset carries a business owner and a technical owner with an escalation path, a status and a
  version history on the asset itself (not just on documents). Copy this.
- **Multi-dimensional risk, not a single tier.** Score risk across operational, legal, ethical,
  reputational and technical dimensions and derive a composite score plus tier from inputs (use-case
  stakes, data sensitivity, deployment context, model type, regulatory scope). The EU four-tier scale is
  one output lens, not the whole risk model.
- **Framework.type is the key to the UK vs EU question.** Model a framework's shape explicitly:
  `type in {statutory_conformity, principles_based, standard, sectoral}`. EU AI Act is
  `statutory_conformity`: enumerated Annex obligations, pass or fail, a mandatory technical
  documentation annex (Annex IV), a conformity declaration. The UK is `principles_based`: there is no
  single UK AI Act; it is five cross-sectoral principles (safety and robustness, transparency and
  explainability, fairness, accountability and governance, contestability and redress) enforced by
  existing sector regulators (ICO, FCA, CMA, Ofcom). So a UK report is not a pass/fail conformity
  checklist; it is a principle-by-principle narrative plus supporting evidence plus the relevant
  sector-regulator obligations, attestation-style. Report templates must branch on `Framework.type`, or
  a credible UK report is impossible. The UseCase `regulatory_scope` selects which templates apply and
  can trigger both (an org operating in the UK and the EU generates both reports off one evidence set).
- **PolicyPack is the reusable unit; attaching it seeds the work.** A PolicyPack (Credo's abstraction)
  bundles a regulation's obligations plus default risk scenarios plus recommended controls plus its
  report template, as versioned content with an effective date. Attaching a pack to a use case seeds
  its risk register and control checklist rather than making the user hand-build controls. Keep pack
  authoring (central, updated as laws change) separate from pack application. Distinguish a documentary
  policy facet (obligations and controls for reporting) from an enforceable policy facet (the runtime
  authorization policy and gateway guardrails).
- **A report is an immutable, versioned snapshot rendered from the object graph.** At generation, freeze
  the evidence versions, risk scores, the framework version and the sign-off signature, and stamp
  generated-at, so the report is reproducible and defensible later. Gap and conformity reports are the
  same engine with a different lens (enumerate obligations, mark satisfied, partial or unsatisfied by
  evidence presence and freshness, emit remediation tasks). Support two altitudes from the same data: a
  regulator or audit pack (full evidence-bound conformity doc plus technical annex plus audit trail) and
  an executive or board report (portfolio risk posture, tier distribution, trends). Add an AI Bill of
  Materials (AI-BOM) as a structured JSON export of assets, dependencies, owners and tiers.
- **Multiple intake paths into one canonical record.** Do not hard-code a single manual intake form.
  Support a self-service form, shadow-AI discovery, bulk CSV or API import, and MLOps sync, all funneling
  into one asset or use-case record with a governance review and refine step. A lightweight
  self-classification wizard (Holistic's EU AI Act risk calculator) is a good front door before a full
  assessment.
- **An immutable AuditEvent log is a core table, not an afterthought.** Every governance decision
  recorded is what makes the audit pack credible; ACP already has the signed ledger, so bind governance
  decisions into it.
- **Three UX altitudes (see also A.3b).** A portfolio dashboard (risk posture, tier distribution,
  framework readiness, alerts); an entity detail view that is the heart of the product (a use case or
  asset with tabs for overview and metadata, risks, controls and evidence with freshness badges,
  assessments, frameworks and compliance status, a version and audit timeline, and tasks); and a work
  surface (my tasks, pending approvals, remediation). The detail view is the single biggest jump from a
  naive CRUD list. An AI-assisted intake and mapping assistant (Credo's GAIA) lowers the intake barrier
  and auto-suggests risks and controls; optional, but both leaders now lead with it.

Sources (public product and solution pages; both apps gate detailed docs behind login, so the schema is
inferred from published pages, Holistic's being notably explicit about fields and lifecycle):
Credo AI product `credo.ai/product`, artifacts `credo.ai/solutions/artifacts`, policy intelligence
`credo.ai/policy-intelligence`, regulations `credo.ai/solutions/regulations-and-standards`, EU AI Act
`credo.ai/eu-ai-act`, agent registry `credo.ai/ai-agent-registry`; Holistic AI platform
`holisticai.com/ai-governance-platform`, inventory `holisticai.com/ai-inventory`, risk management
`holisticai.com/ai-risk-management`, risk-posture reporting
`holisticai.com/use-case/ai-risk-posture-reporting`. The UK vs EU distinction is grounded in how each
regime works (EU statutory conformity versus UK principles-based, regulator-led), not a vendor "UK AI
Act" page, because no single UK AI statute exists.

## Part B: exhaustive act conformance

### B.0 Current state: why it is shallow

The library defines seven frameworks and about 33 controls in total, that is roughly four to seven
controls per act. That is a token gesture, not conformance:

- EU AI Act high-risk provider obligations alone span Articles 8 to 15 plus the Annex IV technical
  documentation (a dozen headings), plus prohibited practices (Art 5), transparency (Art 50), deployer
  duties (Art 26), a fundamental-rights impact assessment (Art 27), quality management (Art 17),
  conformity assessment (Art 43), registration (Art 49 and 71), post-market monitoring (Art 72),
  serious-incident reporting (Art 73), and general-purpose model duties (Art 53 to 55). Seven controls
  cannot represent this.
- NIST AI RMF 1.0 is four functions decomposed into categories and about 72 subcategories; we hold four
  nodes, one per function.
- ISO/IEC 42001:2023 has management-system clauses 4 to 10 plus an Annex A of about 38 controls across
  nine objectives; we hold four.
- ISO/IEC 27001:2022 Annex A has 93 controls across four themes; not present at all.
- SOC 2 is the full Trust Services Criteria (CC1 to CC9 common criteria plus the Availability,
  Confidentiality, Processing Integrity and Privacy series) with dozens of points of focus; we hold four.
- GDPR duties triggered by an AI system span many articles; we hold four. India DPDP 2023 is similar. The
  UK approach is five cross-sector principles, each with detailed regulator expectations; we hold five
  one-line stubs.

Plus the structural problems: slug and id drift (`soc2` vs `soc-2`, `art-14` vs `Art.14`,
`riskregister.rs` uses a combined `eu-ai-act-art-14`); a second, independently hardcoded evidence-grading
path in `grc.rs::report()` for only EU AI Act, NIST and ISO 42001; an assessment engine
(`assessment.rs`) hardwired to the EU four-tier scale; a console that offers a single
`eu-ai-act-screening` template; and stale "three frameworks" comments and tests. So the problem is not
only "more frameworks", it is depth: each covered act must carry its complete normative obligation set,
assessed and reported control by control.

### B.1 Target: what "exhaustive" means

For every act we claim to cover:

- Every normative obligation that can bind a subject we govern has a control node. Completeness is
  measured against the framework's own published structure (its article, clause, annex or criterion
  count), not a hand-picked subset. A coverage manifest per framework records the source-of-truth section
  list and which nodes cover it, so a reviewer can see that nothing is missing.
- Each node carries: a stable id; a hierarchy path (framework, then part or annex, then article or
  clause, then control, then point-of-focus); the normative reference and a short faithful paraphrase
  (not copied text, to respect copyright on standards); an obligation type (govern, document, technical,
  process, transparency, oversight, record-keeping); the role it binds (provider, deployer, developer,
  importer, distributor, data controller, data processor, as the act defines); an applicability
  predicate; the required evidence type or types; the assessment method (attestation, artefact, test
  result, ledger proof); and crosswalk links to equivalent controls in other frameworks.
- Not-applicable is a first-class, justified state. Exhaustive does not mean every control fires for
  every subject; it means every control is either assessed or explicitly marked not-applicable with a
  reason.

### B.2 The catalogue becomes versioned data, not code literals

Hand-written `Control` literals in `controls.rs` cannot scale to hundreds of nodes per framework or track
amendments. Move the catalogue to structured, embedded data:

- One catalogue file per framework-version (for example `catalogue/eu-ai-act@2024.yaml`,
  `nist-ai-rmf@1.0.yaml`, `iso-42001@2023.yaml`), compiled in via `include_str!` or `rust-embed` and
  parsed into the existing `Control` shape, extended with the fields in B.1. `controls::library()` loads
  all catalogues; the lookup API stays the same.
- Frameworks are versioned with an effective date, because acts change: the EU AI Act obligations phase
  in on staggered dates, and standards get reissued (ISO 42001:2023). A report pins the framework version
  it was assessed against, and re-assessment against a newer version is a diff.
- A build-time check validates each catalogue against its coverage manifest (every source section is
  referenced by at least one node) and against the id scheme, so an incomplete catalogue fails CI rather
  than shipping as a shallow stub.

### B.3 Per-framework exhaustive scope (the content work)

This is the bulk of the effort and it is content, not plumbing. For each in-scope act, author the full
node set to the completeness bar in B.1:

- EU AI Act (2024): prohibited practices (Art 5); high-risk classification (Art 6 and Annex III);
  provider obligations (Art 8 to 15) with the Annex IV technical documentation broken out heading by
  heading; quality management (Art 17); deployer obligations (Art 26); fundamental-rights impact
  assessment (Art 27); transparency (Art 50); conformity assessment and CE marking (Art 43, 47, 48);
  registration (Art 49, 71); post-market monitoring (Art 72); serious-incident reporting (Art 73);
  general-purpose model duties (Art 53 to 55). Keep the existing EU logic as this framework's assessment
  profile.
- NIST AI RMF 1.0: all four functions to subcategory granularity (GOVERN, MAP, MEASURE, MANAGE), about 72
  nodes, each with its outcome text and suggested evidence.
- ISO/IEC 42001:2023: clauses 4 to 10 plus the Annex A objectives A.2 to A.10 with each control.
- ISO/IEC 27001:2022: Annex A, 93 controls across the four themes (organisational, people, physical,
  technological), plus clauses 4 to 10.
- SOC 2 (Trust Services Criteria): common criteria CC1 to CC9 with points of focus, plus the
  Availability, Confidentiality, Processing Integrity and Privacy criteria.
- GDPR: the duties an AI system triggers, each a node (lawfulness and the Art 5 principles, Art 13 to 15
  information and access, Art 22 automated-decision safeguards, Art 25 protection by design, Art 30
  records, Art 32 security, Art 35 DPIA).
- India DPDP Act 2023: data-fiduciary duties (notice, consent, purpose limitation, security safeguards,
  breach notification, children, significant-data-fiduciary duties, data-principal rights).
- UK: the five cross-sector principles (safety, security and robustness; transparency and
  explainability; fairness; accountability and governance; contestability and redress), each decomposed
  into the regulator expectations, so the principles-based report has real sub-nodes to evidence against,
  not one line each.
- Newly in scope: Colorado AI Act (SB 24-205) developer and deployer duties and high-risk determination;
  NYC Local Law 144 (bias-audit, notice and publication duties); Canada AIDA high-impact duties (as and
  if it progresses); ISO/IEC 23894 risk-management process controls.

Each node cites its official source (regulation article or recital, standard clause) in a citation
field, so an auditor can trace it and the authoring is checkable.

### B.4 Authoring pipeline (how we produce and maintain this volume)

Hundreds of nodes per framework is real work and it must stay current:

- A repeatable authoring flow: start from the framework's published table of contents (the coverage
  manifest), draft each node's paraphrase, evidence type and assessment method, and record the citation.
  The optional author-LLM assist already wired into the server (`author_llm_url`, `author_llm_key`,
  `author_llm_model` in `config.rs`) can draft node text from a section reference, but every node is
  human-reviewed and signed off before it enters the catalogue, and the LLM never invents obligations
  that lack a citation.
- Catalogue changes are reviewed like code (the data files live in-repo and go through the same review),
  and each framework file has a maintainer note recording the source edition and the date checked.
- Copyright: standards text (ISO, the SOC 2 criteria) is not reproduced verbatim; nodes hold short
  faithful paraphrases plus a citation to the clause number, so users consult the licensed source for the
  exact wording.

### B.5 Applicability engine (exhaustive without noise)

Exhaustive conformance is assessed against the applicable subset, computed rather than guessed:

- Given a use-case or asset profile (the role played, risk tier, sector, jurisdiction, deployment mode,
  and headcount thresholds where an act uses them), the engine computes which nodes apply. For example, a
  UK deployer of a non-high-risk assistant does not get the EU Annex IV nodes, but does get the UK
  transparency and accountability nodes; a provider of an Annex III system gets the full Art 8 to 15 set.
- Every applicable node must reach a conformity state, and every non-applicable node is recorded as
  not-applicable with the predicate that excluded it. That pairing is the definition of exhaustive for a
  given subject.

### B.6 Per-control assessment and conformity model

- Extend the assessment engine (currently EU-tier-only in `assessment.rs`) to a per-framework profile
  interface: a screening step, an applicability computation (B.5), and a per-node conformity judgement.
  Keep the EU risk-tier logic as the `eu-ai-act` profile; NIST and the ISO and SOC families use a
  conformity-checklist profile rather than a tier.
- Conformity states per node: conformant, partially-conformant, non-conformant, not-applicable,
  not-assessed. Each conformant or partial node links the evidence satisfying it (through the crosswalk
  and the evidence store, with freshness); each non-conformant or partial node carries a gap and a
  remediation owner.
- `grc_templates()` returns a screening template per framework, not just `eu-ai-act-screening`; the
  console assessment modal takes a framework parameter.

### B.7 Exhaustive reporting

The report is the proof of exhaustiveness (this ties into Part B0.4):

- A framework report enumerates every applicable control with its conformity state, the evidence
  references, the owner, and for anything short of conformant the gap and remediation plan; it lists the
  not-applicable controls with their exclusion reason; and it rolls up a conformity summary (counts and
  percentage by state, plus the overall verdict where the act defines one).
- The report pins the framework version and the assessment date, is an immutable versioned snapshot, and
  exports as signed JSON-LD, PDF and CSV. For the EU AI Act it can render the Annex IV technical
  documentation structure; for the UK it renders the five-principle narrative with sub-node evidence; for
  ISO and SOC it renders a statement-of-applicability-style control table.
- Acceptance for exhaustive: for a chosen subject and framework, the count of applicable plus
  not-applicable nodes equals the framework's full node count for that subject's role, with zero nodes
  left in not-assessed once the assessment is complete.

### B.8 Workstream ordering and acceptance

1. Reconcile slugs and ids, and delete the second hardcoded grading path in `grc.rs::report()` so all
   grading goes through `controls::library()`. Acceptance: one spelling per slug; every framework report
   renders controls, not an empty fallback; no `Art.14`/`A.8` id-format mismatch remains.
2. Move the catalogue to versioned data files with a coverage manifest and a CI completeness check (B.2).
   Acceptance: CI fails if a catalogue omits a manifest section.
3. Author the exhaustive node sets per framework (B.3, B.4), largest-impact acts first (EU AI Act, then
   NIST, ISO 42001, SOC 2, then GDPR, DPDP and UK, then Colorado, NYC, AIDA and ISO 23894). Acceptance:
   each framework's node count matches its coverage manifest, and every node has a citation.
4. Generalise the assessment engine to profiles plus the applicability engine (B.5, B.6). Acceptance: an
   operator can assess a subject against any in-scope framework and get a per-node conformity result;
   auto risk-tiering still works for the EU AI Act.
5. Exhaustive reporting and packs for every framework (B.7). Acceptance: the report enumerates all
   applicable and not-applicable nodes, pins the version, and exports signed; `acp verify-pack` verifies
   a pack for each.
6. Docs: rewrite guide chapter 12 to describe multi-framework exhaustive conformance, the catalogue,
   versioning, the applicability engine and the profiles; reconcile `docs/soc2-iso-control-mapping.md`,
   `docs/roadmap-tier-analysis.md` and the gap docs with the final framework set.

---

## Part C: content firewall (gateway-only) reference design

Decision: the content firewall runs at the LLM gateway, not on every workstation agent, and the build
is deferred. This section captures the reference design now so the gateway target is clear and the
console framing is right. Provenance note as in B0: the competitive references (Lakera Guard and the
guardrail category: Protect AI LLM Guard, NVIDIA NeMo Guardrails and the Aegis content-safety taxonomy,
Guardrails AI, Prompt Security, Robust Intelligence) are from working knowledge as of early 2026 and
should be validated against live product docs when web access is available.

Today the ACP content firewall is a signature set plus a small hashed-ngram logistic-regression
detector plus a toxicity lexicon plus an external scan hook. A mature AI firewall is broader; the
target below is what the gateway should grow into.

### C.1 Detection surface (input and output, both directions)

- Prompt injection and jailbreaks: direct (in the user prompt) and indirect (in a fetched document,
  tool result, or RAG context). This is the headline detector for every guardrail vendor.
- PII and secrets: names, emails, national ids, cards, plus API keys, tokens and credentials, with
  entropy gating so long ids do not false-positive.
- Data leakage and exfiltration: sensitive data leaving in the response, including system-prompt leak.
- Toxicity and harmful content: a category taxonomy (hate, harassment, self-harm, sexual, violence,
  weapons, illegal), as in the Aegis content-safety taxonomy, not a single toxicity flag.
- Off-topic and policy violation: relevance and allowed-topic enforcement per application.
- Groundedness and hallucination: is the response supported by its context (the reliable form of
  hallucination detection for RAG), which ACP already has a baseline for.
- Unsafe tool and agent actions: a bridge to the authorization policy (the firewall flags, the policy
  decides), and malicious URL and code detection in inputs and outputs.
- Multimodal: image and audio parts routed to a scanner via the existing external hook.

### C.2 Policy and configuration model

- Per-application and per-policy configuration, not one global switch. An application selects a policy;
  a policy is a set of category rules.
- Per category: an action (allow, block, redact, flag or monitor) and a threshold, plus allowlists and
  denylists and custom regex or keyword rules. This generalises the current single-config model.
- Granularity: per endpoint, and ideally per user group (tie into the group-based model already built),
  and per data class.
- Every decision is logged with the category, the score, the matched rule, and the action, so a block
  is explainable and becomes evidence.

### C.3 Deployment posture

- Inline at the gateway (blocking) on the request and response path, with an async monitoring mode for
  rollout (mirrors the policy observe mode). Low added latency is a hard requirement; keep the built-in
  detectors fast and route heavy or specialist detection to the external scan hook.
- The external scan-hook contract already exists and is the right seam for specialist detectors (a
  transformer-grade injection model, a managed content-safety service, a multimodal scanner). Keep the
  built-in engine as the on-prem floor and the hook as the augmentation, which is ACP's honest position.

### C.4 Dashboard and observability

- The gateway firewall view should show detections over time by category, blocked versus flagged
  counts, per-application and per-policy breakdowns, top offending categories, and recent incidents,
  with drill-down to the logged decision. This is the analytics story the guardrail vendors lead with,
  and ACP currently lacks.
- Tie firewall detections to governance: a block or a run of injections becomes evidence and can seed a
  finding or incident (ACP already has the memory-write and incident seams for this).

### C.5 Console and doc consequences now (no build)

- The Vue Content firewall screen frames the config as gateway scope, with the category-based policy
  model above as the target layout even if only the current toggles are wired initially.
- The guide (chapters 4 and 10) describes the content firewall as a gateway feature and keeps the
  honest boundary that authorization, not the filter, is the primary control.

## Sequencing across the plan

1. Part A.1 and A.2: scaffold the Vue app, port the theme and shell, prove the data path on Overview.
2. Part B.1: reconcile slugs and ids (small, unblocks correct reports) in parallel with A.
3. Part A.3: build the views, read-heavy first, then the forms.
4. Part B.2 and B.4: complete the report and pack surface and add the in-scope acts.
5. Part B.3: generalise the assessment engine and make the GRC assessment framework-aware (this is the
   largest single piece and benefits from the Vue GRC page being in place to drive it).
6. Part A.4: embed in acp-server, retire acp-console, update the setup docs.
7. Part C: the content-firewall doc and console framing, folded into the relevant view and chapters.

## Open questions to confirm before building

- Embed the SPA into the acp-server binary (`rust-embed`, single file) or serve from disk (`ServeDir`)?
  Recommend embed for a clean two-binary deploy.
- Keep a live `/sse/metrics` endpoint for the Vue app, or switch the console to a simple 2 second poll?
  Recommend poll for simplicity unless push latency matters.
- The exact list of acts to add in Part B.4 (Colorado AI Act and ISO 23894 and ISO 27001 are the
  strongest; confirm whether NYC LL144 and Canada AIDA are in scope now or later).
