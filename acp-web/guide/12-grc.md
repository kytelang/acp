# 12. Discovery, enrolment and GRC

Governing what you know about is only half the job. This chapter covers finding the AI you do not yet
govern, bringing it under policy, and producing the compliance artifacts an auditor asks for. The GRC
model is anchored on the AI system: you register a system once, declare who you are for it in each
market, work its controls per framework, attach evidence, and generate a signed report that is aware of
your jurisdiction.

## Discovering shadow AI

`acp discover` classifies ungoverned model-API and MCP endpoints by provider, from an egress log or
an endpoint list, against a table of known AI hosts and MCP path hints.

```sh
acp discover egress.log          # list shadow-AI endpoints and their providers
```

It produces a worklist and marks scopes it did not cover, so a partial scan does not masquerade as
complete.

## Enrolling endpoints

Register discovered endpoints from the console's **AI Endpoints** page, or the control-plane API,
which records a **signed disposition** per endpoint (the latest wins) in the control-plane database:

```sh
curl -X POST http://<host>:8787/endpoints/register \
  -d '{"endpoint":"claude.ai","disposition":"govern","reason":"sanctioned"}'
# disposition is govern (route through ACP), block (quarantine), or accept-risk (time-boxed)
curl http://<host>:8787/endpoints            # the current dispositions
```

Each disposition is Ed25519-signed, so it is tamper-evident evidence of an operator's decision. The
governed set feeds the coverage report and the [interceptor's rules](05-intercept.md) via
`acp intercept from-enrollment`.

## The GRC model: everything hangs off the AI system

Older versions of Varman kept governance as a flat list of signed records. That could not answer the
question an auditor actually asks: "for this AI system, what is its compliance posture against the
regulation that applies in my jurisdiction, with the evidence, as a signed report I accept." The model
is now anchored on a first-class **AI system**, and every other object hangs off it. All of it is
implemented and live.

The moving parts:

- an exhaustive, versioned **control catalogue** (12 frameworks, 494 controls),
- an **AI system** registry (the use-case anchor),
- **roles per system** that drive which controls apply,
- a persisted **Statement of Applicability** (SoA) per system and framework,
- **evidence** as first-class records with freshness,
- the **control crosswalk** (author once, satisfy many frameworks),
- **conformity states** per control with a rollup,
- an **immutable change-history** plus signed, as-at report snapshots.

### The control catalogue

The catalogue is exhaustive and versioned as data, not hand-written code. It ships inside the binary,
read-only, under `crates/acp-core/catalogue/<slug>@<version>.yaml`. It covers twelve frameworks and 494
controls: EU AI Act, NIST AI RMF, ISO/IEC 42001, ISO/IEC 27001, SOC 2, GDPR, India DPDP 2023, UK AI
principles, Colorado AI Act, NYC LL144, Canada AIDA and ISO/IEC 23894.

Each control is not just an id and a title. It carries a hierarchy path (for example Chapter III,
Section 2, Article 14), a normative reference (`Art. 14`, `A.8.2`, `CC6.1`, `GOVERN 1.1`), an
obligation type (govern, document, technical, process, transparency, oversight, record-keeping,
prohibition), the roles it binds (provider, deployer, importer, distributor, controller, processor), an
applicability predicate (for example `risk_tier in [high]`, `role=deployer`, `asset_type=gpai`), an
evidence type (attestation, artefact, test, ledger), a crosswalk to equivalent controls in other
frameworks, and a citation to the official source. Each framework also declares its **type**
(`statutory_conformity`, `principles_based`, `standard` or `sectoral`), which is what makes a UK report
read differently from an EU one. See "Jurisdiction-aware reporting" below.

### Registering an AI system

The AI system is the hub. Register it once with: id, name, purpose, owner, lifecycle state (intake,
development, staging, production, retired), risk tier, sector and the set of jurisdictions it operates
in (for example `["uk","eu"]`).

```sh
curl -X POST http://<host>:8787/systems \
  -d '{"name":"hiring-screener","purpose":"rank CVs","owner":"hr-lead",
       "risk_tier":"high","sector":"employment","jurisdictions":["uk","eu"]}'
curl http://<host>:8787/systems            # the registry
```

In the console, open **Governance**, **AI Systems** and click **+ Register system**.

### Declaring roles per system

The same system is governed differently depending on what your organisation is for it in a given
market. Declare a role (provider, deployer, importer or distributor) per jurisdiction:

```sh
curl -X POST http://<host>:8787/systems/<id>/roles \
  -d '{"role":"deployer","jurisdiction":"uk"}'
```

Roles feed the applicability predicate on each control, so a UK deployer and an EU provider of the same
system see different applicable control sets and therefore report differently. This is not a display
filter: it drives which obligations bind you.

### The Statement of Applicability

For each system and framework, Varman persists a Statement of Applicability: one row per control saying
whether it is **applicable** or not, a **justification** (the reason it is excluded, or the note on how
it is met), and a **status** (planned, in progress, implemented). The framework report is graded
directly from the SoA, so the SoA is the working surface, not a report artefact.

```sh
curl http://<host>:8787/systems/<id>/soa/eu-ai-act          # read the SoA for a framework
curl -X POST http://<host>:8787/systems/<id>/soa/eu-ai-act \
  -d '{"control_id":"art-14","applicable":true,"status":"implemented",
       "justification":"human reviewer signs every rejection"}'
```

In the console, open the system, pick a framework tab, and work down the control list. The applicable
set is seeded from the control catalogue's predicates against the system's profile and roles; you can
override any row with an explicit applicable-or-not and a justification.

### Evidence with freshness

Evidence is a first-class record bound to a system, framework and control. Each piece carries a title,
a source, an owner, a produced timestamp, an artefact reference and, crucially, a **valid_until**
freshness date.

```sh
curl -X POST http://<host>:8787/systems/<id>/evidence \
  -d '{"framework":"eu-ai-act","control_id":"art-12","title":"audit-log config",
       "source":"ledger","owner":"carol","valid_until_ms":1790000000000}'
```

Freshness gates the grade. A control the SoA marks implemented but which has no fresh evidence (none
attached, or every piece expired) does not count as conformant: it drops to **partial**, with the
reason "claimed implemented but no fresh evidence". A signed report is then honest about its own
currency rather than presenting stale paperwork as live proof.

### The control crosswalk: author once, satisfy many

Every control declares a crosswalk to equivalent controls in other frameworks, and the report resolver
walks that graph symmetrically. Evidence attached to one control automatically satisfies the mapped
controls in every other framework. Attach EU AI Act Art. 12 (record-keeping) evidence once and it also
satisfies GDPR Art. 30 (records of processing); the GDPR report shows that control conformant with the
reason "satisfied via crosswalk: eu-ai-act:art-12". You assess and collect once, and report against
whichever regulations apply.

### Conformity states and the rollup

Each control in a report resolves to one conformity state: **conformant**, **partial**,
**non-conformant**, **not-applicable** or **not-assessed**. The logic, in order: a control the SoA
excludes is not-applicable; one that is applicable, marked implemented and backed by fresh evidence is
conformant; one implemented but without fresh evidence is partial; one satisfied via a crosswalk edge is
conformant; anything else falls back to its SoA status or, with no SoA row at all, not-assessed. The
report carries a **conformity rollup**: totals for applicable, not-applicable, conformant, partial,
non-conformant and not-assessed, so the posture is one glance.

### Immutable change-history and as-at reporting

Every governance change to a system (created, roles declared, SoA updated, evidence added) appends an
immutable event to the change-history (`grc_audit`): who did what to which entity, when. This is the
audit trail an assessor relies on, and it is append-only.

```sh
curl http://<host>:8787/systems/<id>/audit          # the change history, newest first
```

Because history is preserved, a report can be rendered **as at** any past date. Pass `as_at` (epoch
milliseconds) and the resolver filters evidence and SoA rows to only those that existed by that instant,
so you can reproduce the conformance posture as it stood on the day of an incident or a prior audit,
not just today.

```sh
curl "http://<host>:8787/systems/<id>/report/eu-ai-act?as_at=1780000000000"
```

Reports are also stored as immutable, signed snapshots, so a point-in-time rendering is pinned and
reproducible.

## Jurisdiction-aware reporting

The report is `(system) x (framework) -> graded, signed, versioned`. It branches on the framework's
type, because the regimes are genuinely different in shape:

- **EU AI Act** is `statutory_conformity`: enumerated Annex obligations, pass or fail, the Art. 9 to 15
  controls with status and evidence, data governance, human oversight, accuracy and robustness,
  post-market monitoring, and a conformity declaration (the Annex IV technical documentation shape).
- **UK AI principles** is `principles_based`: there is no single UK AI statute, so the report is a
  principle-by-principle narrative (safety and robustness, transparency and explainability, fairness,
  accountability and governance, contestability and redress) with the same evidence bound under each
  principle, plus the relevant sector-regulator expectations. It is attestation-style, not a pass/fail
  checklist.

An organisation operating in both markets registers one system, declares an EU provider role and a UK
deployer role, works one SoA, and generates both reports off the same crosswalked evidence.

## The console flow, end to end

1. **Register the system.** Governance, AI Systems, **+ Register system**. Give it a name, purpose,
   owner, risk tier, sector and jurisdictions.
2. **Declare roles.** On the system, add a role per jurisdiction (provider, deployer, importer,
   distributor). This sets which controls bind you in each market.
3. **Work the SoA per framework.** Open a framework tab. For each control, confirm it is applicable (or
   exclude it with a justification) and move its status towards implemented as your team closes it.
4. **Attach evidence.** Bind each piece of proof to its control with an owner and a valid_until date.
   The crosswalk carries it to mapped controls in other frameworks automatically.
5. **Generate and download the report.** The framework report is graded live from the SoA and evidence,
   with the conformity rollup and any freshness or crosswalk reasons per control. Download it as a signed
   JSON-LD pack (`@type: acp:ComplianceReport`, `conformsTo` the framework, verifiable offline with
   `acp verify-pack` and the public key alone) or as CSV for the controls table. Reporting is
   jurisdiction-aware: the UK principles-based narrative and the EU statutory Annex IV report come from
   the same object graph.

> API: `GET/POST /systems`, `GET /systems/:id`, `POST /systems/:id/roles`,
> `GET/POST /systems/:id/soa/:framework`, `GET/POST /systems/:id/evidence`,
> `GET /systems/:id/audit`, `GET /systems/:id/report/:framework?as_at=<ms>`, and the signed pack and CSV
> at `GET /report/framework/:name/pack` and `GET /report/framework/:name/csv`. Day to day, use the
> console; the API is for schedulers and CI.

## Runtime evidence still counts

The system-anchored model documents governance; it does not replace the runtime record. When the proxy
allows, denies or steps up an actual tool call, that goes into the tamper-evident decision ledger
([chapter 9](09-evidence.md)), an append-only Merkle log with a signed tree head. Evidence with source
`ledger` binds a control to that machine-generated proof, so a report can cite runtime facts rather than
author-attested paperwork. Post-market monitoring (EU AI Act Art. 72), serious-incident cases (Art. 73)
and the auditor evidence pack (`GET /audit/pack`, verified with `acp verify-pack`) all draw from the
ledger, so the strongest parts of a report are the ledger itself.

::: tip Per-regulation reference
The complete, code-aligned control list for each framework, with how Varman supports it and how evidence and reporting work, is in the [Conformance reference](/guide/conformance/).
:::
