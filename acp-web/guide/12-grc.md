# 12. Discovery, enrolment and GRC

Governing what you know about is only half the job. This chapter covers finding the AI you do not yet
govern, bringing it under policy, and producing the compliance artifacts an auditor asks for.

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

You can also register an endpoint from the web console's AI-endpoints page ([chapter 14](14-operations.md)),
which classifies the provider and records the same signed disposition.

Each disposition is Ed25519-signed, so it is tamper-evident evidence of an operator's decision. The
governed set feeds the [coverage report](#measuring-unavoidability), and the enrolment feeds the
[interceptor's rules](05-intercept.md) via `acp intercept from-enrollment`.

### How to register an AI endpoint (step by step)

1. Select **AI Endpoints** in the sidebar.
2. Click **+ Register endpoint**. The **Register an AI endpoint** popup opens.
3. Fill in **Endpoint (host or URL)** (required, for example `claude.ai`). The provider is classified automatically.
4. Choose a **Disposition**: `govern` (route through the control plane), `block` (quarantine), or `accept-risk` (time-boxed). Add a short **Reason**.
5. Click **Register endpoint**. The signed disposition is stored (the latest wins) and appears in the list. Re-registering the same endpoint updates its disposition.

## Measuring unavoidability

Two commands measure whether anything is acting off-ACP.

```sh
acp coverage observed.txt governed.txt --require-full    # signed coverage report
acp canary-egress targets.txt                            # fails (exit 3) if a model/tool is reachable off-ACP
```

`acp coverage` joins the observed endpoints against the governed set, lists ungoverned and leaky
paths, computes a coverage percentage, and signs the report. `--require-full` makes it gate a rollout.
`acp canary-egress` actively probes for direct model or tool access and fails if any host is reachable
without going through ACP.

## What is a governance record

If you are new to GRC (governance, risk and compliance), start here. A **governance record** is a
signed operator document that captures a compliance decision or artefact about an AI system. It is
paperwork, the kind an auditor asks for, written by a person and attested by the control plane. It is
**not** a runtime enforcement decision. When the proxy allows, denies or steps up an actual tool call,
that goes into the tamper-evident decision ledger ([chapter 9](09-evidence.md)). A governance record is
the human-authored document that sits above those decisions: "we assessed this system as high-risk",
"here is the model card", "here is our risk register entry". Think of the ledger as the flight recorder
and governance records as the logbook the crew signs.

Every governance record is Ed25519-signed by the control plane when you create it, stored in the
control-plane database, and re-verified whenever it is read, so the console shows a checked "signed"
state rather than an asserted one. The signature proves the document was not altered after signing. It
does not prove that any "evidence" or "linked-decision" reference written inside the record points at a
real ledger record: those references are author-supplied text today.

There are seven kinds. Choose the kind for what you are actually recording.

### assessment

**What it is for:** tiering a system under the EU AI Act (unacceptable, high, limited or minimal) and
listing the controls that tier must satisfy.

**When you create one:** at the start of governing a new AI system, to decide how much oversight it
needs.

**Worked example:** you are launching `hiring-screener`, an agent that ranks CVs. Because it makes
employment decisions, the screening flags it as an Annex III use, so the assessment tiers it **high**
and pulls the full EU AI Act high-risk obligation set (Articles 9 to 15: risk management, data
governance, technical documentation, record-keeping, transparency, human oversight, accuracy and
robustness). A plain spellchecker, by contrast, would come out **minimal** with no mandated controls.

### conformity

**What it is for:** turning the obligations from an assessment into a worked checklist you drive to
done, control by control, with an owner and evidence links on each.

**When you create one:** right after a high-risk assessment, to actually close the obligations.

**Worked example:** the `hiring-screener` assessment produced seven high-risk obligations. The
conformity record seeds all seven as `gap`. As your team completes each one you move it to `satisfied`,
name the owner (say `carol`, compliance) and attach the evidence. The record reports completeness
(for example 5 of 7, 71 percent), and it counts as conformant only when every control is `satisfied`.

### risk

**What it is for:** an AI risk register entry: a named risk scored likelihood by impact, with an owner,
a treatment and a lifecycle status.

**When you create one:** whenever you identify a specific risk you want to track to closure.

**Worked example:** "the screener may leak candidate PII into a model prompt". You set likelihood
`medium` and impact `high`, which gives an inherent score of 2 by 3 = 6 (a **high** band). You assign
the owner, choose a treatment (`mitigate`), set the status (`open`, then `mitigating`, `accepted` or
`closed`), and optionally link the controls and ledger decisions that bear on it.

### model-card

**What it is for:** the documented properties of a model or system: intended use, limitations, training
data, evaluation summary, owner, and the risk tier and use case it is bound to.

**When you create one:** for every model you put into service, so an auditor can read what it is and how
it was evaluated.

**Worked example:** a model card for the screener records provider `acme`, version `1.0`, intended use
"screen CVs", limitation "no protected-attribute use", evaluation summary "bias tested", owner
`hr-lead`, risk tier `high`, and a link to use case `uc-hire`. A completeness check flags a card that
is missing intended use, limitations, evaluation summary or owner.

### use-case

**What it is for:** a use-case lifecycle record that moves through gated stages: proposed, assessed,
approved, deployed, retired.

**When you create one:** to govern a use case end to end and enforce sign-off gates between stages.

**Worked example:** `uc-hire` starts `proposed`. It cannot move to `assessed` until an assessment is
linked, and it cannot move to `approved` until a valid approval attestation exists. Stages cannot be
skipped forward (proposed straight to deployed is refused), but a use case can be retired at any time.
Advance the status from the console or with `POST /grc/:id/status`, and the control plane re-signs the
record on the change, so the lifecycle move is itself signed evidence.

### attestation

**What it is for:** a named person attesting something about a subject, non-repudiably. It binds an
attestor and a role to a subject with a signature.

**When you create one:** whenever a human sign-off is required, for example the approval gate above.

**Worked example:** `carol`, in the role `compliance`, attests that the "conformity assessment approved"
for subject `assess-hiring`. The record binds her name and role to that statement and signature, so it
is a durable, verifiable sign-off rather than an email. This is the artefact the use-case approval gate
looks for. It is distinct from a break-glass approval, which gates a live action; an attestation is a
sign-off on the record.

### aibom

**What it is for:** an AI bill of materials over your supplied inventory: every agent, MCP server, tool
and model class in the estate, each with its provenance, admission verdict, integrity pin and the
policy in force over it.

**When you create one:** to answer "what AI is in our estate, where did each piece come from, and is it
governed" with a signed document rather than a spreadsheet. It is emitted as CycloneDX so it drops into
tools you already have.

**Worked example:** you feed in the inventory and the record lists each component (say a frontier model
class and two MCP tool servers) with its SHA-256 digest, its admission verdict and the policy hash in
force, and it flags anything that was denied admission.

**MITRE ATLAS enrichment:** when a model admission scan returns findings, ACP maps each finding kind to
its MITRE ATLAS technique id (for example a malicious pickle maps to AML.T0011.000, a prompt-injection
finding to AML.T0051) and annotates the AI-BOM entry (the CycloneDX `acp:atlas` property) and the
console Models page with them. This puts the standard adversarial-technique language an auditor or a SOC
already speaks on top of whatever the scanner returns. ACP does not run the scanner itself; it enriches
its output.

### When do I use a governance record versus the evidence ledger?

Use the **evidence ledger** when you want proof of what actually happened at runtime: it is the signed,
tamper-evident, hash-chained record of every allow, deny and step-up the proxy made, and you cannot
edit it. Use a **governance record** when you want to document a human governance decision or artefact
about a system: a risk tier, a checklist, a risk item, a model card, a lifecycle stage, a sign-off or a
bill of materials. The ledger is machine-generated proof; governance records are author-attested
paperwork. Both are signed and useful, but do not present a governance record as if it were ledger
proof: an auditor gets runtime evidence from the ledger and documented governance from these records.

The signed control packs now cover seven frameworks: EU AI Act, NIST AI RMF, ISO/IEC 42001, SOC 2,
GDPR, India DPDP Act and the UK AI principles. Each is a signed, versioned data pack, verified before
it loads.

## Oversight-quality monitoring

Human oversight has to be effective, not just present (EU AI Act Article 14). Because the control plane
records every approval decision with the approver, the request time and the decision time, it can
measure whether oversight is real or rubber-stamping, rather than assume it.

In the console, open **Oversight** (under Governance). The page lists each approver with their decision
count, approve rate, median decision time, and an effective-or-weakness badge. An approver is flagged
when they approve nearly everything, decide faster than a human plausibly could have reviewed, or
approve in bulk within a short window. The thresholds are configurable, and a change to them is written
to the meta-audit log. Flagging an approver writes a signed governance finding, so the weakness is
itself tamper-evident evidence.

> API (for automation and CI): `GET /oversight` returns the same profiles, `POST /oversight/config`
> updates the thresholds, and `POST /oversight/scan` writes the signed findings. These are for
> schedulers; day to day, use the console page above.

## The GRC surface

Varman produces two honestly different kinds of compliance artifact. Know which is which.

### Ledger-backed (derived from real signed records)

- **`acp grc-report evidence.db`** grades EU AI Act, NIST AI RMF and ISO 42001 controls from counts
  decoded out of real ledger decision records.
- **`acp siem`** projects real decisions into your SIEM ([chapter 9](09-evidence.md)).
- **Warehouse re-verification** re-checks an exported evidence row against a Merkle inclusion proof
  and a signed tree head.

These are as strong as the ledger, because they are the ledger.

### Signed operator documents (author-attested)

You create these from the console's **Governance** page (the **Create governance record** popup, which
carries a **Kind** selector) or the control-plane API (`POST /grc`). Each record is Ed25519-signed by
the control plane, stored in the control-plane database, and re-verified on read. The signature proves
the document was not altered after signing; it does **not** prove that the "evidence" or
"linked-decision" references inside it correspond to real ledger records, because those are free-text
today. The seven record **kinds** (assessment, conformity, risk, model-card, use-case, attestation and
aibom) and when to use each are explained with worked examples under
[What is a governance record](#what-is-a-governance-record) above.

The static control library across the three frameworks is served by the control plane and shown on the
console Governance page. (These record kinds were previously separate `acp` subcommands; management now
lives in the console and the control-plane API, so the CLI subcommands are retired.)

Advancing a record's status is not API-only. Each record on the console Governance panel carries per-record
**Review**, **Approve** and **Close** controls that POST to `POST /grc/:id/status`; the control plane
re-signs the record on the change, so the lifecycle move is itself signed evidence, not an unsigned edit.

Both kinds are useful. An auditor gets runtime proof from the ledger-backed set and documented
governance from the signed set. Do not present the second kind as if it were the first.

### How to create a governance record (step by step)

1. Select **Governance** in the sidebar.
2. Click **+ Create record**. The **Create a governance record** popup opens.
3. Choose a **Kind** (`assessment`, `conformity`, `risk`, `model-card`, `use-case`, `attestation` or `aibom`).
4. Fill in **Subject** (required, the system or agent the record is about, for example `checkout-agent`) and, optionally, a **Title** and **Status** (defaults to `open`).
5. Put the record content in **Details** as JSON or plain text.
6. Click **Create record**. The control plane signs it (Ed25519), stores it in the control-plane database, and re-verifies it on read, so the list shows a checked "signed" state, not an asserted one.

### How to run a guided assessment (step by step)

Rather than hand-authoring an assessment, use the guided wizard so the tier and the control checklist are computed for you.

1. Select **Governance** in the sidebar.
2. Click **+ New assessment**. The **New EU AI Act assessment** popup opens.
3. Fill in **Subject** (required) and optionally a **Title** and an **Assignee**.
4. Answer the nine screening questions (prohibited practice, safety component or Annex III use, biometric identification, critical infrastructure, employment or education, essential services, law enforcement, interacts with people, generates content).
5. Click **Run assessment**. The control plane runs the deterministic screening, assigns the EU AI Act tier (unacceptable, high, limited or minimal) and builds a control checklist from the built-in control library. It signs and stores the record.
6. The new record appears in the table with its **Tier**, **Stage**, **Assignee** and a **Controls** cell showing progress (for example `0/7 controls`).

The screening questionnaire itself is served at `GET /grc/templates`, so a client can render the same wizard from the control plane's own definition.

### How to work an assessment or conformity checklist (step by step)

1. In the **Governance** table, open the **Controls** cell for the record (click the `k/m controls` disclosure).
2. Each control shows its framework id (for example `art-14`), title and current state (`open` or `done`).
3. Click **Mark done** as your team completes a control, or **Reopen** to reverse it. Every toggle re-signs the record server-side, so the checklist progress stays tamper-evident and the record still reads as verified.
4. Use **Review**, **Approve** or **Close** to advance the record's stage; the stage change also re-signs.
5. Set or change the **Assignee** to route the work to an owner.

The checklist lives inside the signed document, so `k/m` progress is part of what the Ed25519 signature covers, not a side note.

### Linked evidence on a governance record

When you create a record you can list **Linked decision ids** (comma separated). These are advisory references to decisions in the evidence ledger. The control plane checks each id against the central ingested-evidence store and shows a ratio such as `1/2 verified` in the record row. It never trusts or rewrites what you typed: an id that does not exist in the ledger simply counts as unverified. A record with no linked ids shows `0/0`.
