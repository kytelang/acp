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
today. Choose the record **kind** for what you are recording:

- **assessment** tiers a system under the EU AI Act (unacceptable / high / limited / minimal) and
  lists the controls it must satisfy.
- **conformity** turns those obligations into a worked checklist you drive to conformant.
- **risk** is an AI risk register scored likelihood by impact, with treatment and lifecycle.
- **model-card** is a model-card registry.
- **use-case** is a use-case lifecycle registry (proposed to assessed to approved to deployed to
  retired); advance its status from the console or with `POST /grc/:id/status`.
- **attestation** binds a named attestor and role to a subject, non-repudiably.
- **aibom** records a CycloneDX AI bill of materials over your supplied inventory.

The static control library across the three frameworks is served by the control plane and shown on the
console Governance page. (These record kinds were previously separate `acp` subcommands; management now
lives in the console and the control-plane API, so the CLI subcommands are retired.)

Both kinds are useful. An auditor gets runtime proof from the ledger-backed set and documented
governance from the signed set. Do not present the second kind as if it were the first.

### How to create a governance record (step by step)

1. Select **Governance** in the sidebar.
2. Click **+ Create record**. The **Create a governance record** popup opens.
3. Choose a **Kind** (`assessment`, `conformity`, `risk`, `model-card`, `use-case`, `attestation` or `aibom`).
4. Fill in **Subject** (required, the system or agent the record is about, for example `checkout-agent`) and, optionally, a **Title** and **Status** (defaults to `open`).
5. Put the record content in **Details** as JSON or plain text.
6. Click **Create record**. The control plane signs it (Ed25519), stores it in the control-plane database, and re-verifies it on read, so the list shows a checked "signed" state, not an asserted one.
