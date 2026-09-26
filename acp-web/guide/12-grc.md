# 12. Discovery, enrolment and GRC

Governing what you know about is only half the job. This chapter covers finding the AI you do not yet
govern, bringing it under policy, and producing the compliance artifacts an auditor asks for.

## Discovering shadow AI

`acp discover` classifies ungoverned model-API and MCP endpoints by provider, from an egress log or
an endpoint list, against a table of known AI hosts and MCP path hints.

```sh
acp discover < egress.log        # list shadow-AI endpoints and their providers
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

## Measuring unavoidability

Two commands measure whether anything is acting off-ACP.

```sh
acp coverage observed.txt governed.txt --require-full    # signed coverage report
acp canary-egress probes.json                            # fails (exit 3) if a model/tool is reachable off-ACP
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

You create these from the console's **Governance** page or the control-plane API (`POST /grc`), and
they are Ed25519-signed by the control plane and stored in the control-plane database, then re-verified
on read. The signature proves the document was not altered after signing; it does **not** prove that
the "evidence" or "linked-decision" references inside it correspond to real ledger records, because
those are free-text today. The `acp` commands below remain for scripting and offline use.

- **`acp assess`** tiers a system under the EU AI Act (unacceptable / high / limited / minimal) from
  a questionnaire and lists the controls it must satisfy.
- **`acp conformity`** turns those obligations into a worked checklist you drive to conformant.
- **`acp risk`** is an AI risk register scored likelihood by impact, with treatment and lifecycle.
- **`acp modelcard`** is a model-card registry.
- **`acp usecase`** is a use-case lifecycle registry (proposed to assessed to approved to deployed to
  retired) that refuses a transition without a linked assessment or attestation.
- **`acp attest`** binds a named attestor and role to a subject, non-repudiably.
- **`acp aibom`** emits a signed CycloneDX AI bill of materials over your supplied inventory.
- **`acp controls`** is the static control library across the three frameworks.

Both kinds are useful. An auditor gets runtime proof from the ledger-backed set and documented
governance from the signed set. Do not present the second kind as if it were the first.
