# Varman

**Varman, the Agent Control Plane (ACP).** Varman (Sanskrit: armour, a shield) is a vendor-neutral,
on-premises layer that governs what your AI agents and applications actually do, decides whether each
action is allowed, and records every decision as tamper-evident evidence that a third party can
verify with a public key alone.

It is a single, complete product that combines what an AI firewall does, what a GRC platform does, and
the runtime authorization and verifiable evidence that neither of them provides, so you do not have to
assemble three tools.

## What it does

- Controls what agents may do at the resource boundary (which database, secret, file, model, network),
  with allow, deny, require-human-approval, or allow-with-obligations.
- Proves what happened, in a signed, tamper-evident ledger that verifies independently.
- Stops content attacks (prompt injection, jailbreaks, PII, secrets), hardened against obfuscation and
  indirect injection.
- Governs sequences and data flow (toxic combinations, exfiltration, data-boundary enforcement).
- Keeps a human in control (step-up approvals, separation of duty, a scoped signed kill-switch).
- Covers every surface: agent tool calls (MCP), model APIs, arbitrary HTTP/API traffic, and coding
  agents' own powers.
- Satisfies auditors: evidence-backed EU AI Act, NIST AI RMF and ISO 42001 reports from real runtime.

## Start here

- Is it right for you: `docs/evaluation-guide.md`
- Security and cryptographic design: `docs/security/whitepaper.md`
- Run the end-to-end acceptance: `bash demo/vertical/run.sh`
- Reference deployment: `deploy/`
- Commercial readiness and the honest gaps: `docs/commercial/pre-launch-requirements.md`

The codebase uses the `acp-` prefix (Agent Control Plane) as its internal architecture identifier;
the product brand is Varman.

## Status

A complete, tested reference implementation (large passing test suite plus a ten-of-ten end-to-end
acceptance for the core governance vertical). Not yet a commercially hardened product: single-node
verified, no third-party certifications yet, no production references. See
`docs/commercial/pre-launch-requirements.md`.

## Licence

Apache-2.0.
