# Control-framework mappings (v1.2.1)

This maps ACP's enforced controls and the evidence they produce to the obligations of the major AI
and security frameworks, so an assessor can trace a specific requirement to a specific, verifiable
artifact in the ledger. Each row names the ACP mechanism (a decision id, a code module, or an export
field) that evidences the obligation. The mapping is expressed as data so a GRC platform can pull it
by control id (see `acp_core::grc`); this document is the human-readable form.

Status note: this is the ACP-authored mapping. It still needs review by a compliance or legal
specialist before it is used in a formal audit; that review is the only open leg of v1.2.1.

## How to read the evidence column

- "Ledger: <field>" means the property is provable from an exported evidence pack (`acp export` /
  `acp verify-pack`) without trusting the running service.
- "Module: <name>" means the control is implemented and unit-tested in that ACP module.
- "Report: <field>" means the figure is on the governance report (`/report`), re-derivable from the
  verifiable log.

## EU AI Act (high-risk AI system obligations)

| Article / obligation | ACP control | Evidence |
| --- | --- | --- |
| Art. 12 record-keeping / logging | Every tool call is a signed, append-only ledger leaf | Ledger: leaf_hash, STH; `acp verify` |
| Art. 14 human oversight | Step-up holds a high-impact action for human approval | Ledger: verdict=step_up + linked approval outcome |
| Art. 13 transparency of operation | Explainable denials carry rule id, reason, impact | Ledger: rule_id, matched, impact |
| Art. 9 risk management (traceability) | Impact taxonomy versioned into each record | Ledger: impact.taxonomy; Module: impact |
| Art. 15 accuracy / robustness of controls | Classifier eval harness with a regression gate | Module: classify + classify_eval tests (D2) |
| Post-market monitoring | Drift monitoring + governance report | Module: drift (D6); Report: verdicts, coverage |

## ISO/IEC 42001 (AI management system)

| Clause / Annex A control | ACP control | Evidence |
| --- | --- | --- |
| A.6 AI system impact assessment | Per-call impact scoring, versioned taxonomy | Module: impact; Ledger: impact |
| A.7 data for AI systems (lineage) | Data-class-to-tool lineage from labels only | Module: lineage (v2.2.1) |
| A.9 use and operation controls | Policy-gated enforcement of tool calls | Module: policy/eval; Ledger: decision |
| A.10 third-party and change control | Self-governance meta-audit of policy/key/RBAC changes | Module: metaaudit (H0.7); Ledger: type=meta |
| Performance evaluation / monitoring | Report posture score, coverage, weakening flags | Report: posture_score, weakening |

## NIST AI RMF (functions)

| Function | ACP control | Evidence |
| --- | --- | --- |
| GOVERN (policy, roles, accountability) | RBAC over edit-policy/approve/export/see-args | Module: acp-auth (H0.8) |
| MAP (context, impact) | Impact taxonomy + data-boundary lineage | Module: impact, lineage |
| MEASURE (metrics, drift) | Classifier eval + drift + perf gate | Module: classify_eval, drift, perf gate |
| MANAGE (response, oversight, recovery) | Step-up approvals, break-glass, DR restore | Module: approvals, breakglass, ledger DR test |

## SOC 2 / NIST 800-53 (security controls the platform itself meets)

| Control | ACP mechanism | Evidence |
| --- | --- | --- |
| AC-3 access enforcement | Policy engine denies/steps-up gated calls | Ledger: decision; Module: grc maps to AC-3 |
| AU-2 / AU-9 audit events + protection | Tamper-evident Merkle log with signed heads | Ledger: STH; `acp verify`; Module: grc -> AU-2 |
| AU-10 non-repudiation | Ed25519-signed tree head, key-id rotation history | Module: sign, keymgr (H0.3) |
| SC-8 transmission integrity | mTLS between proxy and server, signed webhooks | Module: acp-mtls, webhook (F10); [x] mTLS |
| CP-9 / CP-10 backup + restore | Restore drill re-verifies the ledger | Ledger: backup/restore drill test (H0.4) |
| SI-4 monitoring | Liveness gap + fail-open spike detection | Module: liveness (B1), anomaly (B3) |
| SI-7 software/firmware integrity | Tool-server fingerprint recorded in evidence | Ledger: tool_server_fingerprint (B5) |

## Sector retention overlays

Minimum-retention obligations (SEC 17a-4, FINRA 4511, MiFID II record-keeping) are enforced by the
retention-floor rule: a purge or tier move that would drop below the mandated minimum is refused.
See `docs/ops/cost-and-tiering.md`. The mapping of each sector rule to its retention window is a
per-tenant configuration reviewed with the customer.

## What this mapping deliberately does not claim

ACP evidences these controls; it does not by itself make a customer compliant. The customer's own
policies, their data governance outside the proxy, and the independent audits in the plan's `[e]`
set are required for a certification. This document is the traceability layer that makes those
audits efficient, not a substitute for them.
