# Enterprise trust plan (C2)

This is a written plan, not code. It sets out how Varman (the ACP control plane and its enforcement
points) earns and keeps enterprise trust: the certification path, the support and SLA model, the
security-review cadence, and how the product's verifiable-evidence architecture serves as an audit
asset. It is deliberately honest about what exists today versus what is planned.

## 1. Certification path

### SOC 2 (Type I then Type II)

- **Scope.** The control plane (`acp-server`), the console (`acp-console`), and the managed workstation
  agent (`acp-agent`), plus the build and release pipeline. Trust Services Criteria: Security
  (required), Availability, and Confidentiality; Processing Integrity is a natural fit given the signed
  evidence ledger.
- **Sequence.** (1) readiness assessment and gap analysis; (2) remediate gaps and operate the controls
  for the observation window; (3) Type I (design of controls at a point in time); (4) Type II (operating
  effectiveness over 6 to 12 months).
- **Control themes.** Access control (the RBAC / SCIM work in A5 is the technical backbone), change
  management (signed policy packs and the meta-audit log), encryption at rest and in transit (ledger
  KEK, mutual TLS, HSM signing), logging and monitoring (structured STDERR logs, SIEM export), incident
  response, vendor management, and backup / DR (the C1 leader lease, shared-state persistence and the
  verify-on-restore path).

### ISO/IEC 27001, and the AI-specific ISO/IEC 42001

- **27001** covers the information-security management system (ISMS): Statement of Applicability against
  Annex A, risk assessment and treatment, and the internal-audit plus management-review cycle.
- **42001** covers the AI management system (AIMS). This is where Varman is differentiated: the product
  is itself an AIMS control surface, so the same evidence that governs customer AI also evidences our
  own 42001 posture. The built-in control library and framework packs (A4) map directly to 42001
  clauses.

### EU AI Act

Varman's assessment engine (A1) tiers a system under the EU AI Act and drives the high-risk obligation
checklist. For our own high-risk features we run the same wizard and keep the signed record, so our
conformance is demonstrated with the product, not asserted alongside it.

## 2. Support and SLA model

| Tier | Audience | Response targets | Channels |
| --- | --- | --- | --- |
| Community | Evaluators, PoC | Best-effort | Issues, docs |
| Standard | Production, single region | P1 4h / P2 1 business day, business hours | Email, ticket portal |
| Enterprise | Production, regulated | P1 1h / P2 4h, 24x7; named CSM; quarterly review | Ticket portal, shared channel, phone bridge |

- **Availability SLA.** Enterprise targets 99.9% monthly for the control plane, backed by the C1 HA
  topology (two or more replicas behind one shared store, a fenced leader lease, and shared liveness /
  alert state that survives failover). The enforcement points fail safe independently of control-plane
  availability, which is documented as a design property, not an SLA loophole.
- **Severity definitions, escalation ladder and credits.** Defined in the order form; P1 is a
  production outage or a security incident, P2 is degraded governance, P3 is a question or minor defect.
- **Maintenance.** Announced windows; the HA topology allows rolling upgrades with no governance gap.

## 3. Security-review cadence

- **Continuous, in-product.** The detection-efficacy CI gate (C3) runs on every change; the continuous
  red-teaming runner (B4) records a signed attestation per run and flags regressions below the catch
  threshold; the model-admission scanner (B3) gates new models with a signed AI-BOM.
- **Per release.** Dependency and supply-chain scan, SAST, and a review of any change to the trust core
  (signing, ledger, authorisation).
- **Quarterly.** Internal security review and threat-model refresh; rotation drill for keys and the
  break-glass path.
- **Annual.** Independent third-party penetration test and a cryptographic review of the evidence
  architecture (Merkle construction, signature scheme, canonicalisation). Findings are tracked to
  closure and summarised for customers under NDA.
- **Ongoing.** A coordinated vulnerability-disclosure policy and a security contact; threat-intel packs
  (B5) keep the firewall signatures current between releases.

## 4. The verifiable-evidence architecture as an audit asset

Varman's differentiator for an auditor is that its claims are checkable, not asserted:

- **Every decision is signed and chained.** Each enforcement point keeps a tamper-evident Merkle
  ledger; `acp verify` checks the chain and every record signature, and a standalone export verifies on
  a clean machine with only the public key. An auditor can re-derive the evidence rather than trust a
  dashboard.
- **Governance records are signed operator documents.** Assessments, conformity checklists, risk
  entries, model cards and attestations (A1) are Ed25519-signed and re-verified on read; status and
  checklist changes re-sign, so progress is tamper-evident. Linked evidence (A2) is reconciled against
  the ledger, so a control's "satisfied" claim points at real decisions.
- **Central fleet evidence is re-verified, not asserted.** The control plane re-signs and re-verifies
  ingested decision records; the console shows a checked state, never an asserted one.
- **Framework content is signed and versioned.** Control packs (A4) and threat packs (B5) carry
  signatures; a tampered pack is rejected on load and packs re-verify on read.
- **Regulator-ready exports.** The framework report (A6) combines control status, linked-evidence
  counts, the breach summary and coverage into a structured, printable, exportable artefact an auditor
  can consume directly.

Because the same signed evidence serves both customer governance and our own SOC 2 / ISO / EU AI Act
posture, the audit cost compounds downward: one verifiable substrate, many attestations.

## 5. Honest status

In place today: the technical controls named above (RBAC / SCIM, signing, HSM, mTLS, ledger KEK, HA and
DR, the CI efficacy gate, red-teaming, model admission, signed packs, regulator exports). Not yet in
place: the certifications themselves (they require an operating history and an external auditor), a
staffed 24x7 on-call, and a public trust portal. This plan is the roadmap to close that gap; it is
reviewed each quarter alongside the security review.
