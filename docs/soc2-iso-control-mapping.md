# Control mapping and readiness: SOC 2, ISO/IEC 27001, ISO/IEC 42001 (R6)

This is a readiness assessment, not an audit and not code. It maps the technical controls that already
exist in Varman (the ACP control plane and its enforcement points) to the SOC 2 Trust Services Criteria,
the ISO/IEC 27001:2022 Annex A controls, and the ISO/IEC 42001 AI management system. It is deliberately
honest about the difference between a control that exists in the product and the documented policy plus
operating evidence an auditor needs. It complements `docs/enterprise-trust-plan.md`, which sets out the
certification sequence and timeline.

The central point: most of the technical substance exists, and the signed evidence ledger is itself the
audit asset. The remaining work for certification is documented policy, an operating window, and an
auditor, not new product features.

## Readiness legend

- **Implemented**: the control exists in the product and is exercised by tests or a drill.
- **Partial**: the mechanism exists but needs configuration, an operating window, or documented policy.
- **Process**: no code gap; this is a policy, an organisational practice, or a third party.

## 1. SOC 2 Trust Services Criteria

| TSC | Criterion | Varman control | Readiness |
| --- | --- | --- | --- |
| CC6.1 | Logical access, least privilege | acp-auth RBAC capabilities and roles; per-request authorization on every mutating route; SCIM user/group provisioning | Implemented |
| CC6.1 | Authentication of principals | Entra JWT verification (RS256 + JWKS rotation); attested workstation identity via acp-agent | Partial (real-tenant cutover pending, see R7) |
| CC6.6 | Encryption in transit | mutual TLS between PEPs and the control plane | Implemented |
| CC6.7 | Encryption at rest, key management | ledger KEK; Ed25519 signing keys; optional PKCS#11 HSM signing | Partial (HSM is deployment-specific) |
| CC7.1 | Detection of security events | content firewall, injection/PII/secret detectors, CI efficacy gate, threat-feed signatures | Implemented |
| CC7.2 | Monitoring and alerting | structured logs, SIEM export, webhooks (HMAC-signed), drift and lineage monitors | Implemented |
| CC7.3 | Evaluation and response | red-team runner; approval SLA escalation; kill-switch across surfaces | Implemented |
| CC7.4 | Incident response | break-glass with dual control; meta-audit of every governance action | Partial (runbook is process) |
| CC8.1 | Change management | signed policy and threat packs (verify-on-load); signed AI-BOM; content-pack versioning | Implemented |
| A1.1 / A1.2 | Availability, recovery | HA leader lease with shared-store fencing; verify-on-restore; the soak + failover drill (R8) | Implemented |
| C1.1 / C1.2 | Confidentiality | redaction on the scan path; retention policy; least-privilege access | Partial (retention window is policy) |
| PI1.1 | Processing integrity | Ed25519-signed records; RFC 6962 Merkle ledger with `acp verify`; fencing tokens | Implemented |

## 2. ISO/IEC 27001:2022 Annex A (selected)

| Annex A | Control | Varman control | Readiness |
| --- | --- | --- | --- |
| A.5.15 | Access control | RBAC capabilities and roles (acp-auth) | Implemented |
| A.5.16 | Identity management | SCIM provisioning; Entra app-role to capability mapping | Partial (real-tenant, R7) |
| A.5.17 | Authentication information | JWT verification; agent one-time tokens stored hashed | Implemented |
| A.5.18 | Access rights | per-route authorization; dual-control for break-glass | Implemented |
| A.8.2 | Privileged access rights | break-glass grant with expiry and dual control | Implemented |
| A.8.5 | Secure authentication | RS256 + JWKS rotation | Partial (R7) |
| A.8.9 | Configuration management | signed policy packs; config snapshots | Implemented |
| A.8.15 | Logging | structured logs; meta-audit; the append-only signed ledger | Implemented |
| A.8.16 | Monitoring activities | SIEM export; drift, lineage, and continuous vendor monitors | Implemented |
| A.8.24 | Use of cryptography | Ed25519, TLS, KEK, optional HSM | Implemented |
| A.8.28 | Secure coding | CI gates; the OSSA ownership verifier in the toolchain; red-teaming | Partial |
| A.5.7 | Threat intelligence | signed threat-feed packs, polled and verified | Implemented |
| A.5.23 | Cloud services security | on-prem and single-tenant deployment model; no external calls without a configured hook | Implemented |
| A.5.30 | ICT readiness for continuity | HA lease, failover drill, backup/restore in the shakedown | Implemented |

## 3. ISO/IEC 42001 (AI management system)

Varman is itself an AIMS control surface, so the same evidence that governs a customer's AI also
evidences the management system.

| 42001 area | Requirement | Varman control | Readiness |
| --- | --- | --- | --- |
| AI risk assessment | identify and assess AI risks | risk register; use-case assessments; conformity records; impact taxonomy | Implemented |
| AI system impact assessment | assess impact on individuals and society | model cards; use-case stage gates; assessment records | Implemented |
| Data for AI systems | provenance and quality of data | lineage monitor; data-boundary and residency controls | Implemented |
| AI system lifecycle | governed development and deployment | model admission scan; signed AI-BOM; rollout and offboarding records | Implemented |
| Third-party and supplier | manage AI supply chain | supply-chain admission; vendor monitoring and review SLAs; AI-BOM | Implemented |
| Monitoring and review | ongoing monitoring of AI systems | drift, groundedness, trajectory, and continuous vendor monitors | Implemented |
| Incident and corrective action | respond to AI incidents | kill-switch; approval escalation; break-glass; the signed ledger as the record | Implemented |
| Transparency | provide information about AI systems | signed AI-BOM; report snapshots per framework; model cards | Implemented |
| MITRE ATLAS alignment | adversarial-threat language | ATLAS enrichment of scan findings on the AI-BOM and console (R4) | Implemented |

## 4. The evidence ledger as the audit asset

Every governance action (a policy change, an admission decision, an approval, a break-glass grant, a
kill) is written as an Ed25519-signed record into an RFC 6962 Merkle log. `acp verify` re-derives the
tree head and checks every signature. For an auditor this replaces sampled screenshots with a complete,
tamper-evident record: the operating evidence for CC7, CC8, A.8.15/16 and the 42001 monitoring and
incident areas is generated as a by-product of running the product, not assembled by hand at audit time.

## 5. What remains for certification (process, not code)

1. Author the policy set (access control, change management, incident response, vendor management,
   business continuity) that references these technical controls.
2. Complete the real-Entra identity cutover (R7) so the authentication criteria move from Partial to
   Implemented against a live tenant.
3. Operate the controls over the observation window and collect evidence (the ledger does most of this).
4. Engage an auditor: SOC 2 Type I then Type II; ISO 27001 ISMS and ISO 42001 AIMS in parallel, per the
   sequence in `docs/enterprise-trust-plan.md`.
