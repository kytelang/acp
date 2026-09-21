# Audit-readiness pack (SOC 2 / ISO 27001 enabling artifact)

The SOC 2 Type II report and the ISO 27001 certificate are events only an external auditor issues.
This pack is what makes that engagement a walkthrough rather than a project: it maps ACP's controls
to the SOC 2 Trust Services Criteria and ISO 27001 Annex A, and points each one at the evidence
already in the repo. When the auditor engages, everything they check is here.

## How to use this

For each control, the "Evidence" column names a runnable artifact or a source file. Everything is
re-derivable and local: no dashboard to trust, no screenshots. The auditor can clone the repo, run
the named script or test, and see the control operate.

## SOC 2 Trust Services Criteria (Security / Availability / Confidentiality)

| TSC | Control in ACP | Evidence |
| --- | --- | --- |
| CC6.1 logical access | OIDC (Entra) auth + RBAC; mTLS proxy<->server | `acp-auth`, `acp-mtls` tests |
| CC6.6 credentials in a vault | HSM-held signing key (PKCS#11) | `acp-hsm` (SoftHSM-verified) |
| CC7.1 detection of events | tamper-evident Merkle log; liveness + spike alerts | `acp verify`; B1/B3 server endpoints |
| CC7.2 monitoring | governance report + `/metrics` + `/alerts` + `/liveness` | acp-server; `acp-console` |
| CC7.3 evaluation of events | break-glass with meta-audit; drift monitor | `breakglass`, `drift` |
| CC7.4 incident response | break-glass drill; runbook (shakedown) | `scripts/shakedown.sh` |
| CC8.1 change management | signed policy provenance; meta-audit of policy/key/RBAC changes | `policyprov`, `metaaudit` |
| A1.2 backup / recovery | tested backup+restore drill | `scripts/shakedown.sh`; ledger DR test |
| C1.1 / C1.2 confidentiality | args stored as hashes; redaction; encryption at rest (BYOK) is a built module, integration into the ledger and stores pending | `redact`; `acp-encrypt` (module built, not yet wired) |
| CC7.1 (integrity) | append-only DB trigger + Merkle tamper detection | `scripts/pentest.sh` (two layers) |

## ISO 27001 Annex A (2022)

| Annex A control | ACP mechanism | Evidence |
| --- | --- | --- |
| A.5.15 access control | RBAC over edit-policy/approve/export/see-args | `acp-auth` |
| A.8.5 secure authentication | OIDC + mTLS | `acp-auth`, `acp-mtls` |
| A.8.12 data leakage prevention | redaction; args-hash-only evidence; no-args support | `redact`; `acp diagnose` |
| A.8.13 information backup | backup + tested restore | `scripts/shakedown.sh` |
| A.8.15 logging | tamper-evident, independently verifiable log | `acp verify` |
| A.8.16 monitoring | liveness / spike / drift | server endpoints; `drift` |
| A.8.24 use of cryptography | Ed25519 signing, crypto-agility; AES-256-GCM at rest available in acp-encrypt (integration pending) | `sign`, `agility`; `acp-encrypt` (built, not yet wired) |
| A.8.28 secure coding | clippy -D warnings, fuzz, model check, review | CI; `docs/ops/secure-sdlc.md` |
| A.5.7 threat intelligence / A.5.24 incident mgmt | pen-test harness + break-glass | `scripts/pentest.sh` |

## Evidence index (what to run)

- `bash scripts/pentest.sh` : policy enforced, fail-closed, two-layer tamper detection, no args leak.
- `bash scripts/shakedown.sh` : 500-decision soak, verify, backup/restore, break-glass drill.
- `cargo test --workspace` : the full suite, including trust-core invariants and the approval model check.
- `acp verify <ledger>` / `acp verify-pack <pack>` : independent evidence verification.
- `bash scripts/sbom.sh` : the signed CycloneDX SBOM.
- `docs/compliance/control-mappings.md` : the AI-Act / ISO 42001 / NIST RMF mapping.

## What is still the auditor's to do

Issue the opinion. Everything they need to form it, the controls, the evidence, and the ability to
re-run each one, is in this repo. The gaps that remain are operational: a period of operating
history (Type II observes controls over time) and the auditor's independent testing. Neither is
something the codebase produces; both are unblocked by this pack.
