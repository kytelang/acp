# Security questionnaire baseline (H1.8)

Enterprise procurement sends a CAIQ or SIG questionnaire. This is the standing set of answers, kept
in sync with what the product actually does, so a questionnaire is a lookup rather than a research
project. It is also the index of what the trust portal hosts.

## Trust portal contents

- This document and the control-framework mappings (`docs/compliance/control-mappings.md`)
- The data-processing agreement and the sub-processor list (`docs/compliance/dpa-and-subprocessors.md`)
- The SOC 2 report and ISO 27001 certificate, once issued (the `[e]` items)
- The penetration-test summary, once performed
- The deprecation and support policy (`docs/ops/deprecation-policy.md`)

## Representative answers

- Identity and access: SSO/OIDC via the customer's IdP (Entra ID model), RBAC over edit-policy,
  approve, export, and see-args; approval authority synced from the IdP over SCIM and revoked on
  deprovision.
- Cryptography: evidence signed with Ed25519 behind a KMS/HSM seam; key rotation preserves
  verification of historical records via key ids; transparency anchoring provides an external time
  reference.
- Data protection: arguments stored as hashes, raw payloads separated and redactable, encryption in
  transit, encryption at rest with customer-managed keys on the roadmap, right-to-erasure supported
  without breaking the audit log.
- Logging and monitoring: tamper-evident Merkle evidence log with independent verification;
  liveness gap detection and fail-open spike alerting; governance report with posture and coverage.
- Resilience: durable spool before forward (no lost decisions), backup and tested restore drill,
  graceful drain on shutdown.
- Supply chain: dependency scanning in CI, SBOM published, signed releases (in progress), a
  documented contingency plan for young dependencies.
- Software development: mandatory review, fuzz and property tests for the trust core, an exhaustive
  model check for the single-use-approval invariant.

## Known gaps stated honestly

Mutual TLS between internal services is implemented (the acp-mtls crate, client certificate required).
Encryption at rest with customer-managed keys is a built module (acp-encrypt) whose integration into
the ledger and stores is pending, and the external attestations (SOC 2, ISO 27001, penetration test)
are on the roadmap and are not claimed as complete. A questionnaire answer that is
not yet true is marked "in progress" with the target, never asserted.
