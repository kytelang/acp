# Production readiness

Date: 2026-09-22
Status: living checklist. This is an honest, code-grounded assessment of what stands between the
current reference implementation and an unattended production rollout carrying regulated data. It is
written from a read of every crate and module, not from memory. Read it with `docs/features.md` (the
tagged capability map) and `docs/evaluation-guide.md` (section 7, maturity).

Verdict: Varman is fit for a supervised design-partner pilot, not for unattended production with
regulated data. The gaps cluster in three areas: evidence-at-rest confidentiality, control-plane
availability and durability, and operability (observability, secrets, Kubernetes packaging). Most
gaps have the implementing code already written but not wired, which lowers the cost to close them.

## What is already sound (so the gaps below are credible)

- Enforcement core is real and fail-closed: the Cedar PDP (`acp-policy`), the proxy pipeline with
  record-before-forward evidence (`acp-proxy`), gateway credential brokering (`acp-gateway`), the
  guard attestation sidecar (`acp-guard`) and the MITM intercept proxy (`acp-intercept`).
- Evidence integrity is sound: RFC 6962 Merkle log, Ed25519 signed tree heads, public-key-only
  verification that survives removal of the append-only triggers, WAL enabled on the SQLite store.
- Resilience primitives are wired: concurrency caps with 503 and Retry-After load-shed on both
  data-plane binaries, upstream timeouts, graceful drain on SIGTERM.
- Code hygiene: zero `unsafe`, zero `TODO`/`FIXME`, zero production panics (the only `panic!` sites are
  inside `#[cfg(test)]`), and the workspace test suite passes.

## P0: blockers before any production with real data

- [x] P0-1 Encryption of evidence at rest. DONE (2026-09-22): `acp-encrypt` is wired into the ledger.
      When `ACP_LEDGER_KEK` (64 hex chars) is set, argument blobs are AES-256-GCM envelopes bound to
      `args_hash` as AAD; the KEK never touches the database; verification, erasure and plaintext
      backward-compatibility are preserved; a wrong or absent KEK reveals nothing. Verified by unit
      tests (`crates/acp-ledger/tests/encryption_tests.rs`) and end to end through the proxy (no
      plaintext on disk, ledger still verifies). Remaining hardening: source the KEK from a KMS or
      secret manager instead of an environment variable (folds into P0-2 key custody).
- [ ] P0-2 Hardware key custody. The signing key is a 0600 seed file; anyone who reads it can forge
      evidence and tree heads. `acp-hsm` (PKCS#11) is implemented but orphaned. Fix: wire
      `acp-hsm` (or `keymgr` rotation) behind the `Signer` seam for ledger, break-glass and policy
      signing.
- [ ] P0-3 Evidence-ledger durability. The ledger is a single SQLite file per node and is not
      replicated; it is the crown jewel and a single point of loss. The helm values claim
      "append-only and replicated," which is not true today. Fix: add replication or streaming
      offsite backup (or state the RPO honestly and wire scheduled `ledger-backup`), and correct the
      helm claim.
- [ ] P0-4 Control-plane single point of failure. `acp-server` is a single instance whose liveness
      and spike state is in-memory (`Mutex` on `AppState`), lost on restart; HA is unwired (`ha.rs`
      has no caller). Fix: wire the `ha.rs` leader lease, move shared state to `acp-pgstate`, and run
      active plus standby.

## P1: serious, required for unattended production

- [ ] P1-1 Structured logging and log levels. There is no `tracing` or `RUST_LOG`; there are about 74
      raw `println!`/`eprintln!` calls across server, proxy and gateway. No JSON logs, no correlation
      ids, no verbosity control. The OTLP span builder (`otelspan.rs`) exists but `build_span` is
      never called by any binary, so distributed tracing is unwired (only decision events reach the
      SIEM sinks). Fix: adopt `tracing` with a JSON subscriber and levels; wire request-scoped spans.
- [ ] P1-2 Secrets management. `deploy/docker-compose.yml` and `deploy/helm/acp/values.yaml` carry a
      plaintext Postgres password; model API keys are passed by flag or environment. Fix: use
      Kubernetes Secrets or Vault; never bake a DSN password into values.
- [ ] P1-3 Helm chart completeness. Only `templates/gateway.yaml` exists. There is no control-plane
      Deployment, Service, Ingress, Secret, probe, resource limit, HPA, PodDisruptionBudget or
      NetworkPolicy. Fix: complete the chart so it installs a real cluster deployment.
- [ ] P1-4 Default-deny posture. The default policy verdict is `allow`, so unmatched actions are
      permitted; the `posture.rs` default-deny maturity path is unwired and the CLI scaffolds
      `default: allow`. Fix: wire the staged path to default-deny and change the scaffold guidance.
- [ ] P1-5 Protections on by default. Trajectory, data-boundary and the content firewall are opt-in
      proxy and gateway flags; the SSRF egress allowlist (`egress.rs`) is implemented but not wired
      into any outbound-dial path (only the canary uses it). Fix: make the key protections on by
      default and wire the allowlist into the dial path.
- [ ] P1-6 Gateway test depth. The highest-traffic binary has only two unit tests on the pure
      `decide()`; the axum service (budgets, streaming, break-glass watch, content firewall) has no
      integration or load tests. Fix: add integration and load tests for the gateway path.
- [ ] P1-7 GRC evidence reconciliation. `assess`, `conformity`, `risk`, `modelcard`, `usecase` and
      `aibom` are Ed25519-signed operator documents whose linked-decision references are free-text and
      are not checked against the ledger. Only `grc-report`, `siem` and `warehouse` are truly
      ledger-backed. Fix: validate linked-decision ids against real ledger records at sign time.
- [x] P1-8 DLP classifier quality. DONE (2026-09-22): replaced the length-only secret rule with a
      character-diversity plus Shannon-entropy gate (keeping the high-precision keyword rule), and made
      numeric PII (SSN, phone) reject matches embedded in a letter-bearing token so UUIDs, hashes and
      identifiers no longer false-positive. Added unit tests and a labelled eval gate
      (`classify.rs` tests): secret precision, recall and FPR all pass; the exact former false
      positives (git SHA, UUID, long path, long word) now classify as none.

## P2: hardening

- [ ] P2-1 Upstream retry and backoff (currently a single attempt on gateway and proxy).
- [ ] P2-2 Wire or clearly shelve the built-but-unwired governance modules (SCIM, dual-control, ITSM
      tickets, webhook signing, rollout, fleet, drift, metering, offboarding, mcpdrift, hostshim,
      timeline, adapter, agility, keymgr rotation, external anchor). See `docs/features.md`.
- [ ] P2-3 Multi-tenancy in the control plane (`acp-pgstore` enforces Postgres RLS, but `acp-server`
      is single-tenant with no tenant plumbing).
- [ ] P2-4 Third-party assurance: SOC 2, penetration test, independent cryptographic audit. See
      `docs/commercial/pre-launch-requirements.md`.
- [ ] P2-5 Make the console's `acp-server` URL configurable (it is currently hardcoded).
- [ ] P2-6 Rate limiting on the control-plane API itself (only the data plane sheds load today).

## How to read this against the docs

- `docs/features.md` says which capabilities are enforced, which are built-but-unwired primitives, and
  which crypto pieces are implemented but not in the path. This document says which of those gaps block
  production and in what order to close them.
- `docs/evaluation-guide.md` section 7 states the maturity honestly for a buyer.
