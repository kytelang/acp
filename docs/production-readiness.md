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
- [~] P0-2 Hardware key custody. PARTIAL (2026-09-22). Done and verified: the P0-1 KEK can now be
      sourced from a mounted secret FILE via `ACP_LEDGER_KEK_FILE` (not just raw env), and the helm
      chart mounts it from a Kubernetes Secret (`ledgerKek`), so the at-rest key comes from a secret
      store, not the pod spec. NOT done: wiring the `acp-hsm` PKCS#11 signer behind the ledger's
      `Signer` seam for the SIGNING key. The signer code exists, but it could not be verified here:
      SoftHSM 2.7 segfaults on the Ed25519 path (macOS), and wiring it would also pull the native
      `cryptoki` dependency into every service. It needs validation against a real HSM before being
      enabled; do not claim HSM signing custody until that passes. The signing key remains a 0600
      seed (which can now also be a mounted secret file).
- [~] P0-3 Evidence-ledger durability. PARTIAL (2026-09-22): corrected the false "append-only and
      replicated" claim in the helm values and documented durability honestly (append-only, locally
      durable via SQLite WAL, NOT replicated by the chart; back it up and set an RPO). The control
      plane is now a StatefulSet with its own persistent volume. REMAINING: wire scheduled backup or
      streaming replication in-cluster (`acp-cli ledger-backup` exists as the backup primitive).
- [ ] P0-4 Control-plane single point of failure. `acp-server` is a single instance whose liveness
      and spike state is in-memory (`Mutex` on `AppState`), lost on restart; HA is unwired (`ha.rs`
      has no caller). Fix: wire the `ha.rs` leader lease, move shared state to `acp-pgstate`, and run
      active plus standby.

## P1: serious, required for unattended production

- [x] P1-1 Structured logging and log levels. DONE (2026-09-22): added the `acp-obs` crate (one
      `init` call sets a `tracing` subscriber with an env filter and an optional JSON formatter) and
      wired it into all five services (server, gateway, proxy, guard, intercept). Every operational
      `eprintln!` is now a leveled `tracing` event; the stdio proxy's protocol output on stdout is
      untouched. Configure with `ACP_LOG`/`RUST_LOG` (levels) and `ACP_LOG_FORMAT=json`. Verified:
      leveled compact and JSON output, env-filter suppression, and the proxy's JSON-RPC stdout stays
      clean with structured logs on stderr; full workspace suite green. REMAINING (enhancement): wire
      request-scoped spans and the `otelspan` OTLP exporter for distributed tracing.
- [x] P1-2 Secrets management. DONE (2026-09-22): docker-compose reads the Postgres password from a
      required env var (`ACP_PG_PASSWORD`, via `deploy/.env`, gitignored) and fails closed if unset;
      the helm chart takes the Postgres DSN from a Kubernetes Secret (`postgres.dsnSecret`) injected
      as an env var and expanded into the flag at runtime, so no password appears in values or the pod
      spec. Verified: `docker compose config` passes with the env set and refuses without it; the
      rendered chart shows the DSN only via `secretKeyRef`.
- [x] P1-3 Helm chart completeness. DONE (2026-09-22): the chart now renders a control-plane
      StatefulSet with a persistent volume plus Service, a gateway Deployment with resource requests
      and limits and probes plus Service, and gated Ingress, HorizontalPodAutoscaler,
      PodDisruptionBudget and NetworkPolicy, with a shared labels helper. Verified with `helm lint
      --strict` (clean) and `helm template` (all resources render, default and with the gated
      features enabled).
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
