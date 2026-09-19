# P2 operations: scale and resilience

Date: 2026-09-19
Status: deployment guidance for the P2 hardening items that are infrastructure concerns rather than
in-process code. #14 (guard primitive) and #15 (live discovery) shipped as code; #13, #16, #17 below
are operational and are documented here with concrete choices.

## #13 Shared / distributed state (multiple PEP instances)

Each proxy/gateway instance keeps its own in-process state: token/cost budgets (persisted per
instance via --budget-state) and tool-integrity pins. Running several replicas therefore splits
budgets and pins per instance. Options, cheapest first:

- Partition by scope: run one gateway per model-class or per team, so each budget lives in one place.
- Shared store: back the budgets and pins with Redis (or a small Postgres). The TokenBucket state is
  tiny (capacity, tokens, refill, last_ms); key it as `budget:{app}:{resource}` and do a check-and-
  decrement in the store (a Lua script for atomicity). Tool pins become `pin:{server}:{tool}`.
- Sticky routing: hash `app` at the load balancer so a given app always hits the same instance
  (keeps per-instance budgets correct without a shared store).

Recommendation: Redis-backed budgets + pins when running more than one replica; the in-process path
stays the single-instance default.

## #16 HA control plane

acp-server holds the registry, the signed policy store, the evidence ledger, and keys. To remove it
as a single point of failure:

- Ledger: append-only SQLite; replicate with Litestream / LiteFS (streaming WAL to object storage)
  or ship the WAL. Restores are verifiable with `acp verify`. For higher write concurrency, move the
  ledger to Postgres behind the same append/verify API.
- Registry + policy store: small JSON/dir state; put on replicated storage (a shared volume or a
  small replicated DB) so a standby sees the same source of truth. Policy is signed, so a replica
  serving a stale-but-signed policy still fails safe.
- Break-glass grant + keys: the grant file and signing keys on shared, access-controlled storage
  (keys ideally in an HSM/KMS, see below), so a failover node applies the same emergency state.
- Failover: run an active plus a warm standby behind a VIP / load balancer with health checks
  (/healthz, /readyz). The proxies/gateways already hot-reload policy and fail closed, so a brief
  control-plane blip degrades safely rather than opening the gate.

Targets to set: RTO (time to failover) and RPO (max evidence loss) - with per-append ledger
durability plus streaming replication, RPO is near zero.

## #17 Supply chain and disaster recovery

- Reproducible builds: pinned Rust toolchain (rust-toolchain.toml), committed Cargo.lock, and a
  clean-room build; produce an SBOM (cargo-cyclonedx) and scan (cargo-audit / cargo-deny).
- Signed releases: sign the release binaries (cosign / minisign) and publish the digests; the
  evidence ledger already self-signs, and policy + break-glass grants are signed, so the runtime
  chain is covered - this closes the gap for the binaries themselves.
- Key protection: production signing keys (policy, ledger, break-glass, enforcement) via the existing
  acp-hsm (PKCS#11) or a KMS-wrapped seed, never a bare on-disk seed (P0 set 0600 as the floor).
- DR runbook:
  1. Backups: `acp ledger-backup` on a schedule, shipped off-box; snapshot the registry + policy
     store + keys (or keep keys in HSM/KMS with their own recovery).
  2. Restore: bring up acp-server pointing at the restored ledger + stores; run `acp verify` on the
     ledger and confirm `/policy-store` shows the expected signed version.
  3. Re-enrol: proxies/gateways reconnect (mTLS certs from the CA); confirm decisions flow to the
     restored ledger and a `grc-report` reflects the expected controls.
  4. Test the drill regularly; a backup that has never been restored is not a backup.

## Status

- #14 guard primitive: DONE (acp verify-enforcement)
- #15 live discovery: DONE (acp discover --watch)
- #13 shared state, #16 HA, #17 supply-chain/DR: operational, guidance above; implement against the
  chosen store / orchestrator / CI.
