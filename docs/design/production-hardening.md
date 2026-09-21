# Production hardening

Date: 2026-09-19
Status: the P2 items (#13-#17) overlap `docs/design/p2-operations.md`, which is the consolidated operations reference; read that for the current state. Update (2026-09-21): #13 shared state SHIPPED as Postgres via the `acp-pgstate` crate (`--budget-pg`/`--pin-pg`), verified across replicas.
Status: prioritised hardening plan for taking ACP from feature-complete (all 6 phases built and
tested) to production. Grounded in a review of the actual code; P0 = before real traffic, P1 = before
broad rollout, P2 = scale and resilience. On-prem single-org, so no multi-tenant work is implied.

## P0 - before any real traffic  [ALL DONE]

1. Gateway resource protections (the gateway lacks what the MCP proxy transport already has):
   - Upstream timeout: `reqwest::Client::new()` has no timeout; a hung model API pins connections. Add `.timeout(...)` like the proxy (30s).
   - Concurrency cap: no semaphore; unbounded in-flight requests. Add a `Semaphore` + shed with 503, like the proxy.
   - Response streaming: `resp.bytes().await` buffers the whole response; model APIs stream by default (SSE) and responses can be large. Stream chunk-by-chunk like the proxy's `text/event-stream` path.
   - Request body limit: no cap; a huge body is a DoS. Add `DefaultBodyLimit`.
   (These four are fixed in the same-day hardening commit; see the gateway.)
2. [DONE] Rate-limit / budget durability: the gateway's token budgets live in an in-memory `HashMap`, so a
   restart resets every budget (a caller can bypass a daily cap by forcing a restart) and budgets are
   not shared across instances. Persist counters (embedded store) or use a shared store; at minimum
   document the restart-resets-budgets caveat.
3. [DONE] Secrets off the command line: `--upstream-key` (model key), `--break-glass-key`, and seeds are
   passed as argv and show in `ps`. Accept them from a file or environment variable instead.
4. [DONE] Dev auth must never reach production: `--dev-auth` issues unauthenticated role tokens. Gate it
   behind an explicit `ACP_ALLOW_DEV_AUTH=1` and refuse to start with `--dev-auth` otherwise; the
   `/auth/dev-token` route must not exist in a real deployment.
5. [PARTIAL] Signing-key protection: key seeds now written 0600 (unix); HSM/KMS-wrapping via acp-hsm remains for the strongest posture. policy-store, ledger, break-glass, and enforcement keys sit on disk as raw
   seeds. Wire the existing `acp-hsm` (PKCS#11) path for these, or at least 0600 + a KMS-wrapped seed;
   never world-readable.
6. Console real sign-in [DONE via IAP pattern]: the console now FORWARDS the caller's real bearer
   token to acp-server (from ctx.request headers), so production deploys an identity-aware proxy
   (oauth2-proxy / Entra IAP) in front of the console that performs the OIDC login and injects the
   user's token; the console passes it through and acp-server verifies it with the RBAC we built. The
   dev-token stand-in is used only when no such header is present (local use, and dev-auth is now
   guarded). A built-in auth-code flow inside the console remains an optional alternative to the IAP.

## P1 - before broad rollout  [DONE]

7. [DONE - server enforcement + toolchain] mTLS between components: proxy/gateway to acp-server and to upstreams should use the existing
   `acp-mtls` (client-cert-required), not plain HTTP, so the control channel is authenticated.
8. [DONE - backup+verify] Ledger durability and retention: define backup, off-box replication, and a retention/rotation
   policy for the evidence ledger; verify recovery across a restart (the store is per-append durable,
   but backup/DR is unproven at scale).
9. [DONE] JWKS robustness: handle clock skew (small leeway on exp/nbf), a `kid` miss triggering an immediate
   refresh (not only the hourly timer), and a JWKS-fetch failure at startup failing closed for
   RBAC-required deployments rather than silently disabling RBAC.
10. [DONE] Observability: health/readiness endpoints on the gateway, Prometheus/OTel metrics (decisions by
    verdict, latency, upstream errors, budget denials, kill-switch state), and structured logs. Today
    the gateway logs decisions to stderr only.
11. [DONE] Fail-closed audit: if the ledger write fails on the gateway, decide the policy (the proxy already
    fails closed on evidence-write failure; the gateway currently forwards without recording on a
    ledger error). Make the gateway match the proxy's record-before-forward guarantee.
12. [DONE - harness] Load and soak tests: the suites are unit/integration; add throughput and endurance tests for the
    proxy and gateway (concurrency, large bodies, streaming, budget churn, key rotation).

## P2 - scale and resilience  [14,15 code done; 13,16,17 documented in p2-operations.md]

13. Shared/distributed rate-limit and pin state for multiple gateway/proxy instances (today each
    instance is independent).
14. Enforcement-attestation rollout: deploy the attestation guard in front of tool servers and the
    egress policy in front of models, so unavoidability is real, not just available.
15. Discovery telemetry: wire live egress ingestion (network sensor / eBPF / proxy logs) feeding the
    shadow-AI classifier continuously, rather than a manual `acp discover` over a file.
16. HA control plane: run acp-server with a standby and a shared/replicated store for the registry and
    policy store; define failover.
17. Supply-chain and DR: reproducible builds, signed release artifacts (the ledger signs itself;
    the binaries should too), and a documented disaster-recovery runbook.

## Not needed (recorded so it is not re-raised)

- Multi-tenancy: dropped. ACP is on-prem single-org; a single shared control plane is correct.
