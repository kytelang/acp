# Reference deployment

A starting point for running ACP as a small, resilient deployment. It is not production-tuned; it is the artifact a design partner drops into, and the base for a failover drill.

## What it shows

- A control plane (registry, signed policy store, tamper-evident evidence ledger, approvals).
- Two LLM gateway replicas that share one rate-limit budget through Postgres, so a replica failure keeps limits correct (verified in code; this makes it real infrastructure).
- Health and readiness endpoints for load-balancer failover.

## Docker Compose (quick start)

```sh
cd deploy
docker compose up -d --build
# gateways on :8799 (A) and :8798 (B); control plane API on :8787; web console on :8080
bash failover-drill.sh   # proves the shared budget survives a replica failure
```

## systemd (a bare host)

Copy the binaries to /usr/local/bin, put policy.yaml and gateway.env under /etc/acp, then:

```sh
cp systemd/*.service /etc/systemd/system/
systemctl enable --now acp-server acp-gateway
# The console (acp-console.service) and the per-tool-server guard (acp-guard.service) ship too.
# The console needs the Kyte-built console files under /opt/acp/console; the guard is a per-upstream
# sidecar, so set /etc/acp/guard.env (ACP_GUARD_UPSTREAM, ACP_GUARD_PUBKEY) before enabling it.
```

## Helm (Kubernetes)

```sh
helm install acp ./helm/acp --set postgres.dsn="host=<pg> user=acp password=<pw> dbname=acp"
# Enable the web console with --set console.enabled=true (see the limitation below).
```

## Production notes (what "in anger" adds on top)

- Postgres: use a managed, replicated instance; the DSN is the only shared-state dependency.
- Evidence ledger: replicate with Litestream or LiteFS (streaming WAL to object storage), or move it to Postgres behind the same append and verify API. Restores are verifiable with `acp verify`.
- Control plane: run active plus warm standby behind a VIP with health checks; policy is signed, so a standby serving a stale-but-signed policy still fails safe.
- Keys and break-glass grants: on access-controlled shared storage, keys ideally in an HSM or KMS (see acp-hsm).
- Set RTO and RPO targets: with per-append ledger durability plus streaming replication, RPO is near zero.

## Web console (compose and Helm)

The console is a Kyte app, not one of the Rust binaries, so it is a SEPARATE image (it is not built by
`deploy/Dockerfile`). Build it with the Kyte toolchain and publish it as `acp-console:local` (compose)
or set `console.image` (Helm) before enabling it.

Known limitation: the console binary hardcodes its control-plane upstream as `http://127.0.0.1:8787`
(`acp-console/src/main.ky`) and cannot yet be pointed at a service DNS name without a source change.
Compose works around this by sharing the control-plane's network namespace so `127.0.0.1:8787`
resolves; the console's `:8080` is published through the control-plane service. In Helm the console is a
standalone Deployment, so `console.controlPlaneUrl` is injected only as documentation of the intended
target: to get a working link today, run the console as a sidecar in the control-plane pod. Making the
upstream configurable is the proper fix and is out of scope for the deploy assets.
