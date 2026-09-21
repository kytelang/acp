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
# gateways on :8799 (A) and :8798 (B); control plane on :8080
bash failover-drill.sh   # proves the shared budget survives a replica failure
```

## systemd (a bare host)

Copy the binaries to /usr/local/bin, put policy.yaml and gateway.env under /etc/acp, then:

```sh
cp systemd/*.service /etc/systemd/system/
systemctl enable --now acp-server acp-gateway
```

## Helm (Kubernetes)

```sh
helm install acp ./helm/acp --set postgres.dsn="host=<pg> user=acp password=<pw> dbname=acp"
```

## Production notes (what "in anger" adds on top)

- Postgres: use a managed, replicated instance; the DSN is the only shared-state dependency.
- Evidence ledger: replicate with Litestream or LiteFS (streaming WAL to object storage), or move it to Postgres behind the same append and verify API. Restores are verifiable with `acp verify`.
- Control plane: run active plus warm standby behind a VIP with health checks; policy is signed, so a standby serving a stale-but-signed policy still fails safe.
- Keys and break-glass grants: on access-controlled shared storage, keys ideally in an HSM or KMS (see acp-hsm).
- Set RTO and RPO targets: with per-append ledger durability plus streaming replication, RPO is near zero.
