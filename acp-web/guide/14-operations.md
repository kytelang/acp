# 14. Operations and deployment

This chapter covers running the stack: the control plane, the web console, shared state, logging,
deployment with helm and compose, and an honest read of production readiness.

## The control plane

`acp-server` is the control-plane HTTP service: the approvals inbox, signed policy deploy,
break-glass, health, and the read-only evidence API the console renders.

```sh
acp-server \
  --addr 0.0.0.0:8787 \
  --ledger evidence.db \
  --approvals approvals.db \
  --store sqlite:///var/lib/acp/control.db?mode=rwc \
  --cp-key /var/lib/acp/cp.key \
  --policy-store /etc/acp/policy \
  --break-glass-file /etc/acp/grant.signed
```

It serves an approval inbox at `/`, `GET /healthz` and `/readyz`, `GET /verify` (verifies the
ledger), `GET /report` (verdict and outcome tallies plus coverage), `GET /metrics` (Prometheus),
heartbeat and liveness endpoints, `GET /timeline` and `/evidence/recent`, the apps and agents
listings, the policy store with a signed `POST /policy-store/deploy` (RBAC-gated on `EditPolicy`),
break-glass engage and clear (gated on `BreakGlass`), and the registration APIs that write to the
control-plane database (`POST /apps`, `/agents`, `/endpoints/register`, `/grc`). It drains gracefully
on `SIGTERM`. The control-plane database is chosen by `--store` connection URL (sqlite, Postgres or
MySQL); without it the registration APIs return "no --store configured". `--cp-key` is the key the
control plane signs endpoint dispositions and GRC records with. See [chapter 16](16-setup.md).

**Auth.** With no auth flags it runs RBAC-off for local use. Enable real identity with
`--entra-tenant`/`--entra-audience`, or `--oidc-jwks`/`--oidc-issuer`/`--oidc-audience`, or
`--dev-auth` (a mock issuer, itself gated behind an environment flag). If auth is requested and the
JWKS fails to load, the server refuses to start.

**Honest limit.** The control plane is single-tenant today, and its liveness and spike-detector state
is in-memory and resets on restart. High availability (a leader lease plus shared state) is the last
open blocker to running the control plane in production.

## The web console

`acp-console` is the management console over the control plane's verifiable API. It is where you run
day-to-day governance: it both **reads** figures that are all served by `acp-server` and re-derivable
from the signed evidence (so no trust lives in the UI), and **performs management** by POSTing to the
control-plane API, which is where signing and every policy decision actually happen. The console holds
no signing key.

Management actions are popup forms: **Register a team / application**, **Register an agent** (which
returns a one-time token, shown once), **Register an AI endpoint** (govern, block or accept-risk, with
the provider classified automatically), **Create a governance record** (with a Kind selector), a
tabbed **Policy** view with a syntax-highlighted editor and `.yaml` upload plus signed deploy, and
**Engage or clear the kill-switch** with live status. It also gives a live governance overview with a
verdict-distribution bar, the approvals inbox, teams and agents listings, an evidence view, an
integrity view (ledger verify, proxy liveness, spike alerts, self-governance log), and a printable
governance report. The console has a light and dark theme.

```sh
# start the control plane (with a store so registration persists), then the console
acp-server --ledger evidence.db --addr 127.0.0.1:8787 --store sqlite://control.db?mode=rwc --cp-key cp.key
cd acp-console && kyte build && ./build/debug/bin/acp-console   # http://127.0.0.1:8080
```

## Shared state (high availability)

For more than one gateway or proxy replica, back the shared state with Postgres so replicas share one
budget and one set of tool-integrity pins, and a failover keeps limits correct.

```sh
acp-gateway ... --budget-pg "host=pg user=acp password=... dbname=acp"
acp-proxy   ... --pin-pg    "host=pg user=acp password=... dbname=acp"
```

Token budgets refill under a row lock, and tenant isolation in the multi-tenant store is enforced by
Postgres row-level security. **Important:** connect as a **non-superuser** role. Postgres superusers
(and roles with BYPASSRLS) ignore RLS, so the store refuses to initialise against such a role rather
than silently break isolation.

## Logging

All services use structured logging. Set the level with `ACP_LOG` (or `RUST_LOG`), and switch to
one-JSON-object-per-line for a log pipeline with `ACP_LOG_FORMAT=json`.

```sh
ACP_LOG=info ACP_LOG_FORMAT=json acp-gateway ...
ACP_LOG=warn acp-proxy stdio ...
```

## Deployment

The `deploy/` directory carries a Dockerfile, a docker-compose reference deployment (Postgres,
control plane, two gateway replicas that share a budget), a failover drill, systemd units, and a helm
chart.

**docker-compose** reads the Postgres password from `deploy/.env` (`ACP_PG_PASSWORD`) and fails
closed if it is unset. Copy `deploy/.env.example` and fill it in; never commit the real file.

**helm** (`deploy/helm/acp`) renders a control-plane StatefulSet with its own persistent volume plus
a Service, a gateway Deployment with resource limits and probes plus a Service, and gated Ingress,
HorizontalPodAutoscaler, PodDisruptionBudget and NetworkPolicy. Optional blocks turn on evidence
encryption at rest (`ledgerKek`, mounted from a Secret), HSM signing (`hsm`, slot and pin from a
Secret), and a verified backup sidecar (`controlPlane.backup`). The DSN comes from a Kubernetes
Secret, never from values.

```sh
helm install acp deploy/helm/acp \
  --set ingress.enabled=true \
  --set gateway.autoscaling.enabled=true \
  --set ledgerKek.enabled=true \
  --set controlPlane.backup.enabled=true
```

## Production readiness, honestly

Varman is a complete, tested reference implementation with a large passing test suite and a
ten-of-ten end-to-end acceptance for the core vertical. It is ready for a proof of concept and a
design-partner pilot, not an unattended production rollout without hardening. In place today:
encryption at rest, HSM signing, structured logging, secrets kept out of the deployment files, the
full helm chart, an entropy-gated DLP classifier, the staged default-deny path, and a fail-closed
guard against a mis-scoped database role. Remaining before an unattended rollout: control-plane high
availability, turning the sequence and firewall protections on by default, load testing the gateway,
and cross-checking the GRC documents against the ledger.
