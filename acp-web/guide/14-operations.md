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

Management actions are popup forms and inline controls: **Register a team / application**, **Register an
agent** (which returns a one-time token, shown once) with a per-agent **Deactivate** action (`POST
/agents/:id/deactivate`, which revokes the agent), **Register an AI endpoint** (govern, block or
accept-risk, with the provider classified automatically), **Create a governance record** (with a Kind
selector) with per-record **Review / Approve / Close** status controls (`POST /grc/:id/status`, re-signed
server-side), a tabbed **Policy** view with a syntax-highlighted editor and `.yaml` upload plus signed
deploy, and **Engage or clear the kill-switch** with live status. It also gives a live governance overview
with a verdict-distribution bar, the approvals inbox, teams and agents listings, an evidence view (with a
**Fleet evidence** panel over the central `ingested_evidence` store, each row badged verified or
unverified), an integrity view (ledger verify, proxy **Liveness**, spike **Alerts**, a **Violations**
feed, self-governance log), and a printable governance report. The console has a light and dark theme.

The console reads its control-plane URL from `ACP_CONTROL_PLANE_URL` (default `http://127.0.0.1:8787`),
so a compose or helm deployment can point it at the control-plane Service without a rebuild.

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

All services use structured logging, and **all of them write logs to STDERR**. This is deliberate: the
`acp-proxy` stdio transport carries the JSON-RPC protocol on STDOUT, so keeping logs off STDOUT means
structured logging never corrupts the frame stream. Set the level with `ACP_LOG` (or `RUST_LOG`), and
switch to one-JSON-object-per-line for a log pipeline with `ACP_LOG_FORMAT=json`.

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

## Setting up Postgres or MySQL

Two different things can move off SQLite, and they take different DSNs. Do not confuse them.

- **The control-plane store** (identity, AI endpoints, GRC records) is chosen with `acp-server --store`
  (or the `ACP_STORE` value the installer wires into the unit's `ExecStart`). It accepts a
  `sqlite://`, `postgres://` or `mysql://` URL. The same server code runs against any of them; schema
  migrations run automatically on connect.
- **The shared runtime state** (gateway token budgets, proxy tool-integrity pins) uses a
  key-value-style connection string: `acp-gateway --budget-pg` and `acp-proxy --pin-pg`. These are
  Postgres-only and enforce tenant isolation with row-level security.

### Create the database and a non-superuser role

For both, connect as an ordinary application role, never a superuser. This matters most for the shared
state: Postgres superusers (and roles with `BYPASSRLS`) ignore row-level security, so the store
**refuses to initialise** against such a role rather than silently break isolation.

```sql
-- Postgres
CREATE DATABASE acp;
CREATE ROLE acp_app LOGIN PASSWORD 'change-me';   -- NOT a superuser, no BYPASSRLS
GRANT CONNECT ON DATABASE acp TO acp_app;
-- after connecting to the acp database:
GRANT USAGE, CREATE ON SCHEMA public TO acp_app;  -- the app creates its own tables on first connect
```

```sql
-- MySQL (control-plane store only; shared state is Postgres-only)
CREATE DATABASE acp CHARACTER SET utf8mb4;
CREATE USER 'acp_app'@'%' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON acp.* TO 'acp_app'@'%';
```

### Point the services at it

```sh
# control-plane store
acp-server --store 'postgres://acp_app:change-me@db/acp' ...
# or MySQL:
acp-server --store 'mysql://acp_app:change-me@db/acp' ...

# shared runtime state (Postgres only), for more than one replica
acp-gateway --budget-pg 'host=db user=acp_app password=change-me dbname=acp' ...
acp-proxy   --pin-pg    'host=db user=acp_app password=change-me dbname=acp' ...
```

The application creates and migrates its own tables on first connect, so the role needs table-creation
rights in its schema but nothing more. If the store cannot initialise (a mis-scoped role, an
unreachable host), the service fails closed rather than starting without persistence.

## Monitoring and alerting

The control plane exposes the signals an operator watches, and the enforcement points feed some of them
by reporting to the control plane. There are three families: scrape metrics, the dead-man's-switch, and
the spike detector plus violation feed.

### What to scrape

The control plane, the gateway and the guard each serve a Prometheus `GET /metrics` endpoint. Scrape
these for request rates, verdict counts and latency, and build your dashboards and alerts on them the
usual way. For distributed tracing, the proxy can stream OTLP spans to an OpenTelemetry collector with
`--otel <endpoint>`; this is a live trace path, separate from the offline `acp siem` projection.

### The liveness dead-man's-switch

A PEP that should be governing traffic but has gone silent is a governance failure, so the control plane
watches for it. A PEP started with `--report-url <control-plane>` posts a heartbeat every ten seconds
to `POST /heartbeat/:proxy`. The control plane reports any proxy that has not been heard from inside the
window (thirty seconds) at `GET /liveness`:

```sh
curl -s http://<host>:8787/liveness    # {"window_ms":30000,"gaps":[...],"healthy":true|false}
```

**Alert on `healthy: false`**: a gap means an enrolled proxy was killed or silenced. The console
integrity view renders the same feed. Note the liveness state is in-memory and resets when the control
plane restarts.

### The spike detector and the violation feed

Each PEP reports a compact, redacted event on a non-allow decision (deny, step-up, fail-open) to
`POST /event/:kind`. Two things consume it:

- **`GET /alerts`** trips when more than ten events of one kind arrive within a minute, so a sudden
  surge of denies or fail-opens pages you:

  ```sh
  curl -s http://<host>:8787/alerts   # {"tripped":["deny",...],"healthy":true|false}
  ```

  **Alert on `healthy: false`.**

- **`GET /events/recent`** is the newest-first violation feed (a bounded ring) the console **Violations**
  panel renders, so an operator can see the actual deny / step-up / fail-open stream from the fleet.

### The central fleet-evidence store

Beyond the compact non-allow events above, a PEP started with `--evidence-url <control-plane>` pushes
**every** decision record (allow and deny) to `POST /evidence/ingest`. The control plane signs each
record with its `cp-key` and keeps it in a central `ingested_evidence` store, deduped by decision id.

- **`GET /evidence/ingested`** returns the newest records, re-verifying each against its embedded public
  key, which the console **Fleet evidence** panel renders with a verified or unverified badge.

This central store is a convenience mirror for fleet-wide triage; it is **not** a replacement for each
PEP's own tamper-evident Merkle ledger, which stays the authoritative, independently verifiable record
(see [chapter 9](09-evidence.md)).

### Authenticating the reporting routes

The `POST /heartbeat/:proxy`, `POST /event/:kind` and `POST /evidence/ingest` routes are the ingestion
side of this. Set a shared token so only enrolled PEPs can report: give the control plane `--report-token`
(or `ACP_REPORT_TOKEN`) and each PEP `--report-token` with the same value (alongside its `--report-url` or
`--evidence-url`). When a token is set the routes are fail-closed; with no token they are open, which is
for local development only.

### Honest scope

Every PEP can now report: the proxy, the gateway, the interceptor and the guard each post heartbeats and
non-allow events when given `--report-url` and `--report-token`, so the liveness, alerts and violation
views cover the whole fleet. Remote PEP decision records are surfaced through the central fleet-evidence
store (`--evidence-url`, `GET /evidence/ingested`, the console **Fleet evidence** panel) described above.
The `/evidence/recent` and `/timeline` views remain a projection of the control plane's **own** ledger
(its control-plane actions: approvals, policy deploys, GRC), which is separate from that fleet mirror.

## Backup, disaster recovery and restore

Backup is covered in [chapter 9](09-evidence.md) (`acp ledger-backup` copies the ledger with its WAL and
re-verifies the copy). This section is the recovery side: how to restore, and how to set a recovery
objective.

### What to protect

- The **evidence ledger** (`evidence.db` and its `-wal`/`-shm`): the signed record of every decision.
- The **control-plane store** (`control.db` or your Postgres/MySQL database): identity, endpoints, GRC.
- The **approvals store**, the **KEK** (`/etc/acp/ledger.kek`), and the **signing keys**. Losing the KEK
  makes recorded argument payloads unreadable; losing a signing key breaks future signing, not past
  verification.

### Streaming replication for a low RPO

`acp ledger-backup` is a point-in-time copy. For a near-zero recovery point objective, stream the
ledger's write-ahead log continuously to object storage with **Litestream** or **LiteFS**, or move the
ledger behind Postgres with the same append-and-verify API. Because an append is durable per record and
the WAL streams continuously, the recovery point is the last streamed frame, so RPO approaches zero. Back
the control-plane store and the shared state with a managed, replicated Postgres so their DSN is the only
shared-state dependency.

### Warm standby for a low RTO

Run the control plane active plus a **warm standby** behind a VIP with health checks (`/healthz`,
`/readyz`). Policy is signed, so a standby that serves a stale-but-signed policy still fails safe: it can
never serve an unsigned or forged policy. Failover is a VIP cutover, so the recovery time objective is
the health-check interval plus DNS/VIP convergence. Set explicit RTO and RPO targets and rehearse them;
`deploy/failover-drill.sh` proves the shared gateway budget survives a replica failure.

### Restoring, and proving the restore

A restore is only trustworthy if you can prove the restored evidence is intact. That is exactly what
`acp verify` is for, so make it the last step of every restore:

```sh
# 1. stop the control plane (or fail the VIP over to the standby)
systemctl stop acp-server

# 2. restore the ledger and control store from the latest good backup / replica
cp /backups/evidence-<ts>.db      /var/lib/acp/evidence.db
cp /backups/evidence-<ts>.db-wal  /var/lib/acp/evidence.db-wal 2>/dev/null || true
# (control.db from its backup, or point --store at the recovered Postgres)

# 3. PROVE the restored evidence verifies before trusting it
acp verify /var/lib/acp/evidence.db          # expect: OK ... verifies

# 4. restore the KEK and signing keys to /etc/acp with 0600, then start
systemctl start acp-server
curl -s http://127.0.0.1:8787/readyz         # ready
```

If `acp verify` fails on the restored copy, that backup is torn or tampered; go to the previous good one.
Verify catches inconsistency, so a restore that verifies is a restore you can hand to an auditor.

### A caveat on hot backups

`acp ledger-backup` copies the db, `-wal` and `-shm` files, which is consistent when writers are
quiesced. Under heavy concurrent writes the file copy can capture a torn WAL snapshot; verify then proves
the copy is self-consistent, not necessarily current to the last write. For a fully consistent hot
backup, quiesce writers briefly or rely on the streaming WAL replication above.

## Upgrades, rollback and schema migration

### Schema migrations

Both the control-plane store (`acp-cpstore`) and the shared Postgres state (`acp-pgstate`) run their
schema migrations **automatically on connect**. There is no separate migrate step to run: start a newer
binary against the existing database and it brings the schema forward. Migrations are additive
(expand-only), so a newer schema stays readable by the version that created it. Because of this, always
**back up the database before an upgrade** (a migration is a one-way step forward).

### Rolling upgrade

The control plane drains in-flight requests on `SIGTERM`, so a rolling upgrade is: bring up the new
version alongside (or fail over to the standby), let the old one drain, then retire it. Policy is signed
and PEPs treat a stale-but-signed policy as fail-safe, so a brief version skew between the control plane
and the PEPs does not open a hole: an out-of-date PEP still enforces the last signed policy it holds and
verifies evidence the same way.

### Rollback

To roll a binary back, redeploy the previous version against the **same** database. Because migrations
are expand-only, the older binary can still read the schema the newer one left. Keep the pre-upgrade
backup until you have confirmed the new version, so a rollback that also needs the old schema has a clean
restore point. Verify the ledger after any rollback that touched the evidence store.

## Incident runbook

A consolidated detect, contain, investigate, recover, clear loop that ties the controls together.

1. **Detect.** An alert fires: `GET /alerts` trips on a deny or fail-open spike, `GET /liveness` shows a
   proxy gap, the console **Violations** panel shows a burst, or a Prometheus alert on `/metrics` pages.
   A tool-integrity pin mismatch (a tool changed under a live agent) is a supply-chain alarm.
2. **Contain.** Engage the kill-switch, scoped as tightly as the incident allows, from the console
   Kill-switch control or `POST /break-glass/engage` (see [chapter 11](11-containment.md)). Use
   `lockdown_all` scoped to the affected `agent:`, `resource:` or `tool:` rather than downing the fleet.
   `lockdown_all` persists past its TTL until you clear it, on purpose.
3. **Investigate.** Use `acp diagnose <ledger.db> <seq>` for a redacted decision bundle (no raw
   arguments), `acp replay <ledger.db> <seq> <policy.yaml>` to re-evaluate a recorded decision against a
   policy and detect drift, and the console evidence and timeline views. The signed ledger is the source
   of truth; `acp verify` confirms it is intact.
4. **Recover.** Once the cause is understood, fix the policy (test the change with
   `acp policy-test --diff`, see [chapter 2](02-policy.md)) and deploy it signed. If evidence or state
   was lost, restore and prove it with `acp verify` (see disaster recovery above).
5. **Clear.** Lift the kill-switch from the console or `POST /break-glass/clear`. Engaging and clearing
   are themselves recorded in the meta-audit, so the emergency response is evidenced. Write up the
   incident against the framework controls with `acp grc-report`.
