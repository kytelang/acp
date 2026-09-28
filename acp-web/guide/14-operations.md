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

**High availability.** The control plane is multi-tenant (records are scoped per tenant with per-tenant
signing keys, and the console tenant switcher re-scopes the view; the per-instance default comes from
`ACP_TENANT`). It supports running more than one
replica behind one shared `--store`: a fenced leader lease elects a single active leader (so there is
no split-brain), and the liveness and spike-detector state is persisted to the shared store, so the
dead-man's-switch and alert state survive a restart or a failover. Give each replica a stable
`--node-id` and, optionally, a `--lease-ttl-ms` (default 15000). `GET /leader` reports which node
holds the lease and the current fencing token.

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
acp-agent mcp ... --pin-pg  "host=pg user=acp password=... dbname=acp"
```

Token budgets refill under a row lock, and tenant isolation in the multi-tenant store is enforced by
Postgres row-level security. **Important:** connect as a **non-superuser** role. Postgres superusers
(and roles with BYPASSRLS) ignore RLS, so the store refuses to initialise against such a role rather
than silently break isolation.

### Two control-plane replicas and failover

Run two (or more) `acp-server` replicas against the same `--store`. Each acquires and renews a fenced
leadership lease; only one is the leader at a time.

```sh
acp-server --addr 0.0.0.0:8787 --store "$STORE" --node-id node-a --lease-ttl-ms 15000
acp-server --addr 0.0.0.0:8788 --store "$STORE" --node-id node-b --lease-ttl-ms 15000
```

`GET /leader` on each returns `{node, leader, holder, token}`. Exactly one reports `leader: true`. If
the leader is killed, the survivor acquires the lease after at most one TTL with a strictly larger
fencing token, so a paused old leader that wakes up is fenced out. PEP heartbeats and events keep
being accepted by whichever replica serves them, and their liveness and spike state is shared, so the
dead-man's-switch and alerts do not reset on failover.

`scripts/soak.sh` is a self-contained scale and failover drill: it drives sustained concurrent load
through the proxy and the gateway (reporting rps and p50/p95/p99), then runs this two-replica failover
under a write load and asserts there is no split-brain, that control and liveness state survive, and
that recovery is bounded by the lease TTL. A measured run (a developer machine, mock upstreams) is
published in `docs/soak-report.md`: proxy about 4,900 rps (p99 37 ms), gateway about 3,400 rps (p99
102 ms), both zero-error, and failover in about 2.7 seconds at a 3 second TTL. Re-run it in your target
environment for environment-specific numbers.

### Backup and restore (DR)

The durable state is the control-plane store (the `--store` database) and each PEP's append-only
signed ledger.

1. **Back up** the store (for SQLite copy the file with the WAL, e.g. `sqlite3 store.db ".backup
   backup.db"`; for Postgres use `pg_dump`) and copy each PEP's `--ledger` file.
2. **Restore** by putting the store back in place and pointing the replicas at it, and by restoring
   the ledger files to their PEP hosts.
3. **Verify** the restored ledger before trusting it:

   ```sh
   acp verify restored-ledger.db
   # OK: restored-ledger.db verifies
   ```

   The Merkle chain and every record signature are checked, so a truncated or tampered restore is
   rejected rather than silently accepted.

## Event webhooks (stakeholder notifications)

Point the control plane at an outbound webhook to notify stakeholders on governance and violation
events:

```sh
acp-server ... --webhook-url https://hooks.example.com/acp --webhook-secret "$ACP_WEBHOOK_SECRET"
```

Each event is a JSON body `{type, ts_ms, event}` where `type` is `grc.created`, `grc.status`,
`grc.assigned` or `violation`. The request carries an `x-acp-signature: t=<unix>,v1=<hmac-sha256>`
header the receiver verifies against the shared secret (the same primitive as the inbound Slack
verification). Attacker-influenced fields (a tool name, a record title) are carried only as JSON values,
never interpolated into markup, so a crafted value cannot forge the notification. Delivery is
best-effort and non-blocking; it never delays enforcement.

**Inbound ticket callbacks (two-way).** A ticket system can close the loop by POSTing to
`/tickets/callback` with the same HMAC signature scheme (`x-acp-signature`, verified against
`--webhook-secret`). The body `{action, id, status?}` either resolves an approval hold
(`approve`/`deny`) or advances a GRC record's status (`grc-status`), re-signing the record. A missing
secret or a bad signature is rejected.

**Named connector adapters (Slack, Jira, MLflow).** On top of these generic rails ACP ships thin,
vendor-neutral adapters for the common enterprise tools; no vendor SDK is embedded.

- **Slack:** `--slack-webhook-url <url>` delivers every control-plane event to a Slack incoming webhook
  as an injection-safe Block Kit message, alongside (or instead of) the generic `--webhook-url` sink.
- **Jira:** `POST /tickets/jira` accepts a Jira `issue_updated` webhook (verified with the same
  `x-acp-signature` HMAC as `/tickets/callback`) and maps it to a resolution using an
  `acp-approval:<id>` or `acp-grc:<id>` issue label plus the new status: a terminal Done/Approved
  approves the hold or sets the GRC record to `approved`, Rejected denies or sets `rejected`, and an
  intermediate transition or a non-ACP issue is a no-op.
- **MLflow:** `--mlflow-url <base>` imports the MLflow model registry at start-up (highest version per
  model) through the normal admission-scan and signed AI-BOM path, so imported models are governed like
  manually registered ones. It is idempotent by (name, version).

These are documented with the request/response shapes in `docs/connectors.md`.

## Logging

All services use structured logging, and **all of them write logs to STDERR**. This is deliberate: the
the `acp-agent mcp` stdio transport carries the JSON-RPC protocol on STDOUT, so keeping logs off STDOUT means
structured logging never corrupts the frame stream. Set the level with `ACP_LOG` (or `RUST_LOG`), and
switch to one-JSON-object-per-line for a log pipeline with `ACP_LOG_FORMAT=json`.

```sh
ACP_LOG=info ACP_LOG_FORMAT=json acp-gateway ...
ACP_LOG=warn acp-agent mcp stdio ...
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
guard against a mis-scoped database role, and control-plane high availability (a fenced leader lease,
shared-store liveness and spike state, and a verify-on-restore DR path). Scale and failover are now
exercised by a published soak drill (`scripts/soak.sh`, numbers in `docs/soak-report.md`), and the
detection-efficacy CI gate runs over a labelled corpus on every build. Remaining before an unattended
rollout: turning the sequence and firewall protections on by default, an endurance run against a real
Postgres store in your environment, and third-party certification (a control-mapping readiness
assessment is in `docs/soc2-iso-control-mapping.md`).

## Storage: one database library

All networked and multi-engine storage runs on **sqlx**: the control-plane store (`acp_server::store`,
sqlite/postgres/mysql by connection URL), the shared budget and tool-pin state (`acp_core::pgstate`,
feature `postgres`), and the multi-tenant RLS store (`acp_core::pgstore`). The only remaining use of a
second database crate is the embedded, per-host evidence **ledger** and the approval store, which stay
on rusqlite by design: they are synchronous, crypto-critical, embedded SQLite files with no server or
multi-engine requirement, and the ledger sits on the append hot path. Porting the ledger to async sqlx
would be a large change to the trust core for no functional gain, so it is kept as a deliberate
exception.

## Setting up Postgres or MySQL

Two different things can move off SQLite, and they take different DSNs. Do not confuse them.

- **The control-plane store** (identity, AI endpoints, GRC records) is chosen with `acp-server --store`
  (or the `ACP_STORE` value the installer wires into the unit's `ExecStart`). It accepts a
  `sqlite://`, `postgres://` or `mysql://` URL. The same server code runs against any of them; schema
  migrations run automatically on connect.
- **The shared runtime state** (gateway token budgets, proxy tool-integrity pins) uses a
  key-value-style connection string: `acp-gateway --budget-pg` and `acp-agent mcp --pin-pg`. These are
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
acp-agent mcp --pin-pg  'host=db user=acp_app password=change-me dbname=acp' ...
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
