# 16. Setting it all up, end to end

This is the runbook: install the stack, configure it, run each component, and check that you are
getting the results you expect. It covers a workstation (a developer governing a local agent) and a
server (the control plane and gateway running as services), and finishes with the checks that prove
the system is working.

## 0. Decide what goes where

Varman has two kinds of component.

- **Client tools**, run on a workstation on demand: `acp-proxy` (wraps a local MCP server),
  `acp-intercept` (a forward proxy), and `acp-verify` (independent evidence verification). The `acp`
  CLI and `acp-guard` ship in the server archive.
- **Services**, run on a server: `acp-server` (the control plane) and `acp-gateway` (the LLM
  gateway). These are the components that should run continuously, as systemd units.

Install the client tools on every developer machine; install the services on one or more Linux hosts.

## 1. Install on a workstation

```sh
# on-demand tools only
curl -fsSL https://acpdocs.web.app/install.sh | sh          # macOS, Linux

# or point it at your control plane to also run acp-intercept as a background service
ACP_SERVER=http://cp.internal:8787 curl -fsSL https://acpdocs.web.app/install.sh | sh

# Windows (PowerShell):
powershell -c "irm https://acpdocs.web.app/install.ps1 | iex"
```

This installs the workstation tools into `~/.acp/bin` (or `%USERPROFILE%\.acp\bin`) and adds it to
your PATH: `acp-proxy` (wraps a local MCP server), `acp-intercept` (a forward proxy), and `acp-verify`
(independent evidence verification). `acp-proxy` is launched on demand by the agent host (it wraps a
tool server over stdio). If you set **`ACP_SERVER`** (your control-plane URL), the installer also
configures **`acp-intercept` as a background service** (a launchd LaunchAgent on macOS, a
`systemd --user` unit on Linux) that listens on `127.0.0.1:8890` (override with `ACP_LISTEN`) and
pulls its governed endpoint set from the control plane, refreshing it so the endpoints you enrol in
the console take effect without touching the machine. Set `ACP_NO_SERVICE=1` to install binaries only.
The installer refuses to run under `sudo`: it installs into your home directory.

Manage the service the usual way, for example `launchctl unload ~/Library/LaunchAgents/ai.acp.intercept.plist`
on macOS or `systemctl --user restart acp-intercept` on Linux. Point your agents' or browser's HTTP(S)
proxy at `127.0.0.1:8890`.

You do not register agents or author policy from the workstation: that is done centrally, from the
console or the control-plane API on the server (below). The workstation tools enforce and verify.

## 2. Install the services on a server

On a Linux host with systemd:

```sh
curl -fsSL https://acpdocs.web.app/install-server.sh | sudo sh
```

This installs binaries into `/opt/acp/bin`, creates a service user, and sets up:

- config in `/etc/acp` (`policy.yaml`, `server.env`, `gateway.env`, and a generated `ledger.kek`),
- data in `/var/lib/acp` (`evidence.db`, `approvals.db`, `control.db`),
- a systemd unit `acp-server` (started), and `acp-gateway` (started only once you set an upstream).

It generates a random key-encryption key so the evidence ledger is **encrypted at rest by default**.
Keep `/etc/acp/ledger.kek` safe: losing it makes recorded argument payloads unreadable.

Enable the gateway once you have a model provider to broker:

```sh
sudo sed -i 's#^ACP_UPSTREAM=.*#ACP_UPSTREAM=https://api.anthropic.com#' /etc/acp/gateway.env
sudo systemctl enable --now acp-gateway
systemctl status acp-server acp-gateway
```

## 3. Configure

### Policy

Edit `/etc/acp/policy.yaml` (or your workstation policy). See [chapter 2](02-policy.md) for the full
DSL. Start in observe mode (`default: allow`) and move to `default: deny` once coverage is proven
(step 7).

### Identity

Register applications and agents from the console (Teams and Agents pages), or the control-plane API
([chapter 8](08-identity.md)); they are stored in the control-plane database:

```sh
curl -X POST http://127.0.0.1:8787/apps   -d '{"name":"acme-app","owner":"you"}'
curl -X POST http://127.0.0.1:8787/agents -d '{"app_id":"<app-id>","name":"coding-assistant"}'
# the agent response carries a one-time token, shown once
```

The proxy then verifies agents against this database with `--registry-url` (see below), so no registry
file is needed.

For the human principal, point the control plane and gateway at your IdP (Entra or any OIDC):

```sh
# add these to the acp-server ExecStart: they are CLI flags, not env vars
--entra-tenant <tenant> --entra-audience <audience>
# or: --oidc-jwks <url> --oidc-issuer <iss> --oidc-audience <aud>
```

### The control-plane database

Identity (apps, agents), AI endpoints, and the GRC records are stored in a control-plane database. You
choose the backend by connection URL, so you pick the database that fits your size forecast without a
rebuild:

```sh
# in /etc/acp/server.env (the server install sets a sqlite default)
ACP_STORE=sqlite:///var/lib/acp/control.db?mode=rwc     # small / single-node (default)
# ACP_STORE=postgres://acp_app:secret@db/acp             # larger / high-availability
# ACP_STORE=mysql://acp_app:secret@db/acp                # mysql, if you already run it
```

The same server code runs against any of these. Registration is then done from the console (Teams,
Agents and AI Endpoints pages) or the control-plane API, and stored centrally in that database; you do
not edit files on each machine. For a Postgres or MySQL backend, connect as an ordinary application
role, not a superuser.

### Evidence at rest and key custody

At-rest encryption is on by default on the server (the generated `ledger.kek`, referenced by
`ACP_LEDGER_KEK_FILE`). To sign evidence on an HSM instead of a file key, add the PKCS#11 environment
to `server.env` ([chapter 9](09-evidence.md)):

```sh
ACP_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
ACP_PKCS11_SLOT=<slot>
ACP_PKCS11_PIN=<pin>
ACP_PKCS11_LABEL=acp
```

### Shared state for more than one replica

Point the gateway and proxy at Postgres so replicas share one budget and pin set. Connect as a
**non-superuser** role (superusers bypass row-level security, and the store refuses to initialise
against one):

```sh
# gateway.env
ACP_BUDGET_PG=host=pg user=acp_app password=... dbname=acp
```

Set `ACP_BUDGET_PG` in the environment **before running the server installer** so it is wired into the
gateway unit's `ExecStart`. If you set it afterwards, add `--budget-pg ${ACP_BUDGET_PG}` to the
`acp-gateway` `ExecStart` in `/etc/systemd/system/acp-gateway.service` and reload systemd. The proxy
takes the same DSN via `--pin-pg` to share its tool-integrity pins.

### Logging

Set `ACP_LOG=info` (or `debug`) and `ACP_LOG_FORMAT=json` for a log pipeline. Both are already in the
generated env files.

## 4. Run the enforcement points

### Govern a local MCP server (workstation)

```sh
acp-proxy stdio \
  --policy acp-demo/policy.yaml --ledger acp-demo/ledger.db --key acp-demo/signing.key \
  --registry-url http://<control-plane-host>:8787 --agent-id <agt-id> --agent-token <token> \
  --content-firewall --trajectory acp-demo/trajectory.yaml \
  -- your-mcp-server --its --args
```

### Govern model calls (server)

The gateway runs as a service once configured (step 2). Point your application's model base URL at
`http://<host>:8799`. See [chapter 4](04-gateway.md).

### The other points

`acp-guard` in front of a tool server ([chapter 6](06-guard.md)), `acp-intercept` as a forward proxy
([chapter 5](05-intercept.md)), and `acp native-compile` for coding agents ([chapter 7](07-native-compile.md)).

## 5. The web console

Run the console pointed at the control plane to get a dashboard, approvals, policy deploy, the
kill-switch, the integrity view, and the AI-endpoints page ([chapter 14](14-operations.md)):

```sh
cd acp-console && kyte build
# ACP_CONTROL_PLANE_URL points the console at the control plane (default http://127.0.0.1:8787)
ACP_CONTROL_PLANE_URL=http://127.0.0.1:8787 ./build/debug/bin/acp-console   # http://127.0.0.1:8080
```

The console reads `ACP_CONTROL_PLANE_URL` (default `http://127.0.0.1:8787`), so in a compose or helm
deployment you set it to the control-plane Service URL rather than rebuilding.

## 6. Register your AI endpoints

Bring the agents and providers your organisation uses under governance, from the console's
**AI Endpoints** page or the CLI ([chapter 12](12-grc.md)):

```sh
# via the control plane API (what the console calls)
curl -s -X POST http://127.0.0.1:8787/endpoints/register \
  -H 'content-type: application/json' \
  -d '{"endpoint":"claude.ai","disposition":"govern","reason":"sanctioned assistant"}'
curl -s -X POST http://127.0.0.1:8787/endpoints/register \
  -H 'content-type: application/json' \
  -d '{"endpoint":"chatgpt.com","disposition":"block","reason":"not approved"}'
curl -s http://127.0.0.1:8787/endpoints          # list, with provider classified
```

The server classifies the provider (Anthropic, OpenAI, xAI, Google, Groq, ...) and records a signed
disposition. `govern` counts it as governed, `block` quarantines it, `accept-risk` is a time-boxed
exception.

## 7. Check you are getting the expected results

This is how you prove the system works, not just that it started. `acp-verify` runs anywhere; the
other checks below run on the server (where the interim admin CLI lives) or are shown in the console.

```sh
# 1. End-to-end acceptance: identity, decision, approval, execution, evidence, verification, plus
#    fail-closed checks (a tampered ledger fails, an invalid token is rejected).
bash demo/vertical/run.sh          # expect: 10/10 PASS

# 2. Verify the evidence ledger independently, with the public key alone. acp-verify is the one tool
#    an outside auditor runs; it never contacts or trusts the server.
acp-verify /var/lib/acp/evidence.db          # expect: OK ... verifies
acp-verify --pack pack.json                  # verify a downloaded evidence pack on a clean machine

# 3. Prove the content firewall on an obfuscation corpus.
acp redteam models/injection-lr.json --min-catch 0.9

# 4. Measure that nothing is acting off-ACP.
acp coverage observed.txt governed.txt
acp canary-egress targets.txt                # exit 3 if a model/tool is reachable off-ACP

# 5. A framework report graded from real records.
acp grc-report /var/lib/acp/evidence.db

# 6. The control plane is healthy.
curl -s http://127.0.0.1:8787/healthz        # ok
curl -s http://127.0.0.1:8787/report         # verdict and outcome tallies + coverage
```

You should see the acceptance pass 10 of 10, the ledger verify, the red-team catch-rate above your
threshold with no false positives, and the report reflect the decisions your agents actually made.

## 8. Move to default-deny

Once real traffic has flowed, check whether it is safe to flip the policy default:

```sh
acp posture /var/lib/acp/evidence.db --required 0.8
```

It reports the rule coverage and the exact tools that would newly block. When it says READY and you
have added explicit allow rules for those tools, change `default: allow` to `default: deny` in your
policy and redeploy ([chapter 2](02-policy.md)).

## 9. Troubleshooting

- **The gateway exits immediately.** It needs `--upstream`; set `ACP_UPSTREAM` in `gateway.env`. If a
  content model path is configured but missing, it fails closed; remove `--content-ml` or install the
  model at the path.
- **`acp verify` fails after a manual edit.** That is the point: the ledger is tamper-evident. Restore
  from a backup (`acp ledger-backup`).
- **Tenant isolation seems off in Postgres.** Connect as a non-superuser role; superusers bypass
  row-level security and the store refuses to initialise against one.
- **A service will not start.** `journalctl -u acp-server -e` shows the structured logs; check the
  config paths in `/etc/acp` and the data directory permissions.

For component detail, follow the chapter links above. For the honest maturity picture and what is not
yet production-hardened, see [chapter 14](14-operations.md) and [chapter 15](15-security.md).

## 10. Troubleshooting and FAQ

### Diagnostic commands

These answer the common "is it actually working?" questions without exposing sensitive arguments.

```sh
# Prove a specific decision, redacted (no raw arguments), for a support ticket.
acp diagnose /var/lib/acp/evidence.db <seq>

# Prove the gate is live: probe calls that each declare the verdict they must produce.
acp canary policy.yaml canaries.json          # exits non-zero (pages) on any mismatch

# Prove a tool server is refusing un-proxied calls (the enforcement attestation).
acp verify-enforcement <proxy-pubkey-hex> <x-acp-enforcement-token> [max-age-ms]

# Prove the evidence is intact.
acp verify /var/lib/acp/evidence.db
```

`acp canary` is the one to run on a schedule: a mis-loaded policy that lets a must-deny probe through is
caught within one probe interval. `acp verify-enforcement` is what a tool-server guard uses to reject a
call that did not come through the proxy (see [chapter 6](06-guard.md)).

### Common problems

- **The proxy forwards everything and warns about no policy.** You started `acp-proxy` with no
  `--policy` or `--policy-dir`, so it is in transparent mode and governs nothing. Supply a policy file
  or point `--policy-dir` at the signed policy store.
- **The gateway exits immediately.** It needs `--upstream` (set `ACP_UPSTREAM` in `gateway.env`). If a
  content-model path is configured but missing it fails closed; remove `--content-ml` or install the
  model.
- **`acp verify` fails.** That is the tamper-evidence working. The ledger was edited or a copy is torn.
  Restore from a backup and re-verify (see [chapter 14](14-operations.md)).
- **Postgres tenant isolation looks off, or the store will not initialise.** You connected as a
  superuser or a `BYPASSRLS` role; row-level security is bypassed by such roles, so the store refuses
  them. Connect as an ordinary application role.
- **An agent's calls are rejected as an invalid token.** The one-time token is wrong or the agent was
  deactivated. Re-register the agent from the console Agents page for a fresh token and update
  `--agent-token`.
- **A step-up never resolves.** If the hold does not appear in the console inbox, start the proxy with
  `--approvals-url <control-plane>` so holds register centrally and the operator's decision reconciles
  back to the proxy (see [chapter 11](11-containment.md)); otherwise the hold stays proxy-local and must
  be resolved where the proxy keeps it.
- **A service will not start.** `journalctl -u acp-server -e` shows the structured logs; check the
  config paths under `/etc/acp` and the data-directory permissions.
- **A probe endpoint is missing.** `/healthz` and `/readyz` are on the control plane; the proxy and
  interceptor do not expose them, so use their heartbeat to the control plane
  ([chapter 14](14-operations.md)) for liveness rather than an HTTP probe.

### FAQ

- **Do I register agents or write policy on the workstation?** No. Registration, policy authoring and
  the GRC records are done centrally from the console or the control-plane API; the workstation tools
  enforce and verify. The `acp` CLI is for verification, testing and offline work.
- **Where did the `acp approve` / `acp app` / `acp risk` commands go?** They are retired from the CLI.
  Run one to see its console or API pointer. Management lives in the console and the control-plane API.
- **Can an auditor check the evidence without trusting our server?** Yes. `acp verify` (or `acp-verify`)
  and `acp verify-pack` need only the public key inside the ledger or pack, and never contact the
  server.
