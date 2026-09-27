# 17. Console reference

The web console (`acp-console`) is the browser UI over the control plane. It is a thin, read-only
view over `acp-server`'s verifiable API: every figure it shows is served by `acp-server` and is
re-derivable from the signed evidence, and every change it makes is forwarded to `acp-server`, which
is the only component that holds a signing key and makes a decision. The console holds no trust and
no key of its own.

This chapter documents every configuration entry an operator can make from the console: each page,
each input field, each button, the server endpoint it calls, and the RBAC capability that endpoint
requires. Reads (the tables and metrics that refresh on their own) are covered briefly; the detail is
on the actions that change state.

## How the console talks to the control plane

The console reads its control-plane URL from the environment variable `ACP_CONTROL_PLANE_URL`. When
it is unset the console falls back to `http://127.0.0.1:8787`, the default local `acp-server` address.

The browser page (`wwwroot/index.html`) uses datastar. It never calls `acp-server` directly. Instead
it posts the on-screen form values (datastar signals) to a small set of routes on the console binary
itself, and the console handler forwards a clean request to `acp-server`. So there are two hops for
every action:

1. browser to console route (for example `POST /policy/deploy`),
2. console to `acp-server` route (for example `POST /policy-store/deploy`).

The tables and metrics are pushed the other way, over a single Server-Sent Events (SSE) stream. When
the page loads it opens `GET /sse/metrics` on the console, and about every two seconds the console
re-reads `acp-server` and patches each panel fragment in place (overview metrics, apps, agents,
policy version, approvals, evidence, policy rules, kill-switch status, health, report, endpoints, GRC,
violations, fleet evidence, firewall status, firewall rules, and the violation report). This is why
after you register or change something, the relevant table updates on its own within a couple of
seconds; the immediate outcome badge you see next to a button is patched straight back by the action
handler.

### Authentication and RBAC

When authentication is disabled (the local and default developer setup) `acp-server` runs with RBAC
off: `authorize(...)` returns early and accepts the call, and the actor is recorded as `console`.

When authentication is enabled, the RBAC-gated `acp-server` endpoints require a bearer token whose
principal carries the right capability. Roles map to capabilities as follows (from `acp-auth`):

| Entra app role | Capability granted |
| --- | --- |
| `PolicyAdmin` | `EditPolicy` |
| `Approver` | `Approve` |
| `Auditor` | `Export` |
| `SecurityOfficer` | `SeeArgs` |
| `BreakGlassOperator` | `BreakGlass` |

Unknown roles grant nothing (fail-closed). Of these five capabilities, only three are actually
enforced on the console-facing endpoints today: **`EditPolicy`**, **`Approve`** and **`BreakGlass`**.
`Export` and `SeeArgs` are defined but not checked by any route the console calls.

How the token is obtained: the console prefers a real token forwarded in the incoming
`Authorization` header (injected by an identity-aware proxy or OIDC login placed in front of the
console). When no such header is present, the console client falls back to fetching a short-lived
token from `acp-server`'s mock endpoint `GET /auth/dev-token?role=...` for local use. It requests the
`PolicyAdmin` role for policy, identity, endpoint, GRC and firewall actions, and the
`BreakGlassOperator` role for the kill-switch. Read endpoints (the GET routes behind the tables) are
not RBAC-gated; a separate report token can gate the report and metrics reads if `acp-server` is
started with one.

### Console route to server route map

| Console route (browser posts here) | Forwards to `acp-server` | Capability |
| --- | --- | --- |
| `POST /approve/{id}` | `POST /approvals/{id}/approve` | `Approve` |
| `POST /deny/{id}` | `POST /approvals/{id}/deny` | `Approve` |
| `POST /apps/register` | `POST /apps` | `EditPolicy` |
| `POST /agents/register` | `POST /agents` | `EditPolicy` |
| `POST /agents/{id}/deactivate` | `POST /agents/{id}/deactivate` | `EditPolicy` |
| `POST /endpoints/register` | `POST /endpoints/register` | `EditPolicy` |
| `POST /policy/deploy` | `POST /policy-store/deploy` | `EditPolicy` |
| `POST /firewall/save` | `POST /firewall/config` | `EditPolicy` |
| `POST /firewall/rule-add` | `POST /firewall/rules` | `EditPolicy` |
| `POST /firewall/rules/{id}/delete` | `POST /firewall/rules/{id}/delete` | `EditPolicy` |
| `POST /grc/create` | `POST /grc` | `EditPolicy` |
| `POST /grc/{id}/to/{status}` | `POST /grc/{id}/status` | `EditPolicy` |
| `POST /kill/engage` | `POST /break-glass/engage` | `BreakGlass` |
| `POST /kill/clear` | `POST /break-glass/clear` | `BreakGlass` |
| `GET /report/violations.csv` | `GET /report/violations.csv` | none (read) |
| `GET /sse/metrics` | reads many GET endpoints | none (read) |

## The layout

The left sidebar groups the pages: **Governance** (Overview, Approvals, Evidence, Violations,
Reports), **Identity** (Teams, Agents, Models, AI Endpoints), **Policy** (Policy, Content firewall),
**Compliance** (Governance), **Emergency** (Kill-switch), and **Health** (Integrity, Monitors). The top-right
carries a light/dark theme toggle, a "live" indicator that pulses while the SSE stream is connected,
and a **tenant selector** (populated from `GET /tenants`). Switching the tenant re-scopes every panel
over the live stream and applies to writes, so an operator can move between tenants in the browser
without restarting; a single-tenant instance can pin its tenant with the `ACP_TENANT` environment
variable. The rest of this chapter walks each page in that order.

## 1. Overview

**What it is for:** the landing page. A read-only, live snapshot of the current governance posture.
There is nothing to configure here.

It shows stat tiles (Records, Decisions, Coverage, Denied, Step-up) and a verdict-distribution bar
(allow, step-up, shadow, deny). Every figure comes from `acp-server`'s `GET /report` and is
re-derivable from the signed ledger. If the tiles read "acp-server unreachable", start the control
plane on `127.0.0.1:8787` (or point `ACP_CONTROL_PLANE_URL` at it).

The **Integrity** page (sidebar: Health) is the companion read-only view: ledger integrity (from
`GET /verify`), proxy liveness (`GET /liveness`), spike alerts (`GET /alerts`) and the self-governance
meta-audit log (`GET /meta-audit`). Both pages refresh over the SSE stream.

## 2. Approvals

**What it is for:** the human step-up inbox. When a policy verdict is `step_up`, the enforcement
point holds the call and registers a pending approval. An operator resolves each hold here with a
single decision. Field step-ups reach the inbox because the proxy forwards them to the control plane
(the proxy is pointed at the console/control plane with its `--approvals-url` flag); the console then
reads the queue from `acp-server`'s `GET /approvals/pending`.

**Each pending hold row shows:** a "step-up" badge, the tool name, and the hold id (read-only, from
the server).

**Buttons (per row):**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Approve** | `POST /approve/{id}` | `POST /approvals/{id}/approve` | `Approve` |
| **Deny** | `POST /deny/{id}` | `POST /approvals/{id}/deny` | `Approve` |

There are no input fields: the decision is the id in the path plus the verb. After you click, the
console forwards the decision to `acp-server` and patches the refreshed inbox back into the page.

> Note: when RBAC is enabled, `acp-server`'s approve and deny endpoints require the `Approve`
> capability (role `Approver`). See the caveat at the end of this chapter about how the console
> currently forwards these two calls.

## 3. Evidence

**What it is for:** two read-only timelines of governed decisions. Nothing to configure.

- **Recent governed decisions** (the tamper-evident ledger): a table of Seq, Tool, Resource,
  Verdict, Agent, Principal, from `acp-server`'s `GET /evidence/recent`.
- **Fleet evidence**: signed decision records streamed from the enforcement points and re-verified by
  the control plane, from `GET /evidence/ingested`. Columns: PEP, Tool, Verdict, Signed (verified or
  not), Decision ID.

Both refresh over the SSE stream. Chapter 9 covers the ledger itself.

## 4. Violations

**What it is for:** the live deny/violation feed. Read-only. Denials, step-ups and blocks reported by
the enforcement points to the control plane, newest first, from `acp-server`'s `GET /events/recent`.

Columns: PEP, Agent, Tool, Verdict, Rule, Impact, Outcome. The aggregated, exportable version of this
data lives on the Reports page.

## 5. Reports

**What it is for:** two auditor-facing reports, both read-only and printable.

- **Governance report**: a consolidated card view (governed decisions, policy coverage, denied and
  step-up counts, ledger integrity), built from `GET /report` and `GET /verify`. Every figure is
  re-derivable from the signed ledger.
- **Breaches and violations report**: policy denials and firewall blocks reported by every
  enforcement point, aggregated. It shows a grand total plus three breakdowns: by verdict, by rule
  (top rules), and by enforcement point. Built from `acp-server`'s `GET /report/violations`.

**Buttons:**

| Button | Action | Endpoint |
| --- | --- | --- |
| **Print / export PDF** | opens the browser print dialog (`window.print()`); the sidebar and top bar are hidden in print | none |
| **Print** (on the breaches report) | same print dialog | none |
| **Download CSV** | downloads the raw violation records as `violations.csv` | console `GET /report/violations.csv`, which forwards `acp-server`'s `GET /report/violations.csv` for a same-origin download |

The CSV columns are `ts_ms, pep, agent, tool, verdict, rule_id, impact, outcome`. The report reads are
not RBAC-gated, but if `acp-server` was started with a report token, `GET /report` and
`GET /report/violations` require that token.

## 6. Teams

**What it is for:** register a team (application). A team owns agents. Open the popup with the
**+ Register team** button in the card header. The page also shows a read-only table of registered
teams (Team, Owner, Agents count, ID), refreshed over SSE from `GET /apps`.

**Register a team / application popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Name** | required | the team or application name | free text (for example `acme-app`) |
| **Owner** | optional | who owns the team | free text (for example `you`) |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Register** | `POST /apps/register` | `POST /apps` | `EditPolicy` |
| **Close** | closes the popup | none | none |

On success the outcome badge shows "registered" and the new app id. The teams table then picks up the
new row on the next SSE tick.

## 7. Agents

**What it is for:** register an agent under a team, and revoke agents. Open the popup with the
**+ Register agent** button. The page shows a read-only table of agents (Agent, Belongs to team,
Status, Action), refreshed over SSE from `GET /agents` (with team names resolved from `GET /apps`).

**Register an agent popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **App ID** | required | the id of the team this agent belongs to | an existing app id (for example `app-...`) |
| **Name** | required | the agent name | free text (for example `coding-assistant`) |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Register** | `POST /agents/register` | `POST /agents` | `EditPolicy` |
| **Close** | closes the popup | none | none |

Registering returns a **one-time token** shown once in the outcome line, with the instruction to save
it now because it is not shown again. Store it: the agent uses it to authenticate to the enforcement
points.

**Deactivate (per row):** for an active agent the table shows a **Deactivate** button.

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Deactivate** | `POST /agents/{id}/deactivate` | `POST /agents/{id}/deactivate` | `EditPolicy` |

A revoked agent shows a "revoked" status and no action button. See chapter 8 for the identity and
registry model.

## 8. AI Endpoints

**What it is for:** enrol an AI agent or provider (for example `claude.ai`, `chatgpt.com`,
`api.x.ai`, or an MCP server URL) and record a signed disposition for it. The provider is classified
automatically by `acp-server`. Open the popup with **+ Register endpoint**. The page shows a
read-only table (Endpoint, Provider, Kind, Disposition, Reason) from `GET /endpoints`, refreshed over
SSE; an expired accept-risk exception is marked "expired".

**Register an AI endpoint popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Endpoint (host or URL)** | required | the host or URL to govern | free text (for example `claude.ai`) |
| **Disposition** | required (defaults to `govern`) | what to do with traffic to this endpoint | `govern` (route through ACP), `block` (quarantine), `accept-risk` (a time-boxed exception) |
| **Reason** | optional | why this disposition (defaults to `sanctioned`) | free text |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Register endpoint** | `POST /endpoints/register` | `POST /endpoints/register` | `EditPolicy` |
| **Close** | closes the popup | none | none |

On success the outcome shows the registered endpoint and the detected provider. Enrolling an endpoint
also seeds firewall rules automatically (see the firewall rules card). Chapter 12 covers enrolment
and discovery.

## 9. Models

**What it is for:** the registered-model inventory, with each model's admission scan result. Register a
model from **+ Register model** (or `POST /models`); if a model scanner is configured
(`--model-scanner-url`), registration runs an admission scan and stores a signed CycloneDX AI-BOM.
Models can also be imported automatically from an MLflow registry with `--mlflow-url` (see
[chapter 14](14-operations.md)).

The page shows a read-only table (Model, Provider, Version, Scan, ATLAS, AI-BOM, ID) from `GET /models`,
refreshed over SSE. The **Scan** cell shows `clean`, `unscanned`, or the findings; the **ATLAS** cell
lists the MITRE ATLAS technique ids mapped from any scan findings (for example `AML.T0051`,
`AML.T0011.000`), from the `atlas` field of `GET /models`; the **AI-BOM** cell shows `signed` when a
signed bill of materials is stored. See [chapter 12](12-grc.md) for the AI-BOM record and the ATLAS
mapping.

**Register a model popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Name** | required | the model name | free text (for example `acme/frontier-1`) |
| **Provider** | optional | the model provider | free text (for example `openai`, `mlflow`) |
| **Version** | optional | the model version | free text |

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Register model** | `POST /models` | `POST /models` | `RegisterApp` |
| **Close** | closes the popup | none | none |

## 10. Policy

**What it is for:** view the deployed policy and author and deploy a new version. The page has two
tabs.

- **Deployed policy** tab: a read-only table of the rules in force (Rule, Agent, Principal, Resource,
  Op, Tool, Effect, Obligations), from `GET /policy-store/rules`, with app and agent ids resolved to
  registered names and "any" shown where a rule is not scoped. The card header shows the deployed
  version badge and the author, from `GET /policy-store`.
- **Editor** tab: a Monaco YAML editor pre-filled with a sample policy.

**Editor tab controls:**

| Control | What it does |
| --- | --- |
| **Upload .yaml** | opens a file picker (accepts `.yaml`, `.yml`, `text/yaml`, `text/plain`); the chosen file's contents are loaded into the editor for review before you deploy |
| **Editor** (Monaco) | edit the policy in the YAML DSL; edits mirror into the datastar-bound `policy` signal |
| **Author** (text field) | the author to attribute the deploy to; defaults to `operator` |
| **Deploy policy** (button) | submits the policy |

**Deploy:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Deploy policy** | `POST /policy/deploy` | `POST /policy-store/deploy` | `EditPolicy` |

The console forwards the `policy` (YAML) and `author` signals to `acp-server`, which validates,
versions and signs the policy and writes it to the trust store; the proxy hot-reloads it only after
verifying the signature. On success the outcome shows "Deployed as v{n}". The rules table and the
version badge update on the next SSE tick.

The YAML DSL (versions, `default`, `rules` with `when`/`verdict`/`obligations`/`approvers`, and the
verdicts `allow`, `deny`, `step_up`, `shadow`) is documented in full in
[chapter 2, Policy and authorization](02-policy.md).

## 11. Content firewall

**What it is for:** configure the content firewall centrally. The config is stored in the control
plane; the enforcement points fetch it, so there is no local model file to distribute. The page has
two cards: the config form and the firewall rules list.

### Firewall config

The card first shows a read-only status line (enabled/disabled, block-secrets on/off, whether an ML
model is loaded, the denied topics, whether an external scanner is set and its fail mode) from
`GET /firewall/config`.

**External scanner hook (contract).** When an **External scanner URL** is set, each enforcement point
POSTs `{"modality", "text", "direction", "context"}` to it and honours the reply `{"block",
"redactions"}`. The `direction` is one of `prompt`, `response`, `tool_args` or `tool_result`, so a
scanner can treat inbound and outbound content differently. Non-text tool parts are forwarded with
`modality: image|audio` and a `content_ref` (a base64 blob or a URL). The full versioned contract and
vendor adapter mappings are in `docs/scan-hook-contract.md`. When `block` is true the enforcement point
blocks the call (a tool call is refused with an error; a tool result is replaced with a safe message);
`redactions`, when present, replaces the offending text. If the scanner errors, **On scanner error**
decides the outcome: fail open runs the built-in engine and proceeds, fail closed blocks. With no URL
set the built-in engine runs exactly as before (offline default).

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Enabled** | optional (defaults `off`) | turns the content firewall on or off | `off` (`false`), `on` (`true`) |
| **Block secrets** | optional (defaults `no`) | block content that looks like secrets or credentials | `no` (`false`), `yes` (`true`) |
| **Denied topics** | optional | topics to deny, comma-separated (split and trimmed into a list) | free text (for example `weapons, malware`) |
| **ML model JSON** | optional | paste `model.json` content; leave blank to use signatures only | JSON text, or empty |
| **External scanner URL** | optional | a first-class external detection hook; blank uses the built-in engine only | URL, or empty |
| **On scanner error** | optional (defaults fail open) | what to do when the external scanner errors or is unreachable | `fail open (built-in still runs)` (`false`), `fail closed (block)` (`true`) |

**Button:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Save firewall config** | `POST /firewall/save` | `POST /firewall/config` | `EditPolicy` |

The console assembles the JSON body (`enabled`, `block_secrets`, `deny_topics` array, `model`) and
posts it; the status line refreshes with the saved config.

### Firewall rules

Operator-authored interception rules: match a destination, choose an action. They are served to every
`acp-agent`, and operator rules win on first match. The card shows a read-only table (Match, Action,
Classify, ID, and a per-row Delete) from `GET /firewall/rules`. Rules also appear automatically from
enrolled AI endpoints.

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Match** | required (defaults `host contains`) | how to match the destination | `host contains` (`host_contains`), `host suffix` (`host_suffix`), `host exact` (`host_exact`), `TLS SNI` (`sni`), `path contains` (`path_contains`) |
| **Value** | required | the value to match against | free text (for example `api.openai.com`) |
| **Path prefix** | optional | further restrict to a path prefix | free text (for example `/v1`) |
| **Action** | required (defaults `block`) | what to do on a match | `block`, `inspect-prompt`, `govern-tool-call`, `dlp-only`, `pass` |
| **Classify** | optional | a label for the matched traffic | free text (for example `model-api`) |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Add rule** | `POST /firewall/rule-add` | `POST /firewall/rules` | `EditPolicy` |
| **Delete** (per row) | `POST /firewall/rules/{id}/delete` | `POST /firewall/rules/{id}/delete` | `EditPolicy` |

The console builds the rule body from the selected match kind (the match kind becomes the JSON key,
with `value` as its value), plus optional `path_prefix`, the `action`, and optional `classify`. The
rules table refreshes after add or delete. The full firewall rules schema and the meaning of each
match kind and action is in [chapter 5, Forward and TLS interception](05-intercept.md); the detection
model is in [chapter 10, The content firewall](10-content-firewall.md).

## 12. Governance

**What it is for:** create and advance signed governance records (GRC). Each record is Ed25519-signed
by the control plane, stored in the control-plane database, and re-verified on read. Open the create
popup with **+ Create record**. The page shows a read-only table (Kind, Subject, Title, Status,
Signed, ID, Advance) from `GET /grc`, refreshed over SSE.

**Create a governance record popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Kind** | required (defaults `assessment`) | the record type | `assessment`, `conformity`, `risk`, `model-card`, `use-case`, `attestation`, `aibom` |
| **Subject** | required | what the record is about | free text (for example `checkout-agent`) |
| **Title** | optional | a human title | free text (for example `EU AI Act tiering`) |
| **Status** | optional (defaults `open`) | the initial status | free text (defaults to `open`) |
| **Details (JSON or text)** | optional (defaults `{}`) | free-form JSON or text specific to the kind | JSON or plain text |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Create record** | `POST /grc/create` | `POST /grc` | `EditPolicy` |
| **Close** | closes the popup | none | none |

**Per-record status controls (Advance column):** three buttons move a record through its lifecycle.

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Review** | `POST /grc/{id}/to/in-review` | `POST /grc/{id}/status` (status `in-review`) | `EditPolicy` |
| **Approve** | `POST /grc/{id}/to/approved` | `POST /grc/{id}/status` (status `approved`) | `EditPolicy` |
| **Close** | `POST /grc/{id}/to/closed` | `POST /grc/{id}/status` (status `closed`) | `EditPolicy` |

The status is re-signed server-side on each transition. What a governance record is, and how the GRC
lifecycle fits the compliance frameworks, is covered in
[chapter 12, Discovery, enrolment and GRC](12-grc.md).

## 13. Kill-switch

**What it is for:** engage or clear the emergency break-glass grant. Engaging writes a signed, scoped
grant that the proxy watches; a lockdown denies matching calls and stays locked until cleared. The
page shows the live status (from `GET /break-glass`): whether a grant is active, its mode, scope,
reason, and whether it is signed. Open the popup with the **Engage / clear** button.

**Engage or clear the kill-switch popup:**

| Field | Required | What it does | Allowed values |
| --- | --- | --- | --- |
| **Mode** | required (defaults `lockdown_all`) | what the grant does | `lockdown_all` (deny matching calls), `disable_enforce` (observe only), `emergency_bypass` (allow held calls) |
| **Scope** | required (defaults `global`) | what the grant applies to; scope it to contain one resource or agent | `global`, or a scope selector such as `resource:database` or `agent:triage` |
| **Reason** | optional (defaults `incident`) | an incident reference | free text |
| **TTL ms** | optional (defaults `3600000`) | how long the grant lasts, in milliseconds | a number of milliseconds (default one hour) |

**Buttons:**

| Button | Console route | Server endpoint | Capability |
| --- | --- | --- | --- |
| **Engage** | `POST /kill/engage` | `POST /break-glass/engage` | `BreakGlass` |
| **Clear** | `POST /kill/clear` | `POST /break-glass/clear` | `BreakGlass` |
| **Close** | closes the popup | none | none |

The console forwards the mode, scope, reason and `ttl_ms` signals to `acp-server`, which writes the
signed grant; the console holds no key. On success the outcome shows the engaged mode and scope, or
"break-glass cleared". The break-glass model and its interaction with policy are covered in
[chapter 11, Sequence, boundary, break-glass](11-containment.md).

## Caveats and things to know

- **Approvals and RBAC:** when RBAC is enabled, `acp-server`'s approve and deny endpoints require the
  `Approve` capability (role `Approver`). The console's approve/deny handler carries the operator's
  bearer token when one is present, and otherwise falls back to an `Approver` dev token, consistent
  with the policy, identity, firewall, GRC and kill-switch actions. In the default local (RBAC-off)
  setup no token is needed.
- **Only three capabilities are enforced today:** `EditPolicy`, `Approve` and `BreakGlass`. The
  `Export` and `SeeArgs` capabilities exist in `acp-auth` but no console-facing endpoint checks them.
- **Dev tokens are for local use only:** the `GET /auth/dev-token` fallback issues a mock token and is
  only available when `acp-server`'s dev auth is enabled. In a real deployment the console shell
  performs an OIDC login and the user's real token is forwarded instead.
- **Reads are live, not on-demand:** the tables and metrics are pushed by the SSE stream every couple
  of seconds, so a newly created or changed record appears shortly after the action, without a manual
  refresh.
