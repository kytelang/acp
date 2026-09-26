# Console-first consolidation and split packaging

Date: 2026-09-22
Status: design, approved in principle (console-first; keep only an independent verifier as a local
tool). Storage backend decision open (SQLite recommended). This document is the authoritative design;
it is not linked from the user guides.

## 1. Why

The system grew a large management CLI (about sixty `acp` subcommands). Most of them change
governance state by writing local files: registering agents, enrolling endpoints, and authoring the
GRC records. That is CLI-for-CLI's-sake. Operating a control plane by running commands on scattered
machines and editing files is the wrong shape: there is no single place to operate the system, no
central store, and no clean server/workstation boundary.

Decision: **operate everything from the console, backed by the control-plane server and a database.**
The management CLI goes away. Two things remain, and neither is "a management CLI":

1. The **enforcement binaries** (the data plane): `acp-proxy`, `acp-gateway`, `acp-guard`,
   `acp-intercept`. These run in the request path; they are deployed, not "used to manage".
2. One small **independent verifier**, `acp-verify`. This is the single principled exception, see
   section 3.

## 2. End-state architecture

- **acp-server + acp-console + a database** are the single place to operate the system. All
  registration and all governance records are created and changed here, through the console (for
  people) or the control-plane API (for automation), and stored centrally. Signing is done
  server-side, as it already is for policy deploy and endpoint registration.
- **The enforcement binaries** are deployed where AI acts and are configured by the control plane.
- **acp-verify** is the only local tool an outside party runs.
- **CI gates** (red-team, content-eval, policy-test) are server API endpoints a pipeline calls, plus a
  thin optional helper; they are not a broad CLI.

### What moves into server API + console + DB

| Was (CLI writing a file) | Becomes |
| --- | --- |
| `app register`, `agent register`, `registry` | `POST /apps`, `POST /agents`, deactivate; console Teams/Agents pages |
| `enroll` (AI endpoints) | done: `POST /endpoints/register` + console AI Endpoints page |
| `assess`, `conformity`, `risk`, `modelcard`, `usecase`, `attest`, `aibom` | `/grc/*` API + console GRC pages |
| `discover` | `POST /discovery/ingest` + console Shadow-AI review, one click to enrol |
| `native-compile`, `intercept pac`, `export` | console download buttons (server generates and signs) |
| `coverage`, `posture`, `grc-report`, `siem`, firewall eval results | console read-only views |

### What remains as a local executable

- `acp-verify` only: `acp-verify <ledger.db>` and `acp-verify --pack <pack.json>`. Verification of the
  evidence must not require trusting the server (section 3).
- The enforcement binaries, which are components, not management.

## 3. Why one local tool survives: independent verification

The product's core claim is tamper-evident evidence a third party can verify **without trusting our
store**. If an auditor verifies the ledger through the console, the answer is "the server says it is
valid", which reintroduces trust in the server and voids the guarantee. So a standalone verifier must
exist that a regulator runs on their own machine, offline, with only the public key. It is tiny and
single-purpose (`acp-verify`), not the old sixty-command CLI. The console still offers "download
signed evidence pack"; the outside party checks it themselves with `acp-verify`.

## 4. Storage

Recommendation: a single **SQLite** control-plane store in the server (a new `acp-cpstore` module or
crate) holding apps, agents, principals, AI endpoints, and the GRC records, behind a trait so the
existing `acp-pgstore` Postgres backend is the drop-in for high availability. Rationale: on-prem, zero
external dependency, consistent with the evidence ledger and approvals store which are already SQLite.
Policy stays in the signed policy store the PEPs watch, managed through the console. This is the one
open decision (SQLite vs Postgres as the default); it does not block the packaging change below.

## 5. Packaging: two archives plus the console

Today the release ships one archive per platform with every binary. That does not match the
deployment split. Change to **two role archives plus a console archive**, per platform:

- **User (workstation) archive**: `acp-user-<tag>-<os>-<arch>.(tar.gz|zip)`
  - `bin/acp-proxy`, `bin/acp-intercept`, `bin/acp-verify`
  - what a developer runs: govern a local MCP server, a dev forward proxy, verify evidence.
- **Server archive**: `acp-server-<tag>-<os>-<arch>.tar.gz` (Linux only; the services target Linux)
  - `bin/acp-server`, `bin/acp-gateway`, `bin/acp-guard`
  - `models/injection-lr.json`, `systemd/*.service`
- **Console archive**: `acp-console-<tag>-linux-<arch>.tar.gz`
  - the Kyte-built `acp-console` binary, `wwwroot/`, `app.yaml`
  - built in CI by installing the Kyte toolchain; see section 6.

Each archive has a `.sha256` sidecar. The layout inside each is `bin/` plus role-specific extras, so
the installers stay simple.

## 6. Git and CI workflow changes

`.github/workflows/release.yml`:

- The Rust build matrix stages **two** archives from the same compiled binaries: the user set on all
  platforms (macOS, Linux, Windows), and the server set on Linux only.
- A new **console job** on Linux installs the Kyte toolchain
  (`curl -fsSL https://kytelang.org/install.sh | sh`, then `~/.kyte/bin` on PATH), runs
  `npm ci && npm run css && kyte build` in `acp-console`, and packages the console archive. This
  removes the manual console build. It is best-effort so a Kyte-toolchain hiccup does not block the
  binaries release.
- Every archive is uploaded to the GitHub Release with its checksum.

## 7. Install scripts

- **`install.sh` / `install.ps1`** (workstation): fetch the **user** archive, install
  `acp-proxy`, `acp-intercept`, `acp-verify` into `~/.acp/bin`. No services.
- **`install-server.sh`** (Linux server): fetch the **server** archive and the **console** archive,
  install binaries system-wide, and configure `acp-server`, `acp-gateway` and `acp-console` as systemd
  services, with the config, data directory, service user and at-rest key as today.

## 8. Deployment split (authoritative)

| Runs on a server (systemd services) | Runs on a workstation / in CI |
| --- | --- |
| `acp-server` (control plane + API + DB) | `acp-proxy` (per session, wraps a local MCP server) |
| `acp-gateway` (LLM gateway) | `acp-intercept` (dev forward proxy) |
| `acp-console` (browser UI) | `acp-verify` (independent evidence verification) |
| `acp-guard` (sidecar beside a tool server) | |

## 9. User-guide impact

The guides change from "run these CLI commands" to "operate from the console; verify independently
with `acp-verify`":

- The overview and setup runbook lead with the two archives and the server/workstation split (partly
  done: the deploy-where table and section).
- The per-component chapters describe the enforcement binaries and how the console configures them.
- A single short chapter covers `acp-verify` and independent verification.
- The old CLI-reference chapter is replaced by the console operations guide plus the control-plane API
  reference; the only command-line surface documented is `acp-verify` and the enforcement binaries'
  flags.

## 10. Phasing

1. Split packaging into user, server and console archives; build the console in CI; installers fetch
   the right archives. Introduce `acp-verify`. (This change.)
2. Control-plane DB and the identity and endpoint APIs and console pages.
3. The GRC APIs and console pages; discovery review.
4. Retire the management CLI; rewrite the guides around console-first.

## 11. Compatibility

This is a breaking change to packaging and to how the system is operated. The old single archive and
the management CLI are replaced. `acp-verify` replaces `acp verify` / `acp verify-pack`; the rest of
the `acp` surface is replaced by the console and the control-plane API. There is no promise of
CLI compatibility across this change; it is a deliberate re-shaping before 1.0.
