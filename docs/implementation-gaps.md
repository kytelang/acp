# Implementation and guide gap audit

Date: 2026-09-26
Status: living checklist. This is a code-grounded audit of gaps between what Varman (ACP) does, what
it claims, and what the user guide documents. It was produced by a five-part review of the control
plane and data layer, the policy enforcement points, evidence/crypto/GRC, the console/CLI/packaging,
and guide coverage. Each item cites the source. Nothing here has been fixed yet; this is the backlog.

It complements `docs/production-readiness.md` (the P0/P1/P2 tracker). Where an item below refines a
production-readiness item, that is noted.

Severity: CRIT = security bypass or data-integrity break; HIGH = broken/advertised-but-missing;
MED = weakens a stated guarantee or blocks operations; LOW = hardening / defence-in-depth.

## Progress (2026-09-26)

DONE and committed this session:
- **E1** PEP->server violation + heartbeat reporting (authenticated); **E3** console Violations panel.
- **A15** authenticated the /event and /heartbeat ingestion routes.
- **A1** gate approvals approve/deny on Approve; **A3** gate + attribute /admin/meta; **A9** attribute
  GRC/endpoint/approval writes to the verified principal (authorize now returns it).
- **A4** GRC status change re-signs the record; **A8** MySQL-safe store DDL; **B3** honest `acp --help`.
- **A6** HTTP transport screens tool results; **A7** argument scanning recurses into nested JSON;
  **A11** loud warning when the proxy runs with no policy (transparent mode kept).
- **A18** interceptor blocks SSRF to internal targets in the dial path.
- **D2**/**D6** doc inaccuracies corrected.

OPEN (larger slices, in progress): A5 (encrypt record+spool), A10 (break-glass reach to intercept/guard
+ require signature), F1 (field approvals full loop), F2/E2 + gateway/intercept/guard producers,
B1/B2/B4-B10 (console actions, deploy, CI), C (guide lifecycle content), and the MED/LOW A-items.

---

## A. Security and correctness (implementation)

### CRIT

- **A1. Approval routes are ungated.** `POST /approvals/:id/approve` and `/deny` never call
  `authorize(...)`, so with RBAC enabled anyone who can reach the server can resolve a step-up hold.
  The human-in-the-loop obligation is bypassable. `crates/acp-server/src/main.rs:287-288, 369-383`.
  Fix: gate both on `Capability::Approve`.

- **A2. Read and export endpoints are ungated; three capabilities are dead.** `Approve`, `Export`,
  `SeeArgs` are never checked by any route. `/report`, `/evidence/recent`, `/verify`, `/timeline`,
  `/apps`, `/agents`, `/endpoints`, `/grc` are all readable with no token even when RBAC is on; only
  `EditPolicy` and `BreakGlass` are actually enforced. This contradicts the RBAC table in the guide.
  `crates/acp-server/src/main.rs:289-316`; `crates/acp-auth/src/lib.rs:125-159`.

- **A3. Meta-audit is forgeable.** `POST /admin/meta` (the self-governance log) is unauthenticated and
  takes `actor` from the request body, so anyone reachable can append forged, arbitrarily-attributed
  governance events. The hash chain is tamper-evident but authorship is not.
  `crates/acp-server/src/main.rs:297, 525-551`.

- **A4. GRC status change breaks the record's own signature.** `update_grc_status` writes the new
  status but does not re-sign; `grc_list` recomputes the doc with the new status and verifies it
  against the old signature, so a legitimate lifecycle change makes the record display as tampered.
  `crates/acp-server/src/main.rs:979` vs `:926-929`.

- **A5. Encryption at rest covers only `args_blob`.** The canonical record (principal, agent, tool,
  resource, rule, operation) is plaintext, and the pre-drain spool writes full arguments in plaintext
  even when the KEK is set. Contradicts the P0-1 "no plaintext on disk" claim.
  `crates/acp-ledger/src/lib.rs:250-255`; `crates/acp-ledger/src/spool.rs:30-40`.

### HIGH

- **A6. HTTP transport does not screen tool results.** Response screening (indirect-injection defence)
  and shared-pin checks run only on stdio; the HTTP path calls only `inspect_response`, and SSE streams
  through unscreened. `crates/acp-proxy/src/http.rs:104-121` vs `stdio.rs:61-63`.

- **A7. Argument scanning only inspects top-level strings.** Injection/secrets nested in sub-objects or
  arrays is never scanned. `crates/acp-proxy/src/dispatch.rs:498-505, 543-550`.

- **A8. MySQL `--store` cannot work.** `id TEXT PRIMARY KEY` is invalid DDL on MySQL; `migrate()` fails
  on connect. Advertised but untested. `crates/acp-cpstore/src/lib.rs:101-104`.

- **A9. No attribution.** `authorize()` discards the `Principal`; writes hardcode operator `"console"` /
  `"web-user"`. Even with real Entra, changes cannot be attributed to the admin.
  `crates/acp-server/src/main.rs:60-74, 380, 823, 881, 897, 967`.

- **A10. Break-glass is fail-open and does not reach every PEP.** Signature enforced only if a pubkey is
  pinned (`verify(None)` returns true); server writes an unsigned grant when `--break-glass-key` unset;
  only proxy and gateway watch the grant, not intercept/guard. Guide claims it "reaches every surface".
  `crates/acp-core/src/breakglass.rs:138-142`; `crates/acp-proxy/src/dispatch.rs:369-374`.

- **A11. Proxy is default-open with no policy.** No `--policy`/`--policy-dir` -> `engine = None` -> every
  `tools/call` forwarded ungoverned, no warning. `crates/acp-proxy/src/dispatch.rs:453-456`.

- **A12. KEK rotation is impossible.** No re-wrap path; rotating the KEK renders every blob permanently
  unreadable. `crates/acp-encrypt/src/lib.rs`.

### MED

- **A13. Enforcement attestation replay window.** Token signed only over `<issued_ms>.<session>`, reused
  per session; a captured `x-acp-enforcement` header works for the whole max-age window (default 30s).
  `crates/acp-core/src/attest.rs:19-27`; `crates/acp-proxy/src/dispatch.rs:275-280`.

- **A14. Gateway app identity is spoofable.** Per-app match uses caller-supplied `x-acp-app`, unverified.
  `crates/acp-gateway/src/main.rs:413-415`.

- **A15. Liveness/spike routes unauthenticated.** `POST /heartbeat/:proxy` and `/event/:kind` can be
  spoofed. `crates/acp-server/src/main.rs:293, 295, 1218-1235`.

- **A16. HSM custody is narrow.** PKCS#11 protects only ledger head signing; GRC/endpoint/break-glass/
  policy are signed with the file cp key even when the HSM is set. `crates/acp-server/src/main.rs:648, 821, 963, 1146`.

- **A17. GRC has no operator non-repudiation and no meta-audit trail.** Operator hardcoded, one shared
  key, and GRC create/status + endpoint register are not appended to the meta-ledger. `main.rs:823, 967, 942-983`.

- **A18. SSRF egress allowlist has zero call sites.** `acp_core::egress`/`is_internal_target` never
  called; interceptor dials can reach loopback/private/metadata. Refines P1-5. `crates/acp-intercept/src/main.rs:273, 312`.

- **A19. Postgres connections are plaintext.** `acp-pgstate`/`acp-pgstore` hardcode `NoTls`.
  `crates/acp-pgstate/src/lib.rs:19`; `crates/acp-pgstore/src/lib.rs:23`.

- **A20. Ephemeral ledger keys on interceptor/guard.** intercept always uses a random key; guard falls
  back to `generate()` without `--ledger-key`. `crates/acp-intercept/src/main.rs:126`; `crates/acp-guard/src/main.rs:93`.

- **A21. Backup can capture a torn WAL snapshot.** Non-atomic `fs::copy` of db/-wal/-shm; verify proves
  consistency, not currency. Refines P0-3. `crates/acp-cli/src/main.rs:907-919`.

- **A22. SIEM is offline-only.** CEF/OCSF/syslog are string builders, no live transport; only OTLP is
  live (`--otel`). `crates/acp-core/src/siem.rs`.

- **A23. Single capability for all authoring.** Policy, identity, enrolment, GRC all gate on `EditPolicy`;
  no SoD. `crates/acp-server/src/main.rs:799, 875, 889, 905, 944, 975`.

- **A24. Classifier CI gate is thin.** 8 inline samples, secret-only asserts, no PII gate, unit-test only.
  `crates/acp-core/src/classify.rs:218-233`.

### LOW

- **A25.** Meta-audit fail-open: HSM failure silently disables the audit ledger. `main.rs:177`.
- **A26.** Envelope AAD binds only `args_hash`; blob dedup leaks equality across records. `lib.rs:218,244`.
- **A27.** Purge/erase miss plaintext args in an undrained spool. `crates/acp-ledger/src/lib.rs:399-415`.
- **A28.** Oversize id-less frame is forwarded, not dropped. `crates/acp-proxy/src/dispatch.rs:438`.
- **A29.** Body-inspecting HTTPS rule with no CA is tunnelled uninspected. `crates/acp-intercept/src/main.rs:269-272`.
- **A30.** Gateway does not screen model responses; redact obligation is a no-op. `crates/acp-gateway/src/main.rs:500, 550-581`.
- **A31.** Generic OIDC `verify()` does not constrain `tid`/`typ`. `crates/acp-auth/src/lib.rs:217-274`.
- **A32.** Multi-tenant `TenantStore` unwired; shared `Client` BEGIN/COMMIT without a mutex. `crates/acp-pgstore/src/lib.rs`.
- **A33.** `ph()` placeholder rewrite assumes no `?` in a SQL literal, untested. `crates/acp-cpstore/src/lib.rs:79-97`.

---

## B. Console, CLI, packaging, deploy, CI

### HIGH

- **B1. No console UI to deactivate an agent.** `POST /agents/:id/deactivate` exists; console is
  register-only. `crates/acp-server/src/main.rs:310`.
- **B2. No console UI to transition a GRC status.** `POST /grc/:id/status` exists; console is create-only,
  and the guide claims status can be advanced "from the console". `main.rs:313`; `guide/12-grc.md:88`.
- **B3. `acp` help still advertises retired commands** as "Common commands" though they hit `retired()`.
  `crates/acp-cli/src/main.rs:85-90, 27-65`.
- **B4. compose and Helm do not deploy the console.** `deploy/docker-compose.yml`; `deploy/helm/acp/templates/*`.
- **B5. install-server auto-starts a console service the guide never mentions.** `install-server.sh:137, 211`
  vs `guide/16-setup.md:179-185`.

### MED

- **B6. Control-plane port inconsistent:** compose/helm :8080, systemd/install-server :8787.
- **B7. compose control-plane omits `--store`/`--cp-key`/`--policy-store`/`--break-glass-file`.**
- **B8. acp-guard has no service unit anywhere** (systemd/compose/helm), though built/shipped/documented.
- **B9. Shipped `deploy/systemd/*.service` drift from install-server's inline units** (and lack a console unit).
- **B10. The console is never built/tested in CI** (only release.yml, `continue-on-error: true`).

### LOW

- **B11.** install.ps1 never configures acp-intercept as a service even when `ACP_SERVER` is set.
- **B12.** install-server.sh summary still lists `enroll.json` (endpoints live in control.db).
- **B13.** `/timeline` richer than `/evidence/recent`; console uses only the latter.
- **B14.** `/admin/meta` has no console/CLI surface (confirm API-only by design).

---

## C. User guide: missing content

### HIGH

- **C1. Approvals how-to** (resolve a step-up hold) + end-to-end flow. Only management surface without a
  runbook. ch.11 or 14.
- **C2. Disaster recovery / restore.** Backup covered, restore not; `deploy/README.md` has the material. ch.14.
- **C3. Key and secret rotation** (KEK, `--cp-key`, deploy/enrol keys, agent tokens, break-glass key,
  enforcement key, JWKS/OIDC). ch.9 or 14. (KEK rotation also blocked in code, A12.)
- **C4. Browser MV3 extension and rule suggestion** (`acp intercept extension`/`suggest`) undocumented; ch.5
  covers only PAC.
- **C5. Monitoring and alerting** (liveness dead-man's-switch, spike detector, `/alerts`, `/metrics`, `--otel`). ch.14.
- **C6. index.md nav omits chapter 16** (the setup runbook).
- **C7. First-run quickstart** (`acp init`, `demo/vertical`). Top of ch.16 or new ch.0.

### MED

- **C8. Upgrade, rollback and schema migration** (migrations auto-run on connect; PEP/server skew). ch.14.
- **C9. Consolidated incident runbook** (detect->contain->investigate->recover->clear). ch.11/14.
- **C10. Policy safe-change tooling** `policy-test --diff`, `replay`, `learn`. ch.2.
- **C11. Postgres/MySQL setup how-to** (DB/role/grants; `--store` vs `--budget-pg`/`--pin-pg`; `ACP_CP_PG_URL`). ch.14/16.
- **C12. Troubleshooting/FAQ** incl. `acp diagnose`, `canary`, `verify-enforcement`, common PEP failures. ch.16.
- **C13. Architecture and threat-model diagrams** (data-flow mermaid ch.1; threat table ch.15).
- **C14. Glossary** of ~15 coined terms.
- **C15. Proxy running modes** `--shadow`, `--fail-open` (changes core safety), `--tool-hash`. ch.3.

### LOW

- **C16.** mTLS implemented only on acp-server; qualify ch.8.
- **C17.** `/healthz`/`/readyz` not on proxy/intercept; probe guidance should say so.
- **C18.** External content-scan hook `--content-scan <url>` contract not shown. ch.10.
- **C19.** install-server.sh/install.ps1 referenced but only install.sh in-tree; note hosting.

---

## D. User guide: inaccuracies (guide says X, code does Y)

- **D1.** ch.12 claims GRC status advanced "from the console"; no UI (B2).
- **D2.** ch.10 "a trained classifier"; default is signature-only, ML opt-in via `--content-ml`.
- **D3.** ch.9 / P0-1 "no plaintext on disk"; only `args_blob` encrypted (A5).
- **D4.** ch.11 break-glass "reaches every surface"; not intercept/guard (A10).
- **D5.** ch.14 conflates wired shared-state store (acp-pgstate) with unwired multi-tenant RLS (acp-pgstore).
- **D6.** ch.8 RBAC table implies all five caps gate access; only EditPolicy/BreakGlass (A2); curl examples
  omit `Authorization`.
- **D7.** "streamed to SIEM" wording; SIEM is an offline projection (A22).

---

## production-readiness.md corrections

- **P0-1 (DONE):** overstated; only `args_blob` encrypted, metadata + spool plaintext (A5).
- **P0-2 (DONE):** narrow; HSM covers only ledger signing (A16); fallback imprecise (A25).
- **P1-7 (OPEN):** add the status-change signature break (A4) and operator non-repudiation gap (A17).
- **P1-5, P0-4, P2-1/2/3/4/5/6:** OPEN, consistent with code.

---

## Suggested remediation order

1. Auth bypasses (A1, A2, A3, A15) + attribution (A9): gate ungated routes, actor from principal.
2. Integrity breaks (A4 GRC re-sign, A5 encrypt record+spool).
3. Advertised-but-broken (A8 MySQL, B3 help, B1/B2 console actions, D-inaccuracies): cheap credibility.
4. Enforcement completeness (A6, A7, A10, A11, A18).
   4b. Central violation/breach reporting (E1 producer wiring first, then E2 evidence ingestion, then
       E3 console breach panel) so the console can actually show violations and breaches.
5. Packaging/deploy consistency (B4-B10).
6. Guide lifecycle content (C1-C7).
7. Remaining MED/LOW as capacity allows.

---

## E. Central violation and breach reporting (the console cannot see PEP decisions)

> Status 2026-09-26: **E1 DONE** (proxy pushes heartbeats + non-allow decisions to the control plane;
> ingestion routes authenticated with a shared report token). **E3 partly DONE**: a console
> **Violations** panel now renders the reported deny/step-up/block feed from `GET /events/recent`.
> Remaining: E2 (full signed evidence ingest for the Evidence/Timeline views), gateway/intercept/guard
> producers, and richer breach filters. See section F for the other payloads.

This is a cross-cutting architectural gap: the enforcement points detect and record violations, but
that stream never reaches the control plane, so the console cannot report it.

**Current state (evidence):**

- Every PEP writes decision/violation evidence to its **own local ledger** (`--ledger` file):
  `crates/acp-proxy/src/dispatch.rs:638-663` (append on decision), `crates/acp-proxy/src/evidence.rs`;
  the interceptor and guard likewise open a local `acp_ledger::Ledger`
  (`crates/acp-intercept/src/main.rs:126`, `crates/acp-guard/src/main.rs:93`).
- No PEP sends anything to the server except agent verification and rule fetch. Grep for outbound
  server calls in every PEP finds only `POST /agents/verify` and `GET /intercept/rules`; there is **no**
  `POST /event`, `POST /heartbeat`, or evidence forwarding.
- The server **has the ingestion API but no producers.** `POST /event/:kind` feeds the fail-open/deny
  spike detector and `POST /heartbeat/:proxy` feeds the dead-man's-switch; the handlers exist
  (`crates/acp-server/src/main.rs:293, 295, 1218-1235`) and are commented "a proxy reports a governance
  event (e.g. fail_open, deny)", but nothing calls them.
- The console reads `/alerts`, `/liveness` and `/evidence/recent`
  (`acp-console/src/Features/Dashboard/Shared/acp_client.ky:265-267, 562-569`). Consequences:
  - `/alerts` (spikes) and `/liveness` (heartbeats) are **permanently empty** because they have no
    producers.
  - `/evidence/recent` and `/timeline` read the **server's own** ledger, which holds only control-plane
    actions (approvals, policy deploys, GRC), **not** the deny/violation records happening at the PEPs.
- Related: `POST /event` and `POST /heartbeat` are also unauthenticated (see A15), so a producer wiring
  must be designed together with authenticating those routes.

**Severity: HIGH.** For a governance product, "show me the violations and breaches" is the primary
console job, and today the console cannot answer it for the actual enforcement stream.

### E1. No producer for the alerting surface (partially built, low effort)

`POST /event/:kind` and `POST /heartbeat/:proxy` are designed for the PEPs but never called, so the
spike detector and dead-man's-switch are dead. Fix: have each PEP (starting with the proxy) POST a
periodic heartbeat and a compact event on each `deny` / `fail_open` to the control plane (behind the
existing `--registry-url`/a new `--report-url`), and authenticate the routes (A15). This lights up the
console Alerts and Liveness panels with real data.

### E2. No evidence centralisation for remote PEPs (not built, larger)

PEP decision records live in per-PEP local ledgers with no path to the control plane, so the console's
Evidence/Timeline views cannot show real enforcement decisions, denials or breaches from remote PEPs.
Options:

- **Push (recommended for workstations/remote PEPs):** add a server ingestion endpoint (e.g.
  `POST /evidence/ingest`) that accepts **signed** evidence records from a PEP (each PEP signs with a
  persistent, pinned `--ledger-key`, see A20), verifies the signature and the PEP identity, and appends
  them into a central ingested view the console reads. Batching + spool/retry so a transient outage does
  not drop evidence; idempotent by `decision_id` (the ledger already dedups by decision id).
- **Pull/scrape (for co-located PEPs):** a collector that reads each PEP ledger and folds it in. Weaker
  for workstations behind NAT.
- Whichever path: the console Evidence view should distinguish **control-plane actions** from **ingested
  PEP enforcement decisions**, and surface a **breach feed** (denies, fail-opens, kill-switch activations,
  content-firewall blocks, SSRF blocks) as a first-class panel, not just a flat recent-evidence list.

### E3. Console breach/violations panel (depends on E1/E2)

Once the data flows, add a dedicated **Violations / Breaches** view to the console (deny stream, spike
alerts, liveness gaps, break-glass events) with filters by PEP, agent, resource and time. Today the
console has only a generic "recent evidence" list sourced from the control-plane ledger.

Note: this expands the "Monitoring and alerting" guide gap (C5) — once E1/E2 land, the guide needs a
section on how violations flow from PEP to console and what each alert means.

---

## F. Workstation to control-plane telemetry contract (what else PEPs should push)

Section E covers the decision/violation stream. This section is the fuller inventory of signals a
workstation PEP (acp-proxy in front of MCP servers, acp-intercept as the forward proxy) already
computes but keeps local, and which the console needs. Each item lists what the PEP has today and the
console view it would feed. All of these share the same missing plumbing (a signed, authenticated
push channel, see E) so they should be designed as one reporting contract, not one-offs.

Priority order below is by operator value.

### F1. Step-up approvals raised in the field (HIGH, currently invisible)

The proxy stores step-up **holds in a LOCAL approval store** (`--approvals`, `acp_approvals::ApprovalStore::open`,
`crates/acp-proxy/src/main.rs:155-158`), so a hold raised at a workstation never appears in the console
Approvals inbox and cannot be resolved from the console. The inbox (`/approvals/pending`,
`/approvals/:id/approve|deny`) only sees holds in the server's own store. This is the highest-value
gap after E: a governance product's approval queue must include field step-ups. Fix: the proxy
registers each hold with the control plane and subscribes for the approve/deny decision (or the
control plane becomes the single approval store the PEP consults). Ties to A1 (gate the approve/deny
routes) and A9 (attribute the resolver).

### F2. Tool inventory and integrity status (HIGH)

Each proxy knows the MCP tool servers it fronts, the tool list it exposes, tool-binary fingerprints
(`--tool-hash`, verified at launch, `main.rs:396-402`) and tool-integrity pins with **drift detection**
(`ToolPins`/`PinResult`, `crates/acp-core/src/toolintegrity.rs`). None of this reaches the console.
A pin mismatch is a supply-chain alarm (a tool definition or binary changed under a live agent) and
belongs on the console as a first-class alert, plus a "governed tools per host, with integrity state"
view. Today pins can be shared via `--pin-pg` (a DB) but there is no console surface.

### F3. Break-glass application acknowledgement (HIGH)

When the server writes a kill-switch grant, proxy and gateway apply it locally (file watcher) but send
no acknowledgement, so the console cannot show "lockdown propagated to N of M PEPs" or which PEPs have
not yet picked it up (or are offline). Fix: PEPs report grant receipt + applied mode/scope; console
shows propagation status. (Also depends on A10: intercept/guard do not apply it at all yet.)

### F4. PEP presence, version and config posture (HIGH)

There is no inventory of which PEPs exist, their version, and their **weakened-config flags**:
`--shadow` (enforces nothing), `--fail-open` (drops fail-closed), no policy configured (A11), no CA on
the interceptor (body inspection off, A29). The console should list every PEP and flag risky posture,
so an operator can see "host X is running fail-open" rather than discovering it during an incident.
Feeds a "Fleet / enforcement points" view. Pairs with the heartbeat in E1.

### F5. Policy version actually in effect (MED)

Each PEP enforces some policy version (file or hot-reloaded store), but nothing reports which version
is live per PEP, so the console cannot tell whether the fleet has converged on the deployed policy or
some PEPs are running stale rules. Fix: include the active policy hash/version in the heartbeat;
console shows a convergence view (deployed vs in-effect per PEP).

### F6. Field-discovered / shadow-AI endpoints and coverage (MED)

The interceptor sees real egress destinations. It can report **newly observed, ungoverned** endpoints
as enrol candidates (closing discover -> enrol from live traffic instead of a manual `acp discover`
over a log), and coverage/leak signals (traffic that reached a destination off-governance). Feeds the
console AI Endpoints page ("discovered, not yet enrolled") and a coverage/unavoidability panel. The
building blocks exist (`acp_core::discovery`, `EndpointRegistry::covered_set`, `covers`).

### F7. Obligations and step-up outcomes (MED)

Counts of redactions/masks applied (redact/DLP obligations) and step-up outcomes (approved/denied/
expired) per agent/resource, so the console can show that obligations are actually being enforced, not
just present in policy. The PEP applies these during dispatch; only the local ledger sees them today.

### F8. Volume and rate metrics (MED)

Calls per agent / tool / endpoint / verdict over time, for the overview dashboard and to feed the
server-side spike detector (E1). The proxy has `/metrics` (Prometheus) locally but the console has no
per-PEP volume view; a compact rollup in the heartbeat would drive the dashboard without a Prometheus
scrape of every workstation.

### F9. PEP health and enforcement errors (LOW)

Upstream failures, TLS-interception failures honestly reported by the interceptor (cert pinning,
HTTP/2 handshake), tool-launch refusals (fingerprint mismatch), and JWKS/auth load failures. These are
logged locally; a summarised error feed on the console helps distinguish "quiet because governed" from
"quiet because broken".

### Design note

F1 to F9 plus E1/E2 are one reporting contract: a signed, authenticated, batched push from each PEP to
the control plane (idempotent by decision/hold/event id, with a local spool + retry so an outage does
not lose data), and the PEP identified the same way enforcement already verifies it (agent token /
pinned key / mTLS). Build the channel once; F1 (approvals) and F2 (tool integrity) are the two that
most change what the console can do, so they are the natural first payloads after the E1 heartbeat and
deny/fail-open events.
