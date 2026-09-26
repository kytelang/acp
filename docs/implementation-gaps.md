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
5. Packaging/deploy consistency (B4-B10).
6. Guide lifecycle content (C1-C7).
7. Remaining MED/LOW as capacity allows.
