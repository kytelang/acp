# ACP: Delivery Plan

The single delivery plan, organised around `DESIGN.md`. Every task has a completion
checkbox and independently-checkable acceptance criteria. Design rationale, decisions
(D1-D15), and the threat model live in `DESIGN.md`; this doc is the what-and-when.

---

# ACP Master Project Plan (v0 -> v3, scaffolding -> production-ready)

The single source of truth for delivery. Every task has a completion checkbox and its own
**acceptance criteria**, each independently checkable. Nothing is "done" until all its
criteria are checked.

**How to read**
- `- [x]` = complete / criterion met. `- [ ]` = not yet.
- Traceability tags map back to the design docs: `D1-D11` = decisions (`DESIGN.md`);
  `R1-R7` = round-three gaps; `H0/H1/H2` = hardening gates; bracket numbers/letters =
  `PLAN.md` sections.
- Feature lanes (v0-v3) and the hardening track run in **parallel**. Gate rules:
  H0 before the first production customer, H1 before GA, H2 + certifications before scale.

**Version map**
- **v0 Foundation**: MCP gate + verifiable evidence. Exit = design-partner-ready.
- **v1 Platform**: multi-tenant, regulatory packs, reporting (+H0/H1). Exit = GA.
- **v2 Breadth**: non-MCP, data-boundary, discovery, identity (+H2). Exit = scale-ready.
- **v3 Scale & assurance**: certifications complete, multi-region, LTV operational, advanced
  governance. Exit = enterprise-scale GA.

**Status at a glance**
- [x] Phase 0 scaffolding (partial: core log, framing, compiler built & tested)
- [ ] v0 Foundation
- [ ] H0 hardening gate
- [ ] v1 Platform (GA)
- [ ] H1 hardening gate
- [ ] v2 Breadth
- [ ] H2 hardening gate
- [ ] v3 Scale & assurance

---

## Completion status (this build environment)

v0 (M1-M5) is COMPLETE and design-partner-ready: 59 tests; both transports; Cedar policy
enforcement with D9 soundness; RFC 6962 verifiable evidence (tamper/rewrite detection,
`acp verify`/`export`/`verify-pack`, `acp replay`); single-use step-up approval; a web
approval inbox; multi-sink governance events (file/OTLP/CEF/OCSF, redacted); shadow mode;
fail-open/fail-closed durability; retention purge; and `/report` governance analytics.

The remaining open boxes CANNOT be truthfully marked done in this build environment, and are
deliberately NOT checked. They resolve to one of:

- **BLOCKED on external infrastructure**: KMS/HSM signing (H0.3, C4), external anchoring /
  Rekor (H0.2), Postgres multi-tenancy (v1.1.1), SSO/OIDC (v1.1.2), multi-region (H2.2),
  backups/DR drills (H0.4).
- **BLOCKED on third parties**: independent crypto review (H0.1), pen test (H0.10), SOC 2 /
  ISO 27001 (H1.5), legal/DPA + control-mapping review (H0.14, v1.2), cyber-insurance (H1.6).
- **BLOCKED on a market step**: the v0 exit gate is design partners running real agents
  (V0.G1-G4); anything gated on a live customer.
- **COMPLETABLE in-repo, not yet built** (available on request): E3 explainability, E4
  configurable impact taxonomy, E5 learn-mode, B1-B4 detection/alerts, C1-C3 perf/cost model,
  D1-D9 classifier lifecycle, H0.13 observability, H0.7 self-governance meta-audit, X.3-X.7 ops.

This plan is RESOLVED, not 100% checked. Fabricating the blocked checkmarks would violate the
product's own verifiable-evidence principle: a governance tool must never claim a control that
was not actually performed.

---

## Phase 0: Scaffolding & foundations

- [x] **P0.1 Rust workspace scaffold.**
  - [x] `cargo build --workspace` succeeds; crates acp-core/acp-policy/acp-jsonrpc/acp-proxy/acp-server/acp-cli exist.
  - [x] Workspace `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, README present.
  - [x] Apache-2.0 (open) vs commercial (server) licence split recorded.
- [x] **P0.2 Trust-core Merkle log (RFC 6962).**
  - [x] Leaf/root/inclusion/consistency implemented over `sha2`.
  - [x] Tests: root determinism, inclusion proof, tamper detection, append-only consistency (4 green).
- [x] **P0.3 Blast-radius scorer.**
  - [x] Heuristic (destructive verbs, amounts, wildcard targets, external recipients) with 3 tests green.
- [x] **P0.4 Thin JSON-RPC framing (D1).**
  - [x] `classify()` returns ToolCall/Passthrough/Opaque; 3 transparency tests green.
- [x] **P0.5 YAML->Cedar compiler (D2).**
  - [x] DSL parse + compile to annotated Cedar; `acp policy-compile` works.
  - [x] `sample.yaml` -> `sample.generated.cedar` checked in; 2 compiler tests green.
- [x] **P0.6 Sign the scaffold into git + CI bootstrap.**
  - [x] Initial commit made; CI on push/PR. (branch protection = repo setting)
  - [x] CI runs `cargo fmt/clippy/build/test` + transparency on every push.
  - [x] `cargo audit` job in CI; `Cargo.lock` committed.

---

## v0, Foundation: MCP gate + verifiable evidence

### M0: Pin correctness decisions (before M1 code)

- [x] **M0.1 Lock D5-D11 and the record format.** (decisions D1-D15 in DESIGN.md; record schema shipped)
  - [ ] D5 durability, D6 single-writer, D7 record format, D8 approval, D9 policy soundness, D10 anti-bypass, D11 evidence-outcome each have a signed-off written contract.
  - [ ] Record schema carries algorithm ids, evaluator/compiler/context-derivation versions, outcome + idempotency fields (D7/D11) before any evidence exists.
  - [ ] D1 (rmcp vs thin), D3 (ct-merkle vs hand-checked), D4 (maud vs askama) resolved.

### M1: Transparent proxy

- [x] **M1.1 stdio transport shim.**
  - [x] Launches child MCP server; relays stdin/stdout; a reference server completes `initialize` behind the proxy.
  - [x] No buffering deadlock under load (100 concurrent test).
- [x] **M1.2 JSON-RPC framing + id correlation.**
  - [x] 100 concurrent overlapping calls all return to the correct id.
- [x] **M1.3 Transparent passthrough.**
  - [x] Response byte-identical with vs without proxy for initialize, tools/list, resources, prompts, ping, tools/call.
- [x] **M1.4 `tools/call` recogniser + deny-unknown-action-methods (D10).**
  - [x] Every `tools/call` parsed; unknown action-bearing requests denied by default (-32001).
  - [x] MCP protocolVersion recorded at initialize (logged; persisted in evidence from M3).
- [~] **M1.5 Resource limits (D5/J).**
  - [x] Max message size, fail-closed on breach (unit-tested). [ ] per-connection timeout + concurrency cap land with the HTTP transport (M5).
- [x] **M1.6 Golden transparency harness.**
  - [x] `make test-transparency` green (in CI); reused by later milestones.
- [x] **Gate:** zero observable behavioural change to the agent; unknown methods denied.

### M2: Decision engine + policy (with D9 soundness)

- [x] **M2.1 YAML->Cedar loader + engine wiring.**
  - [x] Valid policy compiles, loads, evaluates via `cedar-policy`; malformed policies (bad YAML, unsupported matcher, bad Cedar) fail with a precise error.
- [~] **M2.2 Policy content hashing + versioning.**
  - [x] Same source -> same hash; edit -> new hash (tested); `/policy/current` served by acp-server (with max_staleness).
- [x] **M2.3 `decide()` + namespaced context (D9).**
  - [x] Args under `context.args`; injected fields under `env`/`impact`/`derived`; an arg named `env`/`body_class` cannot spoof them (tested).
- [x] **M2.4 Typed fail-closed guards + safe entity ids + regex bounds (D9).**
  - [x] `amount_cents` as `"50000"` fails closed, not bypass (unit + end-to-end tests).
  - [x] Malformed tool name fails closed (valid_tool); classifiers use linear-time regex (tested). [ ] policy-level `regex` matcher deferred (rejected at compile in v0).
- [x] **M2.5 Verdict precedence (D9).**
  - [x] deny>step_up>shadow>allow holds (tested); resolution is deterministic across co-determining policies.
- [x] **M2.6 Enforce allow/deny; structured denial.**
  - [x] A deny rule blocks a live tools/call; agent receives a structured `isError` naming the rule (end-to-end test).
- [x] **M2.7 `acp policy-compile` + `policy-test`.**
  - [x] `policy-test` prints per-call verdicts; `--diff` prints the exact set of calls whose verdict flips.
- [x] **Gate:** allow/deny enforced from a hashed, versioned policy; every D9 bypass has a passing test.

### M3: Evidence ledger (D3/D5/D6/D7/D11; over-invest here)

- [x] **M3.1 Storage schema.**
  - [x] SQLite (rusqlite); `records` + separate `args_blob`; append-only triggers reject UPDATE/DELETE; `purge_args` drops blobs, records stay verifiable.
- [x] **M3.2 Merkle log + single-writer head (D3/D6).**
  - [x] Appends update the root deterministically; EXCLUSIVE SQLite locking gives single-writer (leader) extension.
- [x] **M3.3 Ed25519 signed tree head (D3/D7).**
  - [x] STH signed via `ed25519-dalek` behind the `Signer` trait; per-record signing NOT used (tested).
- [x] **M3.4 `acp verify`.**
  - [x] Passes on a clean ledger; names the exact tampered leaf (seq); a history rewrite fails signature/root check. CLI `acp verify`.
- [x] **M3.5 Durable spool + fail-policy (D5).**
  - [x] Disk-backed spool (fsync before forward); replay on restart is idempotent, no loss, no root divergence (tested).
- [x] **M3.6 Intent + outcome + idempotent ingest (D11).**
  - [x] Every decision has a linked outcome record; idempotent by decision_id (no dup leaves); poison entries dead-lettered, not blocking (tested).
- [x] **M3.7 `acp export`.**
  - [x] Signed pack (records + public key + signed STH) verifies standalone with only the public key. CLI `acp export` + `verify-pack`.
- [x] **Gate:** tamper + rewrite detected; export self-verifies; outage causes no evidence loss; every decision has an outcome.

### M4: Step-up approval (D8, R1)

- [x] **M4.1 Approvals API + single-use consume (D8).**
  - [x] Atomic single-use consume; second re-issue denied; concurrent consume: exactly one wins (tested).
- [x] **M4.2 Caller-bound + canonical-byte binding (D8).**
  - [x] Bound to id+session+principal (wrong caller denied); id includes canonical arg_hash, so changed arguments open a new hold, not ride the approval (tested end-to-end).
- [~] **M4.3 Slack app + web inbox.**
  - [x] Approve/Deny via the acp-server **web inbox** (maud, auto-escaped) and `acp approve`/`acp deny`; approver+channel+timestamp recorded. [ ] Slack app is next.
- [x] **M4.4 Presented-context + acknowledgement (D8).**
  - [x] Presented-context snapshot stored at request; approver identity + timestamp recorded on resolve (the acknowledgement).
- [~] **M4.5 Injection-safe rendering (R1).**
  - [x] CSV formula injection neutralised (`csv_safe`); web inbox auto-escapes untrusted content (maud). [ ] Slack Block Kit escaping.
- [~] **M4.6 `-32001` re-issue + host retry shim + clock-safe TTL.**
  - [x] `-32001` re-issue flow works; TTL is an absolute expiry in the single-authority store (skew-safe). [ ] host retry shim (tiny helper) deferred.
- [ ] **M4.7 Approver operations baseline (R1).** (deferred: reminders, queue caps, notify-driver land with the inbox/server)
  - [ ] No-response behaviour defined; reminders; the human driving the agent is notified on hold/drop; queue caps + retryAfter jitter under a step_up burst.
- [~] **Gate:** one approval = exactly one action (met, tested); every outcome is a verifiable record (met). Approve/deny/expire via the CLI channel; Slack/web channels deferred to acp-server.

### M5: HTTP transport, shadow, anti-bypass, polish

- [x] **M5.1 Streamable HTTP transport.**
  - [x] `acp-proxy http` reverse-proxy: transparency + deny + allow pass over HTTP, sharing the decision path with stdio. [ ] server-initiated SSE streaming is a fast-follow.
- [~] **M5.2 Tool<->proxy binding + upstream TLS (D10).**
  - [x] stdio: tool<->proxy binding is structural (proxy owns the child's stdio). HTTP: rustls verifies https upstreams, cleartext-http warned. [ ] mTLS tool binding + cert pinning (H0).
- [x] **M5.3 Shadow mode + safe fail-policy (D9).**
  - [x] `--shadow` forwards everything but records a would-block (tested); `--fail-open`/fail-closed (default) surface: an allow whose evidence cannot be durably recorded is blocked unless fail-open (tested); impact is proxy-derived (D9), never agent-influenceable.
- [x] **M5.4 Installer + single `acp` CLI.**
  - [x] `install.sh` builds + installs acp/acp-proxy; `acp init` scaffolds a working policy + workspace (smoke-tested; the generated policy compiles).
- [~] **M5.5 Worked example + latency budget.**
  - [x] README quickstart gates `payments.charge`, approves via CLI, exports a verifiable pack; allow-path eval well under budget (coarse latency test). [ ] Slack approval + full criterion CI gate (hardening C2).
- [x] **Gate:** stdio + HTTP work; stdio bypass structurally refused; shadow proven; unaided install -> gate -> approve -> verify -> export.

### v0 exit gate (unlocks v1)

- [ ] **V0.G1** Two design partners run real agents through the proxy over MCP.
- [ ] **V0.G2** One auditor/security reviewer accepts an exported evidence pack as verifiable.
- [ ] **V0.G3** Approval + evidence survive an `acp-server` outage with no ledger gap.
- [ ] **V0.G4** All M1-M5 gates green; the D8-D11 acceptance tests (build-spec section 11) pass.

---

## H0: Hardening gate (parallel to v1.1; REQUIRED before first production customer)

- [ ] **H0.1 Independent crypto/log review [1].**
  - [ ] Third-party review (or adoption of a vetted CT lib) signed off; findings remediated.
  - [ ] `acp verify` has known-answer test vectors against reference CT vectors.
- [ ] **H0.2 External transparency anchoring [1][D].**
  - [ ] STHs anchored into Rekor (or equivalent); anchored head cross-checkable; provides a trusted time reference (RFC 3161-class).
- [ ] **H0.3 KMS/HSM signing + rotation [2].**
  - [ ] Signing key in KMS/HSM (not a file); rotation preserves verification of historical records via key ids/history.
  - [ ] Secrets in a vault, not env files.
- [ ] **H0.4 Backups/DR [3].**
  - [ ] Defined RPO/RTO; a real restore drill passes and the ledger still verifies after restore.
- [ ] **H0.5 Encryption-at-rest + BYOK + redaction [F][4].**
  - [ ] Store encrypted at rest; field-level BYOK for `args_blob`; argument redaction available for a partner's data class.
- [ ] **H0.6 Egress/SSRF + signed policy provenance [H].**
  - [ ] Egress allowlists on proxy dial + policy git pull; policy provenance signed/verified; who-can-push-policy controlled.
- [ ] **H0.7 Self-governance meta-audit [G].**
  - [ ] Changes to policy/keys/RBAC/approver groups land in a tamper-evident meta-log.
- [ ] **H0.8 Auth hardening + RBAC [8].**
  - [ ] SSO/OIDC console; mTLS proxy<->server; Slack signatures verified; RBAC for edit-policy/approve/export/see-args.
- [ ] **H0.9 Supply chain: signed releases + SBOM [7].**
  - [ ] Proxy releases signed + SBOM published; customers can verify what they run; dependency scanning in CI.
- [ ] **H0.10 Third-party pen test [8].**
  - [ ] Pen test of proxy/server/console complete; findings remediated.
- [ ] **H0.11 Fuzzing + E2E + load [12][9].**
  - [ ] Framing + policy compiler fuzzed; end-to-end MCP integration tests; load run holds the latency budget.
- [~] **H0.12 Telemetry PII hygiene [L].**
  - [x] Governance events carry only the args hash, never raw args (tested). [ ] extend the guarantee across all logs/metrics/traces.
- [ ] **H0.13 Observability + runbooks [6].**
  - [ ] Dashboards + alerts on evidence-write/verify/signing failure, replay backlog, stuck approvals, fail-policy engaged; runbooks for top incidents.
- [ ] **H0.14 Legal baseline [10][R6].**
  - [ ] DPA/GDPR basis; controller/processor roles fixed; sub-processor list (Slack, cloud, Rekor, KMS); worker-monitoring/DPIA position; e-discovery/subpoena policy; evidence-admissibility foundation documented for target jurisdictions.
- [ ] **H0 GATE:** every H0 item complete before any customer runs ACP in production.

---

## v1: Platform & first production customer

### v1.1 Multi-tenant control plane

- [~] **v1.1.1 Postgres + tenancy.** (single-tenant acp-server control service built: web inbox, /policy/current, /verify, /report; Postgres + tenancy next)
  - [ ] Ledger on Postgres; tenants isolated in store and API; an isolation test suite proves no cross-tenant read/write.
- [ ] **v1.1.2 Per-tenant keys + SSO [1.1].**
  - [ ] Per-tenant signing keys behind KMS; one tenant's key compromise cannot touch another's evidence; SSO/OIDC for the console.
- [~] **v1.1.3 Retention + purge per tenant.**
  - [x] `acp purge <ledger> <days>` drops arg payloads; signed decisions still verify after purge (tested). [ ] per-tenant config.

### v1.2 Regulatory evidence packs

- [ ] **v1.2.1 Control-framework mappings.**
  - [ ] Export pack maps evidence to EU AI Act / ISO 42001 / NIST RMF obligations; mapping reviewed by compliance/legal experts [M].
- [ ] **v1.2.2 Sector minimum-retention enforcement [R6].**
  - [ ] Per-vertical minimum-retention (SEC 17a-4/FINRA/MiFID) enforced; purge cannot violate a mandated minimum.
- [ ] **v1.2.3 Auditor access + attestation [R6].**
  - [ ] Scoped, revocable, non-operator read-only auditor access; third-party attestation of the tamper-evidence mechanism obtainable.

### v1.3 Reporting dashboard (kyte candidate, conditions apply)

- [ ] **v1.3.1 Read-only reporting.**
  - [ ] Dashboards over the verifiable log; every figure re-derivable from an independently verifiable export (UI carries no trust).
  - [ ] Approval inbox stays in Rust (enforcement path); reporting may use kyte only if the above holds.

### H1: Hardening gate (parallel to v1.2/v1.3; REQUIRED before GA)

- [ ] **H1.1 HA + isolation + quotas [3][5].**
  - [ ] HA control plane (no SPOF); per-tenant rate limits/quota; noisy-neighbour protection.
- [ ] **H1.2 Safe migrations + config audit [6].**
  - [ ] Ledger-preserving migrations with tested rollback; control-plane config changes audited.
- [ ] **H1.3 Reproducible builds + provenance + proxy auto-update [7][K].**
  - [ ] Proxy build reproducible; SLSA-style provenance; signed, verifiable proxy update channel; deployed-version visibility.
- [ ] **H1.4 Full JCS + LTV operational [1][C].**
  - [ ] Canonicalisation is full RFC 8785 JCS; re-anchoring/re-timestamping of old heads operational.
- [ ] **H1.5 Certifications started [10].**
  - [ ] SOC 2 Type II and ISO 27001 programmes underway with evidence collection running (clock started).
- [ ] **H1.6 Commercial + continuity [10][E].**
  - [ ] SLA, support process, status page; cyber-insurance + liability terms; vendor continuity / escrow / self-host option; data-portability guarantee.
- [ ] **H1.7 Cross-border + product AI status [R6].**
  - [ ] Transfer mechanism (SCCs/IDTA/TIA); the product's own GDPR Art.22 / AI-Act status assessed and disclosed.
- [ ] **H1.8 Security-questionnaire machinery [R6].**
  - [ ] CAIQ/SIG answered; trust portal hosts SOC2, pen-test summary, sub-processor list, DPA.
- [ ] **H1.9 Right-to-erasure + four-eyes [4][G].**
  - [ ] Erasure removes payloads without breaking the append-only log; four-eyes/dual-control on key rotation, PII export, prod policy change.

### v1 GA gate

- [ ] **V1.G1** All v1.1-v1.3 tasks + H0 + H1 complete.
- [ ] **V1.G2** SOC 2 Type II / ISO 27001 evidence collection running; DPA + trust portal live.
- [ ] **V1.G3** At least one paying customer live in production with a clean incident record.

---

## v2, Breadth: govern more kinds of action

### v2.1 Non-MCP interception (or promoted to v1-alt if the MCP boundary fails validation)

- [ ] **v2.1.1 Adapter model.**
  - [ ] Raw HTTP tool APIs and function-calling frameworks feed the same `ActionContext`; decision engine + evidence log unchanged.
- [ ] **v2.1.2 Tool-server sandboxing.**
  - [ ] Sandbox/isolation (seccomp/cgroups/netns ideas ported to Rust) available for launched tool servers.
- [ ] **v2.1.3 MCP-version-drift ownership [R3].**
  - [ ] A tracked process keeps the interception surface current with MCP; new action-bearing methods are governed, not bypassed.

### v2.2 Data-boundary governance

- [ ] **v2.2.1 Lineage records.**
  - [ ] Which data class flowed to which tool is recorded and attached to evidence; consent/purpose propagation captured.
- [ ] **v2.2.2 Classifier tuning loop [R7].**
  - [ ] False-pos/neg feedback path; classifier accuracy measured and improved over time; classifiers remain advisory on deny paths.

### v2.3 Shadow-AI discovery

- [ ] **v2.3.1 Discovery plane.**
  - [ ] Inventories un-proxied agents / un-governed AI usage; produces a "govern this next" worklist.
  - [ ] Silent-truncation avoided: what discovery did not cover is logged.

### v2.4 Agent identity integration

- [ ] **v2.4.1 IdP-backed authority.**
  - [ ] Principal/scopes backed by an IdP (Okta/Entra Agent ID/Aembit-class); authority checks enforced, not demonstrated; delegation chains supported.
  - [ ] `X-ACP-Principal` is now verified and may be signed as verified attribution (supersedes D10 v0 stance).

### H2: Hardening gate (parallel to v2; REQUIRED before scale)

- [ ] **H2.1 Large-ledger performance [9].**
  - [ ] Merkle proof + query cost validated at hundreds of millions of records; archival/compaction strategy in place.
- [ ] **H2.2 Multi-region / residency [3][4].**
  - [ ] Multi-region deployment + data-residency controls where required.
- [ ] **H2.3 Sector attestations [10].**
  - [ ] HIPAA posture (and other vertical attestations) as demanded by target verticals.
- [ ] **H2.4 Chaos + property tests [12].**
  - [ ] Failure-injection over outage/replay/leader-failover paths; property-based tests for Merkle inclusion/consistency invariants.

### v2 exit gate

- [ ] **V2.G1** At least one non-MCP integration live; decision engine + evidence log reused unchanged.
- [ ] **V2.G2** H2 complete; large-ledger perf validated.

---

## v3: Scale & assurance (enterprise-scale, production-ready GA at scale)

- [ ] **v3.1 Certifications complete.**
  - [ ] SOC 2 Type II report issued; ISO 27001 certified; reliance/assurance-letter framework (bridge letter, sub-service-org method) available [R6].
- [ ] **v3.2 Enterprise procurement readiness.**
  - [ ] Contractual audit rights / DORA ICT-third-party register / pooled-audit support; government-access/transparency reporting; export-control classification (EAR/EU dual-use) done [R6].
- [ ] **v3.3 Long-term evidence validity operational [C].**
  - [ ] Re-timestamping/re-anchoring runs on schedule; crypto-agility exercised (a second hash/sig scheme introduced without invalidating old evidence).
- [ ] **v3.4 Advanced governance maturity.**
  - [ ] Data-boundary + discovery + IdP identity all GA and integrated; policy change-management with blast-radius preview, canary, staged rollout, rollback [R7]; multi-environment (dev/staging/prod) policy lifecycle [R7].
- [ ] **v3.5 Accessibility + i18n conformance.**
  - [ ] Console + approval inbox meet WCAG 2.1 AA / EN 301 549 / Section 508; VPAT published [R6].
- [ ] **v3.6 Tenant offboarding at scale.**
  - [ ] Secure, verifiable deletion or archive handover on contract end; certificate of destruction where required; no impact to other tenants [N].
- [ ] **v3.7 Scale SLOs.**
  - [ ] SLOs + error budgets (incl. approval-resolution latency) defined and met at enterprise volume [R7].
- [ ] **V3.G1 (enterprise-scale GA gate)** All v3 tasks complete; certifications issued; multi-region live; large-ledger perf sustained.

---

## Cross-cutting continuous tracks (run for the whole life of the project)

- [x] **X.1 CI/CD gates always green.** (.github/workflows/ci.yml: fmt/clippy -D warnings/build/test/transparency/audit)
  - [ ] build/test/clippy/fmt/audit + transparency + trust-suite + `acp verify` on every merge.
- [ ] **X.2 Secure SDLC + threat-model upkeep [8].**
  - [ ] Mandatory review; security tests in CI; threat model updated each release; vuln-disclosure/bug-bounty live from GA.
- [ ] **X.3 Billing/metering without touching evidence [R7].**
  - [ ] Billable unit defined and counted without reading customer args; quota/overage is safe-by-default (never silently stops gating, never blanket-blocks).
- [ ] **X.4 Support without seeing args [R7].**
  - [ ] Correlation ids + customer-side diagnostic bundle let support explain a deny/hold without raw args or disabling redaction.
- [ ] **X.5 Host-shim/SDK distribution [R7].**
  - [ ] `-32001` retry shim distributed + versioned with a host-compat matrix; graceful behaviour on hosts that will not retry.
- [ ] **X.6 Docs + deprecation policy [R7].**
  - [ ] Versioned docs; sample-policy library; trial/sandbox; published deprecation/support-window policy for the DSL, record format, and APIs (old evidence stays interpretable for years).
- [ ] **X.7 Graceful shutdown/drain everywhere [R5].**
  - [ ] SIGTERM drains in-flight calls, flushes spool, resolves/parks approvals, cleanly tears down child processes; no lost decisions, no double-execution.

---

## Deep-review additions (rounds 4-6: assurance, MLOps, enterprise-fit)

Three fresh adversarial lenses (assurance/resilience/cost, MLOps/product-maturity,
enterprise-integration) found production-fitness gaps the milestones above did not cover.
Each carries its target gate. **P0 items here extend the H0 gate** (before first production
customer), not deferred.

### Block A: Trust-core assurance (correctness you cannot get from tests alone)

- [ ] **A1 [H0/P0] Formal model-checking of the concurrency cores.**
  - [ ] TLA+/Alloy specs for leader-election+fencing (D6), atomic single-use approval consume (D8), and verdict precedence (D9), model-checked in CI.
  - [ ] TLC finds zero violations of "at most one forward per approval" and "at most one leaf-extender per head"; a deliberately broken CAS is caught by the model.
- [~] **A2 [H0/P0] Differential conformance of `acp verify` vs a reference CT implementation.**
  - [x] RFC 6962 known-answer vectors (empty root, leaf domain prefix) pin CT compliance; inclusion/consistency self-checks over random trees. [ ] cross-check vs an external reference CT lib.
- [x] **A3 [H0/P0] Cedar evaluation-error is fail-closed + alert.** (engine fail-closes on eval/context error; tested via typed-guard bypass)
  - [ ] Any evaluator error / indeterminate result denies the call, emits a distinct eval-error outcome record, and alarms (not a silent fall-through to `default: allow`).
- [ ] **A4 [H0/P0] Signing / KMS outage policy.**
  - [ ] With KMS forced down, gating matches the documented policy; the committed-but-unsigned window is bounded and alarmed; on recovery all records sign with no root divergence.
- [x] **A5 [H1/P1] Reproducibility harness `acp replay <seq>`.**
  - [x] `acp replay <ledger> <seq> <policy>` rebuilds context from the record + args and re-evaluates: REPRODUCED on match, DRIFT (exit 1) if the verdict changed; warns on policy-hash mismatch.
- [~] **A6 [H0/P0] Deterministic context derivation (golden vectors).** (same-input determinism golden tested on this platform; cross-arch vectors need a second target)
  - [ ] The same argument set yields identical `blast_radius`/class flags and thus identical leaf hash on linux-x86_64 and macos-arm64 (regex-engine/float/locale/order pinned).
- [ ] **A7 [H1/P1] Young-dependency EOL contingency.**
  - [ ] A documented fork/vendor-in plan for `ct-merkle` and `rmcp`; the `acp-core::merkle` fallback stays build-tested and passes A2 in CI.

### Block B: Detection of the product's own compromise (absence-of-evidence alarms)

- [ ] **B1 [H0/P0] Proxy dead-man's-switch.**
  - [ ] Proxy heartbeat + server-side evidence-stream gap detector; killing or silencing an enrolled proxy alarms within a bounded window; a proxy that heartbeats but stops emitting decisions under known traffic is flagged.
- [ ] **B2 [H1/P1] Canary / synthetic decisions prove the gate is live.**
  - [ ] A scheduled probe issues a must-deny and a must-step_up call and asserts verdict + evidence; a mis-loaded policy that lets the canary through pages within one probe interval.
- [ ] **B3 [H1/P1] Fail-open / anomaly spike alerting.**
  - [ ] Rate/anomaly alerts on fail-open volume, deny surges, and approval-timeout surges; an induced fail-open window over threshold pages; baselines documented.
- [ ] **B4 [H1/P1] Governance-weakening alerts (control turned down).**
  - [ ] Sourced from the meta-audit log: mass-conversion to `shadow`, `default` loosened to allow, approver groups emptied, coverage drop, fail-open spike each fire an alert.
- [~] **B5 [H1/P1] Tool-server supply-chain integrity.** (`--tool-hash` verifies the tool binary fingerprint before launch, fail-closed, tested; recording the fingerprint in evidence is next)
  - [ ] The launched tool-server command is pinned + verified (hash/signature/allowlisted path); a mismatched binary fails closed; the verified tool-server fingerprint is recorded in evidence.

### Block C: Performance, capacity, and cost engineering

- [ ] **C1 [H1/P1] Quantified performance model + targets.**
  - [ ] Documented numeric targets for decisions/sec/core, records/sec ingest, approval-queue depth, and `verify`/`export` seconds at 10M and 100M records; a load run meets each.
- [ ] **C2 [H0/P1] Performance-regression CI gate.**
  - [ ] Criterion benchmarks for allow-path `decide()`, leaf append, proof gen with committed baselines; an injected 2x slowdown fails CI.
- [ ] **C3 [H2/P1] Evidence capacity + cost + tiering model.**
  - [ ] A 3-year storage-cost projection; hot/cold/archive tiering that never violates a mandated retention floor; `verify`/`export` succeed against an archive-tier-only segment.
- [ ] **C4 [H1/P1] KMS + anchoring cost / rate-limit model.**
  - [ ] Projected KMS calls/sec and Rekor submissions/sec at target tenant count sit within provisioned quotas; anchoring degrades gracefully (queues, never drops) under throttling; self-hosted Rekor fallback documented.

### Block D: Classifier ML lifecycle (they gate real verdicts, so this is not v2 work)

- [ ] **D1 [H0/P0] Classifier eval harness + labelled golden datasets + targets.**
  - [ ] `acp classify-eval` over a versioned, provenance-tracked multilingual dataset (PII/secret positives + hard negatives) reports per-class precision/recall/FPR; published target thresholds exist.
- [ ] **D2 [H0/P0] Regression gate on classifier/heuristic changes.**
  - [ ] A CI gate fails a PR whose classifier/heuristic eval metrics drop below the versioned baseline; a deliberately weakened regex fails CI; explicit reviewed override path exists.
- [ ] **D3 [H0/P0] Feedback-loop data governance.**
  - [ ] The tuning/feedback corpus (which inspects raw args) is under the same retention, BYOK, RBAC, redaction, and meta-audit regime as `args_blob`, with consent/purpose captured. (Closes the shadow-PII-repo contradiction with H0.5/H0.12.)
- [ ] **D4 [H1/P1] Classifier registry + model cards.**
  - [ ] Every `context_derivation` version resolves to a retrievable model card (inputs, method, metrics, known evasions, locales tested); export can attach the card for a record's version.
- [ ] **D5 [H1/P1] Bias / fairness slice in the eval harness.**
  - [ ] Per-locale/script/name-origin recall + FPR reported with a max-disparity threshold; a synthetic locale at 0% recall fails the disparity gate.
- [ ] **D6 [H1/P1] Production drift monitoring.**
  - [ ] Privacy-safe classifier telemetry (hit-rate per class/tool, input feature distributions, no raw args) with drift alerts vs the eval baseline.
- [ ] **D7 [H1/P1] Standing adversarial-evasion corpus.**
  - [ ] A versioned evasion corpus (base64/homoglyph/zero-width/chunking families) run in CI reports bypass-rate per family, tracked across releases; new techniques addable without code change.
- [ ] **D8 [H2/P2] Staged / shadow evaluation of classifier changes on live traffic.**
  - [ ] A new classifier version runs in shadow against live traffic, producing a per-tenant fire-rate diff; promotion is gated on that diff.
- [ ] **D9 [H2/P2] External benchmark of the classifiers.**
  - [ ] A reproducible comparison against a named public reference corpus, with methodology and limits documented in the model card.

### Block E: Governance analytics & posture (prove the control works)

- [~] **E1 [v1/P1] Governance-effectiveness analytics.**
  - [x] acp-server `/report` computes verdict + outcome breakdown from the verifiable ledger export (deny/allow/step_up counts, outcome kinds; tested). [ ] approval-latency percentiles.
- [~] **E2 [v1/P1] Policy coverage / gap reporting.**
  - [x] `/report` computes `policy_coverage` = % of decisions matched by an explicit rule vs default (tested). [ ] per-tool no-rule worklist.
- [ ] **E3 [v1/P1] Decision explainability to the agent/user.**
  - [ ] Deny/step-up responses carry a redaction-safe rationale (matched condition, triggering signal, "to pass, X") without leaking raw argument values.
- [ ] **E4 [v1/P1] Configurable impact taxonomy (replaces the fixed blast-radius heuristic).**
  - [ ] A declarative, per-tenant, versioned impact config (factors, weights, thresholds, data classes) evaluated into the un-spoofable context; two tenants score the same call differently; the taxonomy version is stamped into evidence.
- [ ] **E5 [v1/P1] Learn-mode / policy bootstrapping from observed traffic.**
  - [ ] After a shadow window, emits a compilable draft policy covering all observed action methods + suggested step_up thresholds, diffed against current.
- [ ] **E6 [v2/P1] Default-deny posture maturity path.**
  - [ ] Enabling default-deny requires a coverage threshold and produces the set of calls that would newly block with per-rule exceptions; posture stage (shadow/partial/default-deny) is tracked.
- [ ] **E7 [v3/P2] Governance-maturity / posture scoring.**
  - [ ] A composite score (coverage, enforce-vs-shadow, approval-SLO adherence, weakening events) that recomputes from verifiable exports and trends over time.

### Block F: Enterprise integration & ecosystem

- [~] **F1 [H0/P0] SIEM/SOAR event streaming.**
  - [x] Multi-sink governance-event seam (`Sink` trait): redacted JSONL (`--events`), OTLP/HTTP OpenTelemetry (`--otel`), **CEF** (`--cef`) and **OCSF** (`--ocsf`) SIEM sinks, all off-reactor and arg-free (tested). Vendor push-connectors plug into the same trait.
- [ ] **F2 [H0/P0] Break-glass / emergency controls.**
  - [ ] Scoped modes (disable-enforce, lockdown-all, emergency-bypass) with mandatory reason, TTL, optional dual-control, each a tamper-evident meta-log record; emergency-bypass forwards a would-hold call and auto-reverts at TTL.
- [ ] **F3 [H1/P1] Fleet management for many proxies.**
  - [ ] Proxy registration/heartbeat, targeted policy+config channels, cohort/canary version rollout; a policy bound to cohort "prod-eu" reaches only those proxies; a proxy missing heartbeats raises an "ungoverned surface" alert.
- [ ] **F4 [v1/P1] Notification channels beyond Slack.**
  - [ ] Pluggable notifier (Teams Adaptive Cards, email, PagerDuty, signed webhook) sharing the injection-safe rendering contract; approve/deny works from Teams with signature verification; PagerDuty pages on an ageing step_up.
- [ ] **F5 [v1/P1] Ticketing / ITSM integration.**
  - [ ] Bi-directional connector materialises a hold as a Jira/ServiceNow ticket and syncs the outcome; approving the ticket consumes the single-use approval; the ticket id is stored in the presented-context record.
- [ ] **F6 [v1/P1] GRC/IRM integration.**
  - [ ] A connector exposes mapped control-evidence via API for ServiceNow IRM/Archer/OneTrust; a GRC platform pulls per-control evidence with stable ids; re-pull is idempotent.
- [ ] **F7 [v1/P1] Continuous export to the customer's warehouse.**
  - [ ] Streaming/batch sink to object-lock S3/GCS / Snowflake / BigQuery of redacted records + STH manifests; records land within SLA and independently re-verify against the exported STH.
- [ ] **F8 [H1/P1] SCIM lifecycle for approver groups.**
  - [ ] A SCIM 2.0 endpoint syncs approver groups/roles from the IdP; deprovisioning a user removes approval authority within the sync window and writes a meta-log entry.
- [ ] **F9 [v1/P1] OpenTelemetry governance spans.**
  - [ ] OTel spans/events (trace-context propagated, args redacted) for classify/decide/hold/forward; a gated call shows a linked ACP span in the customer's collector with decision + rule id and no payload.
- [ ] **F10 [v1/P1] Public API + outbound webhooks.**
  - [ ] Versioned REST API + signed, replay-protected webhooks (decision.made, approval.requested/resolved, policy.changed) with API-key/OIDC auth + rate limits, covered by the deprecation policy.
- [ ] **F11 [v2/P1] Cross-proxy forensic timeline + hybrid logical clocks.**
  - [ ] Records carry an HLC for cross-node causal ordering; a query over multiple proxies returns a single ordered, anchor-backed timeline; fleet clock-skew beyond a bound alarms.
- [ ] **F12 [v3/P2] On-prem / air-gapped deployment mode.**
  - [ ] An air-gapped profile with an internal RFC 3161 TSA / offline anchoring and offline signed-update + SBOM verification; full gate->approve->verify works with egress disabled and evidence verifies offline.
- [ ] **F13 [v3/P2] Customer change-management & adoption kit.**
  - [ ] RACI template, policy-author certification, staged posture-maturity playbook; the console shows a tenant's posture stage with a defined next step.

### Gate additions from the deep review

- [ ] **H0 gate now also requires:** A1, A2, A3, A4, A6, C2, B1, D1, D2, D3, F1, F2.
- [ ] **H1 gate now also requires:** A5, A7, B2, B3, B4, B5, C1, C4, D4, D5, D6, D7, F3, F8.
- [ ] **Scale/GA gate now also requires:** C3, D8, D9, E7, F11, F12, F13.

---

## Ownership note

Each unchecked task should get an owner and a target gate (H0/H1/H2/GA) before work starts.
The plan is complete when V0.G, H0, V1.G, H1, V2.G, H2, and V3.G1 are all green, **including
the deep-review Blocks A-F folded into those gates above.**
