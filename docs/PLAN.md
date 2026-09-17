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

- [ ] **M0.1 Lock D5-D11 and the record format.**
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

- [ ] **M2.1 YAML->Cedar loader + engine wiring.**
  - [ ] Valid policy compiles, loads, evaluates via `cedar-policy`; 10 malformed policies each fail with a precise error.
- [ ] **M2.2 Policy content hashing + versioning.**
  - [ ] Same source -> same hash; any edit -> new hash; exposed via `/policy/current` with `max_staleness`.
- [ ] **M2.3 `decide()` + namespaced context (D9).**
  - [ ] Args live under an un-spoofable sub-key; reserved-name check; an arg named `blast_radius`/`env`/`body_class` cannot spoof the injected context (red->green test).
- [ ] **M2.4 Typed fail-closed guards + safe entity ids + regex bounds (D9).**
  - [ ] `amount_cents` sent as `"50000"`/`5e4` does not bypass a numeric guard (fail-closed).
  - [ ] Malformed tool name fails closed on entity construction; pathological regex input stays within the latency budget.
- [ ] **M2.5 Verdict precedence (D9).**
  - [ ] deny>step_up>shadow>allow holds; ambiguous determining sets rejected at compile time (tested).
- [ ] **M2.6 Enforce allow/deny; structured denial.**
  - [ ] A deny rule blocks a live call; the agent receives a structured `isError` naming the rule id.
- [ ] **M2.7 `acp policy-compile` + `policy-test`.**
  - [ ] `policy-test` prints the exact set of calls whose verdict flips on a rule change (CI gate).
- [ ] **Gate:** allow/deny enforced from a hashed, versioned policy; every D9 bypass has a passing test.

### M3: Evidence ledger (D3/D5/D6/D7/D11; over-invest here)

- [ ] **M3.1 Storage schema.**
  - [ ] `sqlx`+SQLite; `records` + separate `args_blob`; append-only enforced; UPDATE/DELETE on records rejected; retention purge drops blob but leaves record verifiable.
- [ ] **M3.2 Merkle log + single-writer head (D3/D6).**
  - [ ] Appends update the root deterministically; leader-only extension; two instances cannot both extend one log.
- [ ] **M3.3 Ed25519 signed tree head (D3/D7).**
  - [ ] STH signed via `ed25519-dalek` behind the `Signer` trait; algorithm ids present; per-record signing is NOT used.
- [ ] **M3.4 `acp verify`.**
  - [ ] Passes on a clean ledger; names the exact tampered leaf; a history rewrite fails the consistency check.
- [ ] **M3.5 Durable spool + fail-policy (D5).**
  - [ ] Disk-backed spool; kill server mid-run: gated verdicts fail-closed, evidence replays with no loss and no root divergence.
- [ ] **M3.6 Intent + outcome + idempotent ingest (D11).**
  - [ ] Every allowed action has a linked outcome record; retried batches create no duplicate leaves; a poison record does not head-of-line-block replay (dead-letter).
- [ ] **M3.7 `acp export`.**
  - [ ] Signed pack (records + policy versions + public key + STH manifest) verifies standalone on a clean machine with only the public key.
- [ ] **Gate:** tamper + rewrite detected; export self-verifies; outage causes no evidence loss; every decision has an outcome.

### M4: Step-up approval (D8, R1)

- [ ] **M4.1 Approvals API + single-use consume (D8).**
  - [ ] Approval atomically consumed; a second re-issue is denied; two concurrent re-issues do not both forward.
- [ ] **M4.2 Caller-bound + canonical-byte binding (D8).**
  - [ ] Approval bound to approvalId+session+principal (cross-session reuse denied); a re-issue whose bytes do not canonicalise to the approved request is rejected, not relayed.
- [ ] **M4.3 Slack app + web inbox.**
  - [ ] Approve/Deny works on both; Slack webhook signature verified; approver identity+channel+timestamp recorded.
- [ ] **M4.4 Presented-context + acknowledgement (D8).**
  - [ ] The record stores the exact context the approver saw plus an explicit acknowledgement.
- [ ] **M4.5 Injection-safe rendering (R1).**
  - [ ] Slack Block Kit/`mrkdwn` escaped (no fake buttons/link/@here spoofing); CSV export escapes formula-prefixed fields; untrusted content demarcated.
- [ ] **M4.6 `-32001` re-issue + host retry shim + clock-safe TTL.**
  - [ ] An unmodified agent using the shim transparently waits through an approval; TTL evaluated against a single authority / signed absolute expiry (skew-safe).
- [ ] **M4.7 Approver operations baseline (R1).**
  - [ ] No-response behaviour defined; reminders; the human driving the agent is notified on hold/drop; queue caps + retryAfter jitter under a step_up burst.
- [ ] **Gate:** approve/deny/expire on both channels; one approval = exactly one action; every outcome is a verifiable record.

### M5: HTTP transport, shadow, anti-bypass, polish

- [ ] **M5.1 Streamable HTTP transport.**
  - [ ] Transparency + deny + approval suites pass over HTTP; streamed responses byte-identical.
- [ ] **M5.2 Tool<->proxy binding + upstream TLS (D10).**
  - [ ] A direct agent->tool (out-of-band) connection is refused; upstream cert verified/pinned; no cleartext downgrade.
- [ ] **M5.3 Shadow mode + safe fail-policy (D9).**
  - [ ] In shadow, a deny rule blocks nothing but records a would-block; fail-policy "high-impact" never keys on agent-influenceable signals.
- [ ] **M5.4 Installer + single `acp` CLI.**
  - [ ] `curl ... | sh` then `acp init` yields a working local setup.
- [ ] **M5.5 Worked example + latency budget.**
  - [ ] A stranger gates a `payments.charge`, approves in Slack, exports a verifiable pack in <15 min; allow-path <10 ms p95 under load (CI benchmark).
- [ ] **Gate:** stdio+HTTP work; bypass refused; shadow/fail-policy proven; unaided install-to-audit-pack.

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
- [ ] **H0.12 Telemetry PII hygiene [L].**
  - [ ] Logs/metrics/traces provably never contain customer args/PII (scrubbing verified).
- [ ] **H0.13 Observability + runbooks [6].**
  - [ ] Dashboards + alerts on evidence-write/verify/signing failure, replay backlog, stuck approvals, fail-policy engaged; runbooks for top incidents.
- [ ] **H0.14 Legal baseline [10][R6].**
  - [ ] DPA/GDPR basis; controller/processor roles fixed; sub-processor list (Slack, cloud, Rekor, KMS); worker-monitoring/DPIA position; e-discovery/subpoena policy; evidence-admissibility foundation documented for target jurisdictions.
- [ ] **H0 GATE:** every H0 item complete before any customer runs ACP in production.

---

## v1: Platform & first production customer

### v1.1 Multi-tenant control plane

- [ ] **v1.1.1 Postgres + tenancy.**
  - [ ] Ledger on Postgres; tenants isolated in store and API; an isolation test suite proves no cross-tenant read/write.
- [ ] **v1.1.2 Per-tenant keys + SSO [1.1].**
  - [ ] Per-tenant signing keys behind KMS; one tenant's key compromise cannot touch another's evidence; SSO/OIDC for the console.
- [ ] **v1.1.3 Retention + purge per tenant.**
  - [ ] Per-tenant retention config; purge tested; signed leaf + STH survive payload purge.

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

- [ ] **X.1 CI/CD gates always green.**
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
- [ ] **A2 [H0/P0] Differential conformance of `acp verify` vs a reference CT implementation.**
  - [ ] 10k randomised append/proof sequences produce byte-identical roots and mutually-accepted proofs across acp, a reference CT lib, and the `acp-core::merkle` fallback.
- [ ] **A3 [H0/P0] Cedar evaluation-error is fail-closed + alert.**
  - [ ] Any evaluator error / indeterminate result denies the call, emits a distinct eval-error outcome record, and alarms (not a silent fall-through to `default: allow`).
- [ ] **A4 [H0/P0] Signing / KMS outage policy.**
  - [ ] With KMS forced down, gating matches the documented policy; the committed-but-unsigned window is bounded and alarmed; on recovery all records sign with no root divergence.
- [ ] **A5 [H1/P1] Reproducibility harness `acp replay <seq>`.**
  - [ ] Replays a stored record through its pinned evaluator/compiler/classifier/impact versions and reproduces the stored verdict bit-for-bit; a version bump that would flip any historical verdict fails a golden-corpus gate.
- [ ] **A6 [H0/P0] Deterministic context derivation (cross-platform golden vectors).**
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
- [ ] **B5 [H1/P1] Tool-server supply-chain integrity.**
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

- [ ] **E1 [v1/P1] Governance-effectiveness analytics.**
  - [ ] Deny/approve/step-up/fail-open rates and approval-latency percentiles (distribution, not mean), each independently re-derivable from a verifiable export.
- [ ] **E2 [v1/P1] Policy coverage / gap reporting.**
  - [ ] Report of % of calls matched by an explicit rule vs `default` fall-through, plus a per-tool "no explicit rule" worklist. (Distinct from shadow-AI discovery.)
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

- [ ] **F1 [H0/P0] SIEM/SOAR event streaming.**
  - [ ] A push connector emits redacted governance events (deny/hold/approval/break-glass) as parseable OCSF/CEF to Splunk/Sentinel/Datadog within N seconds; args never leave via this channel.
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
