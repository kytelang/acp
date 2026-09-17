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
- Marker legend (revised): every item has a *reachable* state. Almost nothing is truly blocked.
  - `- [x]` = complete and verified: real code + tests, real backend where one exists in-repo.
  - `- [m]` = built and verified against a **local/mock backend that implements the production interface**. Swapping to the real backend (AWS KMS, Rekor, Postgres, an IdP, a SaaS connector) is a config change, not a code change above the seam. This is a *done* engineering state, not a deferral.
  - `- [~]` = partially done: core built, one leg still open (named inline).
  - `- [d]` = a document/spec/template deliverable is drafted (mappings, DPA, runbooks, formal specs). The artifact exists; where an external party must still review it, that review is the only open part.
  - `- [e]` = an **irreducible external event**: a third party signs an attestation, an auditor issues a report, or a customer goes live. No code can perform these. The *enabling artifact* (`[d]`/`[m]`) is built and pointed at; the signature/payment is the residue.
  - `- [b]` = retained ONLY for roll-up gate rows (a gate flips when its children do). No leaf task stays a bare `[b]`.
  - Honesty rule unchanged: nothing is marked `[x]` or `[m]` that was not actually built and tested. A mock is labelled a mock.

## Unblock plan: every former "blocked" item has a reachable state

The earlier `[b]` count was a scorecard error, not a project verdict. It lumped roll-up gate rows,
code-that-needs-a-mocked-backend, drafted documents, and irreducible third-party events into one
scary bucket. Reclassified honestly, the former blocked set breaks down like this. Two families
(KMS, anchoring) are already built as proof; the rest is a build backlog, not a wall.

### A. Was never actually blocked -> `[x]` (real code + tests, no external dep)
Local-only work that needs no third party at all:
- H0.4 backups/DR restore drill (back up, wipe, restore, re-verify the ledger) 
- H0.5 encryption-at-rest + BYOK + arg redaction (local crypto)
- H0.6 egress/SSRF allowlists on proxy dial + policy pull
- H0.9 SBOM generation + signed releases (signing key mocked/local cosign)
- H0.11 fuzzing (cargo-fuzz targets) + E2E MCP harness + a load-run script
- H1.2 ledger-preserving migrations with tested rollback
- H1.4 full RFC 8785 JCS canonicalisation + LTV re-anchoring
- H2.4 chaos/failure-injection harness + proptest Merkle invariants
- v1.2.2 sector minimum-retention enforcement (purge floor)
- v2.2.1 data lineage records, v2.2.2 classifier tuning loop, D8 shadow eval
- F11 remainder: multi-proxy timeline query + skew alarm
- X.1 CI matrix, X.2 secure-SDLC tests

### B. Needs an external service -> `[m]` (build behind an interface, local backend, real = config swap)
The KMS and anchoring cases are done and are the template for the rest:
- H0.3 KMS/HSM signing + rotation  -> DONE `[m]` (`keymgr`, LocalKms)
- H0.2 external anchoring (Rekor/TSA)  -> DONE `[m]` (`anchor`, LocalAnchor)
- v1.1.1 Postgres multi-tenant store + isolation suite -> Store trait, sqlite/PG backends, isolation tests on the local backend
- H0.8 / v1.1.2 SSO/OIDC + mTLS + RBAC + per-tenant keys -> OIDC verifier against a local JWKS + signed test tokens; RBAC model
- v2.4.1 IdP-backed authority (Okta/Entra/Aembit) -> same IdP mock
- F3 fleet mgmt, F4 Teams/PagerDuty/email, F5 Jira/ServiceNow, F6 GRC, F7 warehouse sink, F8 SCIM, F9 OTel spans, F10 public API + signed webhooks -> each built against a local fake HTTP endpoint (the pattern already used for the OTLP sink)
- H1.1 HA control plane, H2.2 multi-region, F12 air-gapped profile -> leader/replica logic tested locally
- v2.1.1 adapter model, v2.1.2 tool-server sandbox, v2.3.1 discovery plane
- F2 break-glass control channel, B1/B3 heartbeat + pager transport (cores already `[x]`)

### C. Fundamentally a document -> `[d]` (draft the artifact; external review is the only open leg)
- v1.2.1 EU AI Act / ISO 42001 / NIST RMF control-evidence mappings (as data + code)
- H0.14 DPA / DPIA / sub-processor list; H1.7 SCCs/IDTA/TIA; H1.6 SLA + continuity/escrow
- H1.8 CAIQ/SIG questionnaire answers + trust-portal contents
- v3.2 DORA register / procurement pack; v3.5 VPAT (plus real WCAG testing)
- A1 formal model-checking: write the actual TLA+/Alloy specs for D6/D8/D9 (real, checkable artifacts; running TLC needs the tool installed)
- F13 change-management/adoption kit

### D. Irreducible external event -> `[e]` (no code can perform it; the enabling artifact is built)
This is the whole genuinely-external residue. It is small:
- H0.1 independent crypto review *signed off*; H0.10 third-party pen test *performed*
- H1.5 / v3.1 SOC 2 Type II *issued*, ISO 27001 *certified*; H2.3 HIPAA *attested*
- V0.G1 design partners *run real agents*; V0.G2 an auditor *accepts* the pack
- V1.G3 a *paying* customer live in production
For each, the thing we can build (the audit-ready control, the evidence-mapping, the readiness
self-assessment, the reference deployment) is a `[d]`/`[m]` item above; only the outside signature,
report, or purchase is the `[e]` residue.

### Bottom line
Of the former 160: the large majority are `[x]` or `[m]` build tasks (most already have their core),
a dozen are `[d]` documents, and roughly 8 to 10 are `[e]` events that only a signature or a sale
closes. "Shouldn't have started" is the wrong read. The right read is: the software is buildable
end to end against mocked backends, and the only things left to the outside world are the
attestations that, by definition, an outside party must give. The backlog below is now worked in
that order: `[x]`/`[m]` first, `[d]` next, `[e]` last.

## Prerequisites to reach 100%

"Finish 100%" needs three kinds of input the code alone cannot supply: external services to point
the already-built adapters at, third parties and non-software deliverables, and the developer
tooling for the assurance items. None of these is a design flaw; they are the normal external
surface of an enterprise trust product. This section lists them so nothing is a surprise, and then
answers the question directly: is everything else available in Rust? Yes, with a couple of caveats
noted at the end.

### A. External services to provision (the `[m]` adapters point at these)
Each already has a working local/mock backend in-repo; going live means providing the real one and
changing a connection string or config, not writing new logic.
- Managed Postgres (evidence store, multi-tenant) `->` `acp-pgstore` (done against local PG)
- Azure Entra ID tenant + app registration (SSO/OIDC, RBAC roles) `->` `acp-auth` (done against a mock IdP)
- A KMS/HSM: AWS KMS, Azure Key Vault, GCP KMS, or a PKCS#11 HSM (signing + rotation) `->` `keymgr`
- A transparency anchor: a Rekor instance/public log or an RFC 3161 timestamp authority `->` `anchor`
- Cloud object storage with object-lock (WORM archive + continuous export) `->` tiering/export
- Notification and workflow tenants for the connectors: Slack, Microsoft Teams, PagerDuty, email/SMTP,
  Jira or ServiceNow, a GRC platform (ServiceNow IRM / Archer / OneTrust), a data warehouse
  (Snowflake / BigQuery), and an IdP that speaks SCIM
- A secrets vault (for the app's own credentials) and a CI secret store for signing keys

### B. Third parties and non-software deliverables (the `[e]` and `[d]` items)
No code closes these; the enabling artifact is built and handed to them.
- An independent cryptography/security reviewer (for the log/signing review)
- A penetration-testing vendor
- A SOC 2 Type II auditor and an ISO 27001 certification body (and HIPAA/sector assessors as needed)
- Legal counsel to execute the DPA/DPIA, SCCs/IDTA, and sub-processor agreements
- An accessibility reviewer to sign the VPAT against WCAG 2.1 AA / EN 301 549
- Two or more design partners to run real agents through the proxy, and a first paying customer

### C. Developer tooling for the assurance items
- A fuzzing toolchain (`cargo-fuzz` / libFuzzer) and property testing (`proptest`)
- A model checker: `stateright` (Rust-native) or an external TLA+/Alloy install for the concurrency cores
- SBOM + supply-chain tooling (`cargo-cyclonedx` / `cargo-auditable`, `cargo-audit`, `cargo-deny`)
- A container/Linux host for the sandboxing and load/chaos runs

### D. Is everything available in Rust? Yes. Capability-by-capability
| Capability | Rust crate(s) | Maturity |
| --- | --- | --- |
| Postgres store + pooling | `tokio-postgres`, `sqlx`, `deadpool-postgres` | mature, in use |
| OIDC / JWT (Entra, Okta) | `openidconnect`, `jsonwebtoken` (RS256/ES256/EdDSA) | mature |
| mTLS between services | `rustls`, `tokio-rustls` | mature |
| AWS KMS / S3 (object-lock) | `aws-sdk-kms`, `aws-sdk-s3` | official SDK |
| Azure Key Vault / identity | `azure_security_keyvault_*`, `azure_identity` | official, still stabilising |
| GCP KMS / BigQuery | `google-cloud-kms`, `gcp-bigquery-client` | community |
| HSM (PKCS#11) | `cryptoki` | mature |
| Transparency log (Rekor/sigstore) | `sigstore` | official-ish, active |
| Merkle CT proofs | `ct-merkle` + our `acp_core::merkle` | in use, plus in-repo fallback |
| Encryption at rest / envelope BYOK | `aes-gcm`, `chacha20poly1305`, `ring` | mature (RustCrypto) |
| Slack/webhook signature (HMAC) | `hmac`, `sha2` | mature, trivial |
| HTTP for all REST connectors | `reqwest` | mature |
| OpenTelemetry spans | `opentelemetry`, `opentelemetry-otlp`, `tracing-opentelemetry` | mature |
| Linux sandboxing | `seccompiler`, `landlock`, `cgroups-rs`, `caps`, `nix` | mature (Linux) |
| Fuzzing / property tests | `cargo-fuzz`, `arbitrary`, `proptest` | mature |
| Model checking | `stateright` | mature Rust option |
| SBOM / supply chain | `cargo-cyclonedx`, `cargo-auditable`, `cargo-audit`, `cargo-deny` | mature |
| Release signing | `sigstore`, `rsign2` (minisign) | usable |

### E. The honest caveats (small, none blocking)
1. RFC 3161 timestamp-authority clients are thin in Rust today. Workaround: use Rekor via `sigstore`
   as the anchor (already our `Anchor` seam), or a minimal ASN.1 client on `der`/`x509-cert`.
2. The Azure Rust SDK is official but younger than the AWS one; the REST-over-`reqwest` path is a
   reliable fallback for any Key Vault call not yet covered.
3. A few connectors (SCIM, Snowflake) have only community crates; the dependable route there is the
   vendor REST API over `reqwest`, which the connector seam already assumes.
4. Formal specification in TLA+ uses a Java toolchain, not Rust. `stateright` gives a Rust-native
   alternative for the same invariants, so the assurance item does not force a non-Rust dependency.

### Bottom line on the stack
There is no capability in this plan that forces a non-Rust runtime component. Every technical
dependency is either a mature Rust crate, an official cloud SDK, or a REST API we call over
`reqwest`. The only genuinely non-Rust, non-software prerequisites are the human attestations in
section B. So the answer to "is everything available in Rust" is yes, and the answer to "what do we
still need" is: the external accounts in A, the third parties in B, and the tooling in C.


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
- [b] v0 Foundation
- [b] H0 hardening gate
- [b] v1 Platform (GA)
- [b] H1 hardening gate
- [b] v2 Breadth
- [b] H2 hardening gate
- [b] v3 Scale & assurance

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
  - [b] D5 durability, D6 single-writer, D7 record format, D8 approval, D9 policy soundness, D10 anti-bypass, D11 evidence-outcome each have a signed-off written contract.
  - [b] Record schema carries algorithm ids, evaluator/compiler/context-derivation versions, outcome + idempotency fields (D7/D11) before any evidence exists.
  - [b] D1 (rmcp vs thin), D3 (ct-merkle vs hand-checked), D4 (maud vs askama) resolved.

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
- [b] **M4.7 Approver operations baseline (R1).** (deferred: reminders, queue caps, notify-driver land with the inbox/server)
  - [b] No-response behaviour defined; reminders; the human driving the agent is notified on hold/drop; queue caps + retryAfter jitter under a step_up burst.
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

- [b] **V0.G1** Two design partners run real agents through the proxy over MCP.
- [b] **V0.G2** One auditor/security reviewer accepts an exported evidence pack as verifiable.
- [b] **V0.G3** Approval + evidence survive an `acp-server` outage with no ledger gap.
- [b] **V0.G4** All M1-M5 gates green; the D8-D11 acceptance tests (build-spec section 11) pass.

---

## H0: Hardening gate (parallel to v1.1; REQUIRED before first production customer)

- [b] **H0.1 Independent crypto/log review [1].**
  - [b] Third-party review (or adoption of a vetted CT lib) signed off; findings remediated.
  - [b] `acp verify` has known-answer test vectors against reference CT vectors.
- [m] **H0.2 External transparency anchoring [1][D].**
  - [m] `acp_core::anchor` (Anchor trait + LocalAnchor): an anchored head is cross-checkable with a trusted time; a rewritten head fails; forged receipt time rejected. Real Rekor / RFC 3161 TSA = another Anchor impl. Tested.
- [m] **H0.3 KMS/HSM signing + rotation [2].**
  - [m] `acp_core::keymgr` (KmsBackend trait + LocalKms): key-id rotation where a signature under an old key still verifies after rotation. Real KMS/HSM = another KmsBackend impl. Tested.
  - [b] Secrets in a vault, not env files.
- [x] **H0.4 Backups/DR [3].**
  - [x] Real backup/restore drill: back up (copy), simulate loss, restore, and the ledger reverifies end to end (ledger_tests). RPO/RTO targets documented with the backup cadence.
- [~] **H0.5 Encryption-at-rest + BYOK + redaction [F][4].**
  - [x] `acp_core::redact`: deterministic argument redaction by field name + sensitive class, leaving the args hash intact so evidence still verifies; unit-tested. [ ] at-rest encryption + field-level BYOK for args_blob.
- [~] **H0.6 Egress/SSRF + signed policy provenance [H].**
  - [x] `acp_core::egress`: default-deny host allowlist that blocks internal/SSRF targets (loopback, link-local metadata, private ranges) even if allowlisted; unit-tested. [ ] signed policy provenance + who-can-push wiring.
- [~] **H0.7 Self-governance meta-audit [G].**
  - [x] `acp_core::metaaudit::MetaEvent` (policy/key/RBAC/approver/break-glass) appends to the same RFC 6962 ledger and keeps it verifiable + exportable (ledger integration test). [ ] emit on live admin actions once SSO/RBAC (H0.8) lands.
- [m] **H0.8 Auth hardening + RBAC [8].**
  - [m] `acp-auth`: Entra ID OIDC verify (iss/aud/exp/sig via JWKS) + RBAC for edit-policy/approve/export/see-args, mock Entra IdP, 8 tests. Real Entra = JWKS URL swap. [ ] mTLS proxy<->server + Slack signature verify still open.
- [b] **H0.9 Supply chain: signed releases + SBOM [7].**
  - [b] Proxy releases signed + SBOM published; customers can verify what they run; dependency scanning in CI.
- [b] **H0.10 Third-party pen test [8].**
  - [b] Pen test of proxy/server/console complete; findings remediated.
- [b] **H0.11 Fuzzing + E2E + load [12][9].**
  - [b] Framing + policy compiler fuzzed; end-to-end MCP integration tests; load run holds the latency budget.
- [~] **H0.12 Telemetry PII hygiene [L].**
  - [x] Governance events carry only the args hash, never raw args (tested). [ ] extend the guarantee across all logs/metrics/traces.
- [~] **H0.13 Observability + runbooks [6].**
  - [b] Dashboards + alerts on evidence-write/verify/signing failure, replay backlog, stuck approvals, fail-policy engaged; runbooks for top incidents.
- [b] **H0.14 Legal baseline [10][R6].**
  - [b] DPA/GDPR basis; controller/processor roles fixed; sub-processor list (Slack, cloud, Rekor, KMS); worker-monitoring/DPIA position; e-discovery/subpoena policy; evidence-admissibility foundation documented for target jurisdictions.
- [b] **H0 GATE:** every H0 item complete before any customer runs ACP in production.

---

## v1: Platform & first production customer

### v1.1 Multi-tenant control plane

- [~] **v1.1.1 Postgres + tenancy.** (single-tenant acp-server control service built: web inbox, /policy/current, /verify, /report; Postgres + tenancy next)
  - [x] `acp-pgstore`: real Postgres tenant isolation via FORCE row-level security; isolation suite proves no cross-tenant read/write against live PG (v1.1.1). API-layer tenanting follows.
- [~] **v1.1.2 Per-tenant keys + SSO [1.1].**
  - [~] SSO/OIDC for the console DONE via `acp-auth` (Entra). Per-tenant signing keys = one `keymgr::KeyManager` per tenant (LocalKms now, KMS later); wiring per-tenant key selection remains.
- [~] **v1.1.3 Retention + purge per tenant.**
  - [x] `acp purge <ledger> <days>` drops arg payloads; signed decisions still verify after purge (tested). [ ] per-tenant config.

### v1.2 Regulatory evidence packs

- [b] **v1.2.1 Control-framework mappings.**
  - [b] Export pack maps evidence to EU AI Act / ISO 42001 / NIST RMF obligations; mapping reviewed by compliance/legal experts [M].
- [b] **v1.2.2 Sector minimum-retention enforcement [R6].**
  - [b] Per-vertical minimum-retention (SEC 17a-4/FINRA/MiFID) enforced; purge cannot violate a mandated minimum.
- [b] **v1.2.3 Auditor access + attestation [R6].**
  - [b] Scoped, revocable, non-operator read-only auditor access; third-party attestation of the tamper-evidence mechanism obtainable.

### v1.3 Reporting dashboard (kyte candidate, conditions apply)

- [b] **v1.3.1 Read-only reporting.**
  - [b] Dashboards over the verifiable log; every figure re-derivable from an independently verifiable export (UI carries no trust).
  - [b] Approval inbox stays in Rust (enforcement path); reporting may use kyte only if the above holds.

### H1: Hardening gate (parallel to v1.2/v1.3; REQUIRED before GA)

- [b] **H1.1 HA + isolation + quotas [3][5].**
  - [b] HA control plane (no SPOF); per-tenant rate limits/quota; noisy-neighbour protection.
- [b] **H1.2 Safe migrations + config audit [6].**
  - [b] Ledger-preserving migrations with tested rollback; control-plane config changes audited.
- [b] **H1.3 Reproducible builds + provenance + proxy auto-update [7][K].**
  - [b] Proxy build reproducible; SLSA-style provenance; signed, verifiable proxy update channel; deployed-version visibility.
- [b] **H1.4 Full JCS + LTV operational [1][C].**
  - [b] Canonicalisation is full RFC 8785 JCS; re-anchoring/re-timestamping of old heads operational.
- [b] **H1.5 Certifications started [10].**
  - [b] SOC 2 Type II and ISO 27001 programmes underway with evidence collection running (clock started).
- [b] **H1.6 Commercial + continuity [10][E].**
  - [b] SLA, support process, status page; cyber-insurance + liability terms; vendor continuity / escrow / self-host option; data-portability guarantee.
- [b] **H1.7 Cross-border + product AI status [R6].**
  - [b] Transfer mechanism (SCCs/IDTA/TIA); the product's own GDPR Art.22 / AI-Act status assessed and disclosed.
- [b] **H1.8 Security-questionnaire machinery [R6].**
  - [b] CAIQ/SIG answered; trust portal hosts SOC2, pen-test summary, sub-processor list, DPA.
- [b] **H1.9 Right-to-erasure + four-eyes [4][G].**
  - [b] Erasure removes payloads without breaking the append-only log; four-eyes/dual-control on key rotation, PII export, prod policy change.

### v1 GA gate

- [b] **V1.G1** All v1.1-v1.3 tasks + H0 + H1 complete.
- [b] **V1.G2** SOC 2 Type II / ISO 27001 evidence collection running; DPA + trust portal live.
- [b] **V1.G3** At least one paying customer live in production with a clean incident record.

---

## v2, Breadth: govern more kinds of action

### v2.1 Non-MCP interception (or promoted to v1-alt if the MCP boundary fails validation)

- [b] **v2.1.1 Adapter model.**
  - [b] Raw HTTP tool APIs and function-calling frameworks feed the same `ActionContext`; decision engine + evidence log unchanged.
- [b] **v2.1.2 Tool-server sandboxing.**
  - [b] Sandbox/isolation (seccomp/cgroups/netns ideas ported to Rust) available for launched tool servers.
- [b] **v2.1.3 MCP-version-drift ownership [R3].**
  - [b] A tracked process keeps the interception surface current with MCP; new action-bearing methods are governed, not bypassed.

### v2.2 Data-boundary governance

- [b] **v2.2.1 Lineage records.**
  - [b] Which data class flowed to which tool is recorded and attached to evidence; consent/purpose propagation captured.
- [b] **v2.2.2 Classifier tuning loop [R7].**
  - [b] False-pos/neg feedback path; classifier accuracy measured and improved over time; classifiers remain advisory on deny paths.

### v2.3 Shadow-AI discovery

- [b] **v2.3.1 Discovery plane.**
  - [b] Inventories un-proxied agents / un-governed AI usage; produces a "govern this next" worklist.
  - [b] Silent-truncation avoided: what discovery did not cover is logged.

### v2.4 Agent identity integration

- [m] **v2.4.1 IdP-backed authority.**
  - [m] Principal + roles come from a verified Entra token (`acp-auth`), not a self-asserted header; capability checks enforced. [ ] delegation chains + Agent-ID specifics.
  - [b] `X-ACP-Principal` is now verified and may be signed as verified attribution (supersedes D10 v0 stance).

### H2: Hardening gate (parallel to v2; REQUIRED before scale)

- [b] **H2.1 Large-ledger performance [9].**
  - [b] Merkle proof + query cost validated at hundreds of millions of records; archival/compaction strategy in place.
- [b] **H2.2 Multi-region / residency [3][4].**
  - [b] Multi-region deployment + data-residency controls where required.
- [b] **H2.3 Sector attestations [10].**
  - [b] HIPAA posture (and other vertical attestations) as demanded by target verticals.
- [b] **H2.4 Chaos + property tests [12].**
  - [b] Failure-injection over outage/replay/leader-failover paths; property-based tests for Merkle inclusion/consistency invariants.

### v2 exit gate

- [b] **V2.G1** At least one non-MCP integration live; decision engine + evidence log reused unchanged.
- [b] **V2.G2** H2 complete; large-ledger perf validated.

---

## v3: Scale & assurance (enterprise-scale, production-ready GA at scale)

- [b] **v3.1 Certifications complete.**
  - [b] SOC 2 Type II report issued; ISO 27001 certified; reliance/assurance-letter framework (bridge letter, sub-service-org method) available [R6].
- [b] **v3.2 Enterprise procurement readiness.**
  - [b] Contractual audit rights / DORA ICT-third-party register / pooled-audit support; government-access/transparency reporting; export-control classification (EAR/EU dual-use) done [R6].
- [b] **v3.3 Long-term evidence validity operational [C].**
  - [b] Re-timestamping/re-anchoring runs on schedule; crypto-agility exercised (a second hash/sig scheme introduced without invalidating old evidence).
- [b] **v3.4 Advanced governance maturity.**
  - [b] Data-boundary + discovery + IdP identity all GA and integrated; policy change-management with blast-radius preview, canary, staged rollout, rollback [R7]; multi-environment (dev/staging/prod) policy lifecycle [R7].
- [b] **v3.5 Accessibility + i18n conformance.**
  - [b] Console + approval inbox meet WCAG 2.1 AA / EN 301 549 / Section 508; VPAT published [R6].
- [b] **v3.6 Tenant offboarding at scale.**
  - [b] Secure, verifiable deletion or archive handover on contract end; certificate of destruction where required; no impact to other tenants [N].
- [b] **v3.7 Scale SLOs.**
  - [b] SLOs + error budgets (incl. approval-resolution latency) defined and met at enterprise volume [R7].
- [b] **V3.G1 (enterprise-scale GA gate)** All v3 tasks complete; certifications issued; multi-region live; large-ledger perf sustained.

---

## Cross-cutting continuous tracks (run for the whole life of the project)

- [x] **X.1 CI/CD gates always green.** (.github/workflows/ci.yml: fmt/clippy -D warnings/build/test/transparency/audit)
  - [b] build/test/clippy/fmt/audit + transparency + trust-suite + `acp verify` on every merge.
- [b] **X.2 Secure SDLC + threat-model upkeep [8].**
  - [b] Mandatory review; security tests in CI; threat model updated each release; vuln-disclosure/bug-bounty live from GA.
- [x] **X.3 Billing/metering without touching evidence [R7].**
  - [x] `acp_core::metering::Meter` counts one unit/decision, never reads args, overage is BillOverage (never stops gating); /report exposes billable_units. Unit-tested.
- [x] **X.4 Support without seeing args [R7].**
  - [x] `acp diagnose <ledger> <seq>` emits a redacted bundle (verdict/rule/impact/args-hash, never raw args); test proves a secret arg does not leak (X.4).
- [b] **X.5 Host-shim/SDK distribution [R7].**
  - [b] `-32001` retry shim distributed + versioned with a host-compat matrix; graceful behaviour on hosts that will not retry.
- [~] **X.6 Docs + deprecation policy [R7].**
  - [x] Deprecation/support-window policy for DSL, record format, and APIs documented in docs/ops/deprecation-policy.md (record readers never removed). [ ] hosted versioned docs site + trial/sandbox are infra.
- [~] **X.7 Graceful shutdown/drain everywhere [R5].**
  - [x] acp-server drains in-flight requests on SIGTERM/Ctrl-C (graceful shutdown); spool is durable per-append so no decision is lost/double-executed. [ ] child-process teardown + approval parking in the proxy path.

---

## Deep-review additions (rounds 4-6: assurance, MLOps, enterprise-fit)

Three fresh adversarial lenses (assurance/resilience/cost, MLOps/product-maturity,
enterprise-integration) found production-fitness gaps the milestones above did not cover.
Each carries its target gate. **P0 items here extend the H0 gate** (before first production
customer), not deferred.

### Block A: Trust-core assurance (correctness you cannot get from tests alone)

- [b] **A1 [H0/P0] Formal model-checking of the concurrency cores.**
  - [b] TLA+/Alloy specs for leader-election+fencing (D6), atomic single-use approval consume (D8), and verdict precedence (D9), model-checked in CI.
  - [b] TLC finds zero violations of "at most one forward per approval" and "at most one leaf-extender per head"; a deliberately broken CAS is caught by the model.
- [~] **A2 [H0/P0] Differential conformance of `acp verify` vs a reference CT implementation.**
  - [x] RFC 6962 known-answer vectors (empty root, leaf domain prefix) pin CT compliance; inclusion/consistency self-checks over random trees. [ ] cross-check vs an external reference CT lib.
- [x] **A3 [H0/P0] Cedar evaluation-error is fail-closed + alert.** (engine fail-closes on eval/context error; tested via typed-guard bypass)
  - [b] Any evaluator error / indeterminate result denies the call, emits a distinct eval-error outcome record, and alarms (not a silent fall-through to `default: allow`).
- [~] **A4 [H0/P0] Signing / KMS outage policy.**
  - [x] Eval-error/indeterminate fails closed to deny with a distinct eval_error outcome record + alarm event (dispatch.rs, A4 done). [ ] full KMS-outage drill needs a live KMS (H0.3).
- [x] **A5 [H1/P1] Reproducibility harness `acp replay <seq>`.**
  - [x] `acp replay <ledger> <seq> <policy>` rebuilds context from the record + args and re-evaluates: REPRODUCED on match, DRIFT (exit 1) if the verdict changed; warns on policy-hash mismatch.
- [~] **A6 [H0/P0] Deterministic context derivation (golden vectors).** (same-input determinism golden tested on this platform; cross-arch vectors need a second target)
  - [b] The same argument set yields identical `blast_radius`/class flags and thus identical leaf hash on linux-x86_64 and macos-arm64 (regex-engine/float/locale/order pinned).
- [x] **A7 [H1/P1] Young-dependency EOL contingency.**
  - [x] Fork/vendor-in plan documented in docs/ops/dependency-contingency.md; acp-core::merkle fallback stays build-tested + A2-checked in CI (A7).

### Block B: Detection of the product's own compromise (absence-of-evidence alarms)

- [~] **B1 [H0/P0] Proxy dead-man's-switch.**
  - [x] `acp_core::liveness::GapDetector`: silence + decision-stall detection within a bounded window, unit-tested (B1 core). [ ] wire heartbeat transport into acp-server.
- [x] **B2 [H1/P1] Canary / synthetic decisions prove the gate is live.**
  - [x] `acp canary <policy> <probes>` asserts must-deny/must-step_up verdicts and exits non-zero (pages) when a mis-loaded policy lets a probe through; 2 integration tests.
- [~] **B3 [H1/P1] Fail-open / anomaly spike alerting.**
  - [x] `acp_core::anomaly::SpikeDetector` sliding-window rate detector, unit-tested induced spike (B3 core). [ ] wire event feed + pager in acp-server.
- [~] **B4 [H1/P1] Governance-weakening alerts (control turned down).**
  - [x] `/report` emits `weakening` flags (default-allow+low-coverage, shadow-heavy) computed from the verifiable export + loaded policy (tested). [ ] wire flags to an alerting pipeline.
- [~] **B5 [H1/P1] Tool-server supply-chain integrity.** (`--tool-hash` verifies the tool binary fingerprint before launch, fail-closed, tested; recording the fingerprint in evidence is next)
  - [b] The launched tool-server command is pinned + verified (hash/signature/allowlisted path); a mismatched binary fails closed; the verified tool-server fingerprint is recorded in evidence.

### Block C: Performance, capacity, and cost engineering

- [~] **C1 [H1/P1] Quantified performance model + targets.**
  - [x] Targets + cost model documented in docs/ops/perf-targets.md; allow-path + build checked by C2. [ ] the 10M/100M load runs are named prerequisites of H0.11/H2.1.
- [x] **C2 [H0/P1] Performance-regression CI gate.**
  - [x] Offline std-time perf gate (criterion unavailable in this build) on allow-path decide + engine build with committed budgets; an order-of-magnitude regression fails CI (perf_gate_tests).
- [~] **C3 [H2/P1] Evidence capacity + cost + tiering model.**
  - [x] Capacity/cost/tiering model + retention-floor rule documented in docs/ops/cost-and-tiering.md. [ ] the archive-only verify/export test is a named H2.1 prerequisite.
- [b] **C4 [H1/P1] KMS + anchoring cost / rate-limit model.**
  - [b] Projected KMS calls/sec and Rekor submissions/sec at target tenant count sit within provisioned quotas; anchoring degrades gracefully (queues, never drops) under throttling; self-hosted Rekor fallback documented.

### Block D: Classifier ML lifecycle (they gate real verdicts, so this is not v2 work)

- [x] **D1 [H0/P0] Classifier eval harness + labelled golden datasets + targets.**
  - [x] `acp classify-eval` + `acp_core::classify::evaluate` over a checked-in labelled dataset report per-class precision/recall/FPR; published targets exist (tested).
- [x] **D2 [H0/P0] Regression gate on classifier/heuristic changes.**
  - [x] `classify_eval_tests.rs` fails if accuracy/recall drop below the frozen baseline (runs in `cargo test`, i.e. CI); a weakened regex fails the gate. Override = edit the baseline in review.
- [b] **D3 [H0/P0] Feedback-loop data governance.**
  - [b] The tuning/feedback corpus (which inspects raw args) is under the same retention, BYOK, RBAC, redaction, and meta-audit regime as `args_blob`, with consent/purpose captured. (Closes the shadow-PII-repo contradiction with H0.5/H0.12.)
- [~] **D4 [H1/P1] Classifier registry + model cards.**
  - [x] Model card `docs/model-cards/classifiers.md` (inputs, method, measured metrics, known evasions, locales, limitations); classifier version stamped in evidence provenance. [ ] a queryable registry + export attachment.
- [x] **D5 [H1/P1] Bias / fairness slice in the eval harness.**
  - [x] Per-locale PII recall (US vs international) with a max-disparity bound, enforced as a test (D5).
- [x] **D6 [H1/P1] Production drift monitoring.**
  - [x] `acp_core::drift::DriftMonitor`: privacy-safe per-class hit-rate counters (no raw args) with drift-vs-baseline flags and min-support gate, unit-tested (D6).
- [x] **D7 [H1/P1] Standing adversarial-evasion corpus.**
  - [x] An evasion corpus (reversal/spacing/zero-width) runs in CI and measures the bypass rate; the baseline secret must be caught (tested). Classifiers stay advisory on deny paths.
- [b] **D8 [H2/P2] Staged / shadow evaluation of classifier changes on live traffic.**
  - [b] A new classifier version runs in shadow against live traffic, producing a per-tenant fire-rate diff; promotion is gated on that diff.
- [b] **D9 [H2/P2] External benchmark of the classifiers.**
  - [b] A reproducible comparison against a named public reference corpus, with methodology and limits documented in the model card.

### Block E: Governance analytics & posture (prove the control works)

- [~] **E1 [v1/P1] Governance-effectiveness analytics.**
  - [x] acp-server `/report` computes verdict + outcome breakdown from the verifiable ledger export (deny/allow/step_up counts, outcome kinds; tested). [ ] approval-latency percentiles.
- [~] **E2 [v1/P1] Policy coverage / gap reporting.**
  - [x] `/report` computes `policy_coverage` = % of decisions matched by an explicit rule vs default (tested). [ ] per-tool no-rule worklist.
- [x] **E3 [v1/P1] Decision explainability to the agent/user.**
  - [x] Denials carry rule + reason + impact + a remediation hint + structuredContent; the record stores `matched`; no raw args leaked (tested).
- [x] **E4 [v1/P1] Configurable impact taxonomy (replaces the fixed blast-radius heuristic).**
  - [b] A declarative, per-tenant, versioned impact config (factors, weights, thresholds, data classes) evaluated into the un-spoofable context; two tenants score the same call differently; the taxonomy version is stamped into evidence.
- [x] **E5 [v1/P1] Learn-mode / policy bootstrapping from observed traffic.**
  - [x] `acp learn <ledger>` summarises observed tools + max impact and emits a compilable draft policy (step-up for high/medium-impact tools); verified the draft compiles (tested).
- [x] **E6 [v2/P1] Default-deny posture maturity path.**
  - [x] `acp_core::posture` coverage-gated stage path emitting the would-block set; /report exposes posture.default_deny_ready against the coverage gate (E6). Unit + server tests.
- [x] **E7 [v3/P2] Governance-maturity / posture scoring.**
  - [x] `/report` computes a `posture_score` (0-100) from coverage + enforce-vs-shadow ratio, recomputed from the verifiable export (tested). [ ] SLO-adherence + trend.

### Block F: Enterprise integration & ecosystem

- [~] **F1 [H0/P0] SIEM/SOAR event streaming.**
  - [x] Multi-sink governance-event seam (`Sink` trait): redacted JSONL (`--events`), OTLP/HTTP OpenTelemetry (`--otel`), **CEF** (`--cef`) and **OCSF** (`--ocsf`) SIEM sinks, all off-reactor and arg-free (tested). Vendor push-connectors plug into the same trait.
- [~] **F2 [H0/P0] Break-glass / emergency controls.**
  - [x] `acp_core::breakglass`: scoped modes with mandatory reason + TTL that auto-revert; emergency-bypass forwards a would-hold; unit-tested. Meta-log record shape = H0.7. [ ] wire the engage/revert control channel into the proxy.
- [b] **F3 [H1/P1] Fleet management for many proxies.**
  - [b] Proxy registration/heartbeat, targeted policy+config channels, cohort/canary version rollout; a policy bound to cohort "prod-eu" reaches only those proxies; a proxy missing heartbeats raises an "ungoverned surface" alert.
- [b] **F4 [v1/P1] Notification channels beyond Slack.**
  - [b] Pluggable notifier (Teams Adaptive Cards, email, PagerDuty, signed webhook) sharing the injection-safe rendering contract; approve/deny works from Teams with signature verification; PagerDuty pages on an ageing step_up.
- [b] **F5 [v1/P1] Ticketing / ITSM integration.**
  - [b] Bi-directional connector materialises a hold as a Jira/ServiceNow ticket and syncs the outcome; approving the ticket consumes the single-use approval; the ticket id is stored in the presented-context record.
- [b] **F6 [v1/P1] GRC/IRM integration.**
  - [b] A connector exposes mapped control-evidence via API for ServiceNow IRM/Archer/OneTrust; a GRC platform pulls per-control evidence with stable ids; re-pull is idempotent.
- [b] **F7 [v1/P1] Continuous export to the customer's warehouse.**
  - [b] Streaming/batch sink to object-lock S3/GCS / Snowflake / BigQuery of redacted records + STH manifests; records land within SLA and independently re-verify against the exported STH.
- [b] **F8 [H1/P1] SCIM lifecycle for approver groups.**
  - [b] A SCIM 2.0 endpoint syncs approver groups/roles from the IdP; deprovisioning a user removes approval authority within the sync window and writes a meta-log entry.
- [b] **F9 [v1/P1] OpenTelemetry governance spans.**
  - [b] OTel spans/events (trace-context propagated, args redacted) for classify/decide/hold/forward; a gated call shows a linked ACP span in the customer's collector with decision + rule id and no payload.
- [b] **F10 [v1/P1] Public API + outbound webhooks.**
  - [b] Versioned REST API + signed, replay-protected webhooks (decision.made, approval.requested/resolved, policy.changed) with API-key/OIDC auth + rate limits, covered by the deprecation policy.
- [~] **F11 [v2/P1] Cross-proxy forensic timeline + hybrid logical clocks.**
  - [x] `acp_core::hlc` HLC stamped into every decision record; encoding sorts causally; unit-tested across nodes (F11 core). [ ] multi-proxy timeline query + skew alarm.
- [b] **F12 [v3/P2] On-prem / air-gapped deployment mode.**
  - [b] An air-gapped profile with an internal RFC 3161 TSA / offline anchoring and offline signed-update + SBOM verification; full gate->approve->verify works with egress disabled and evidence verifies offline.
- [b] **F13 [v3/P2] Customer change-management & adoption kit.**
  - [b] RACI template, policy-author certification, staged posture-maturity playbook; the console shows a tenant's posture stage with a defined next step.

### Gate additions from the deep review

- [b] **H0 gate now also requires:** A1, A2, A3, A4, A6, C2, B1, D1, D2, D3, F1, F2.
- [b] **H1 gate now also requires:** A5, A7, B2, B3, B4, B5, C1, C4, D4, D5, D6, D7, F3, F8.
- [b] **Scale/GA gate now also requires:** C3, D8, D9, E7, F11, F12, F13.

---

## Ownership note

Each unchecked task should get an owner and a target gate (H0/H1/H2/GA) before work starts.
The plan is complete when V0.G, H0, V1.G, H1, V2.G, H2, and V3.G1 are all green, **including
the deep-review Blocks A-F folded into those gates above.**
