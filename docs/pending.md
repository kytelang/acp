# Pending work

Date: 2026-09-20
Status: the single list of what is left to make ACP a complete, single-product AI governance platform (Credo-class GRC plus an AI firewall plus the neutral runtime-authorisation gaps). Everything not listed here is built and tested. Reads with `docs/gap-analysis.md` (section 7.1 and 9), `docs/positioning.md`, and the design docs referenced below.

## How to read this

Each item has: what it is, why it matters, current status, whether it is code or ops or environment-dependent, and the design doc that specifies it. "Integrate by design" items are deliberately not built (ACP calls an external system) and are listed only so the boundary is explicit, not as debt.

## P0: the one thing that materially separates ACP from a real firewall

### 1. ML-based content engine
- What: replace the deterministic signature/regex content engine with trained ML classifiers (injection and jailbreak, toxicity, PII NER, topical guard), behind the existing `ContentPolicy`/`ContentVerdict` seam.
- Why: the current first-party firewall (`acp_core::content`) catches known-shape attacks only. To match Lakera, Cisco AI Defense or Protect AI against novel, paraphrased and obfuscated attacks, it needs trained models. This is the single biggest gap to being a credible firewall rather than a baseline filter.
- Status: designed, not built. `docs/design/ml-based-content-engine.md`.
- Type: code (large), plus a training and evaluation pipeline and model artifacts.
- No LLM required for the baseline: small encoder classifiers on CPU via ONNX Runtime, fully on-prem. A small local guard LLM is optional and opt-in, never a cloud LLM.
- Phasing (from the design doc):
  1. Introduce the `Scorer` seam and refactor the current engine into `SignatureScorer` behind it. Pure refactor, zero behaviour change, no models needed. Safe first step. DONE (`acp_core::content`: Scorer/Signal/ContentEngine/verdict_from; scan_text unchanged; 339 workspace tests).
  2. Build the `acp-content` sidecar (ONNX Runtime) with the injection or jailbreak detector only; wire the gateway and proxy to call it with the signature pre-filter and fail-closed fallback; ship in shadow mode.
  3. Add the PII or secret NER detector plus the redaction path, then the safety or toxicity detector, then the topical guard.
  4. Wire evidence (model id, version, score, threshold), the classify-eval CI gate, and the tuning, shadoweval, drift and posture loops for promotion.
  5. Optional: the guard-LLM heavy detector for customers who accept its latency.

## P1: full GRC depth and production readiness

### 2. GRC assessment-workflow depth
- What: deeper native impact and conformity assessment workflows and a model-card lifecycle, beyond the current control library, EU AI Act tiering, attestations, use-case lifecycle and risk register.
- Why: for full Credo-class parity as a standalone GRC programme, not just the evidence and register that feed one.
- Status: DONE. Conformity workflow (`acp_core::conformity`, `acp conformity`) turns the obligation list into a worked, evidence-linked checklist with a conformance report; model cards (`acp_core::modelcard`, `acp modelcard`) add the core GRC artifact. Alongside the existing control library, EU AI Act assessment, attestations, use-case lifecycle and risk register, the native GRC programme is now Credo-class in depth.
- Type: code.
- Refs: `docs/gap-analysis.md` section 7.1; `acp_core::assessment`, `acp_core::controls`, `acp_core::attestation`, `acp_core::usecase`, `acp_core::riskregister`.

### 3. Production hardening: HA, DR and shared state
- What: high availability control plane, disaster recovery, and shared or distributed state for budgets and tool-integrity pins across multiple PEP instances.
- Why: to be resilient and correct when running more than one gateway or proxy replica.
- Status: designed, not built. `docs/design/p2-operations.md`.
- Type: mostly ops and deployment. The in-process part that is code is the shared-state abstraction (Redis or Postgres backed budgets and pins); the rest (replication, failover, VIP, backups) is deployment.
- DONE (trait + in-process + Postgres + gateway adoption): `acp_core::sharedstate`, `acp-pgstate` (Postgres budgets and pins, verified against live PG), and the gateway's rate_limit path now uses it via `--budget-pg` (verified: two replicas share one budget). REMAINING: proxy tool-pin sharing via PG (the proxy dispatch is sync while PgState is async; low priority since pins are TOFU-stable). The in-process default stays for single-instance.

### 4. Real-Entra cutover
- What: switch verified-human-principal from the mock OIDC path to a real Microsoft Entra tenant.
- Why: to prove the identity claim in production, not only against the mock.
- Status: open, environment-dependent. The code path is built and tested against the mock; only the live cutover remains.
- Type: environment-dependent. Needs the operator to run `az account get-access-token` and provide the audience, issuer and roles, then start the server with `--entra-tenant` and `--entra-audience`.
- Refs: `docs/design/entra-setup.md`.

## P2: completeness and polish

### 5. Browser extension: run-verification and packaging
- What: the generated Chromium MV3 extension (`acp intercept extension`) is a scaffold that passes `node --check` but has not been loaded and driven in a real browser here; it also needs packaging for enterprise force-install.
- Why: to make the browser surface a supported, verified deployment path.
- Status: generated and syntax-valid, not browser-verified. Firefox (MV2/MV3 differences) is not covered.
- Type: code plus manual browser verification.
- Refs: `docs/design/traffic-interception.md` phase 4.

### 6. Keep-alive and HTTP/2 in the interception proxy
- What: the forward proxy and the MITM path inspect one request per connection (Connection: close upstream) and speak HTTP/1.1 only (ALPN http/1.1); an HTTP/2-only client fails the handshake and is recorded as pinning-or-handshake-failed.
- Why: some SDKs and browsers prefer or require HTTP/2; supporting it would widen coverage and improve throughput.
- Status: documented limitation, working as designed.
- Type: code (non-trivial: h2 MITM is complex).
- Refs: `docs/design/traffic-interception.md`; `crates/acp-intercept/src/mitm.rs`.

## Integrate by design (not debt, listed for clarity)

These are deliberately not built because another category owns them and ACP connects rather than rebuilds (per `docs/positioning.md`). They are complete as seams.

- Model and artifact scanning. ACP runs the supply-chain admission gate and the AI-BOM and calls an external scanner (for example Protect AI ModelScan) for the verdict. `acp_core::supplychain`, `acp aibom`.
- Content ML from a specific vendor. The external content-scan hook stays available alongside the first-party engine for customers standardised on a particular ML classifier.
- Model bias, fairness, drift and explainability dashboards. ACP feeds runtime-decision evidence to the monitoring vendors that own this; it has counts-only drift and anomaly signals, not statistical model monitoring.
- Ticketing and CASB connectors. ACP exports to SIEM (CEF, OCSF, OTLP, syslog) and hands MDM and CASB an allow and block list; deeper ITSM and CASB integrations are connectors, not core.
- IdP beyond Entra or OIDC. Other identity providers are integrations.

## Snapshot of what is already done

For contrast, so the pending list is read against the whole. All of the following are built and tested (workspace 336 tests, 0 failures at last run):

- Runtime per-action authorisation at the resource boundary, verified agent and human identity, delegation.
- Tamper-evident Merkle evidence ledger, `acp verify`, SIEM export (CEF, OCSF, OTLP, syslog).
- Human approvals with separation of duty; scoped, signed kill-switch across surfaces.
- Tool-integrity pinning; supply-chain admission gate and signed CycloneDX AI-BOM.
- Unavoidability as a measured posture: enforcement guard sidecar (`acp-guard`), signed coverage attestation (`acp coverage`), egress canary (`acp canary-egress`), gateway base-URL pinning.
- Shadow-AI discovery and the signed enrollment loop with an MDM and CASB export.
- First-party content firewall (signatures, PII and secret detection, redaction, denied topics) native on both the gateway and the MCP proxy.
- GRC: control library, EU AI Act assessment and conformity obligations, signed attestations, use-case lifecycle with gates, evidence-linked risk register, framework reports.
- The full configuration-driven traffic-interception layer: endpoint registry and matcher, forward proxy (block, pass, inspect), TLS interception (MITM) with per-host leaf minting and pinning detection, PAC and browser-extension generation, and the discovery to enrollment to coverage loop.

## Status of the order

1. ML-engine phase 1 (the `Scorer` seam refactor): DONE.
2. Shared-state abstraction for budgets and pins (trait + in-process stores): DONE. Redis/Postgres implementation and hot-path adoption remain (need a live server to verify).
3. GRC assessment-workflow depth (conformity workflow + model cards): DONE.
4. ML-engine phases 2 to 4 (the actual classifier + eval gate): DONE (baseline). A trained hashed-n-gram logistic-regression detector (`LinearScorer` + `scripts/train_injection_lr.py`, `--content-ml`) blocks paraphrases the signatures miss (verified e2e), with an eval harness and CI gate (`eval_injection`, `acp content-eval`, held-out set at models/injection-eval.json). Hardened against obfuscation: detection runs on a normalised view (zero-width strip, homoglyph fold, base64 decode, whitespace collapse) and tool RESULTS are screened for indirect injection (`screen_response`), not just prompts and arguments. Upgrade path (small-encoder / ONNX Runtime, guard LLM) remains optional for broader coverage. Note: detection is defence in depth; the authorisation layer is what actually contains a successful injection.
5. Real-Entra cutover: DEFERRED by decision (mock Entra for now); the code path is built and tested against the mock. Flip when a tenant token is provided.
6. Browser-extension: routing logic run-verified via scripts/verify_pac.js (emulates Chrome PAC helpers; governed->PROXY, benign/spoofed->DIRECT). REMAINING: loading the unpacked extension in a real Chrome (native file picker, not automatable here) and enterprise packaging.
7. HTTP/2 in the interception proxy: deferred (complex, marginal); working as designed on HTTP/1.1.

Nothing further can be finished and verified in-repo without one of the external inputs above.
