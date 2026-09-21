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
  1. Introduce the `Scorer` seam and refactor the current engine into `SignatureScorer` behind it. Pure refactor, zero behaviour change, no models needed. Safe first step.
  2. Build the `acp-content` sidecar (ONNX Runtime) with the injection or jailbreak detector only; wire the gateway and proxy to call it with the signature pre-filter and fail-closed fallback; ship in shadow mode.
  3. Add the PII or secret NER detector plus the redaction path, then the safety or toxicity detector, then the topical guard.
  4. Wire evidence (model id, version, score, threshold), the classify-eval CI gate, and the tuning, shadoweval, drift and posture loops for promotion.
  5. Optional: the guard-LLM heavy detector for customers who accept its latency.

## P1: full GRC depth and production readiness

### 2. GRC assessment-workflow depth
- What: deeper native impact and conformity assessment workflows and a model-card lifecycle, beyond the current control library, EU AI Act tiering, attestations, use-case lifecycle and risk register.
- Why: for full Credo-class parity as a standalone GRC programme, not just the evidence and register that feed one.
- Status: partially closed. The heavier workflow product is currently left to an external GRC platform (positioning). Build only if full native parity is the goal.
- Type: code.
- Refs: `docs/gap-analysis.md` section 7.1; `acp_core::assessment`, `acp_core::controls`, `acp_core::attestation`, `acp_core::usecase`, `acp_core::riskregister`.

### 3. Production hardening: HA, DR and shared state
- What: high availability control plane, disaster recovery, and shared or distributed state for budgets and tool-integrity pins across multiple PEP instances.
- Why: to be resilient and correct when running more than one gateway or proxy replica.
- Status: designed, not built. `docs/design/p2-operations.md`.
- Type: mostly ops and deployment. The in-process part that is code is the shared-state abstraction (Redis or Postgres backed budgets and pins); the rest (replication, failover, VIP, backups) is deployment.
- Concrete next code step: a `Store` trait for budgets and pins with an in-process default and a Redis-backed implementation, keyed `budget:{app}:{resource}` and `pin:{server}:{tool}`, check-and-decrement done atomically.

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

## Suggested order

1. ML-engine phase 1 (the `Scorer` seam refactor): safe, no models, unblocks the firewall upgrade.
2. Shared-state abstraction for budgets and pins (the code half of production hardening).
3. ML-engine phases 2 to 4 (the actual classifiers), once a training and evaluation pipeline is in place.
4. Real-Entra cutover, when a tenant token is available.
5. GRC assessment-workflow depth and browser-extension verification, as needed.
