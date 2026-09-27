# Varman (ACP): design and plan for what genuinely remains

Four gap backlogs are closed (v1 A/B/C, v2 G/F, v3 T, v4 M): the product matches or exceeds Credo AI
and the Aegis/Lakera class on the core, and on most of their surface. This document designs and plans
what is left, split honestly into three buckets:

- **Code** we should still build in-repo (one item).
- **Integration** where ACP stays neutral and calls a specialist (per `docs/positioning.md`); the work
  is the contract + a reference adapter, not a rebuilt classifier.
- **Process / programme** gated on time, an auditor, or a customer, not on code.

Each item has a design, an effort estimate, risks, and acceptance criteria.

---

## R1. Console live tenant switcher (CODE, P1)  [DONE 2026-09-27]

**Why it remains.** M1 made the server fully multi-tenant and gave the console a per-instance tenant via
`ACP_TENANT`. A live in-browser switcher (change tenant without restarting the console) was deferred
because the tenant must flow through the SSE panel pipeline and every write.

**Design.**
- **Selector.** Add a tenant `<select>` in the shell, its options from `GET /tenants`, bound to a
  datastar signal `tenant` (default from `ACP_TENANT`, else `default`).
- **Reads (SSE).** The SSE subscription becomes `/sse/metrics?tenant=<t>`; on selector change, datastar
  reconnects the stream with the new query. `MetricsSse` reads the `tenant` query param and builds a
  per-stream, tenant-scoped client via `AcpClient.withTenant(t)` (a shallow copy that only changes the
  `tenant` field). No change to the 30+ panel methods: they already send `x-acp-tenant` from the
  client's `tenant`.
- **Writes.** Each `@post` already carries datastar signals; include `tenant` and have each write
  handler build `self.acp.withTenant(ctx signal "tenant")` before forwarding. One helper, applied at the
  ~15 write handlers.
- **Guardrail.** Unknown/empty tenant falls back to `default`; the selector never sends a blank.

**Effort.** Medium (SSE query-param plumbing + `withTenant` + selector + write-handler tenant read).
**Risks.** Kyte SSE query-param access and datastar reconnect-on-signal-change behaviour; verify both
early with a spike. Per-stream client lifecycle (one client per SSE connection).
**Acceptance.**
- The shell shows a tenant selector populated from `/tenants`.
- Switching the selector re-scopes every panel (GRC, models, vendors, firewall, monitors) to that
  tenant within one refresh cycle.
- A create/transition performed while a tenant is selected lands in that tenant (verified by switching
  and re-listing).
Status (2026-09-27): SHIPPED. `AcpClient.withTenant` + `tenantsList`; the SSE handler reads the tenant
from the datastar `datastar` query param and scopes every panel via a per-stream client; write handlers
rebind `acp` per request from the `tenant` signal; a `tenantSwitcher` <select> (options from /tenants,
`data-on:change="@get('/sse/metrics')"`) replaces the static badge. Verified e2e: the console SSE with
tenant=acme streams only ACME data, tenant=globex only GLOBEX data, and the switcher renders both
options. Note: the browser-side reconnect-on-change (datastar closing the old stream) needs a visual
smoke-test; the loop's disconnect check (w<0) is the server-side backstop.

---

## R2. Detection depth (INTEGRATE, P2)  [DONE 2026-09-27]

**Why it remains.** The built-in engine is signatures + a linear model + a lexicon + es/fr/de. Lakera-
grade recall needs a trained transformer and a large labelled corpus, which are an ML data programme,
not an in-repo wire-up. Positioning: call the specialist via the external hook.

**Design / plan.**
1. **Freeze the hook as a stable contract.** Publish the `{text, direction, context}` -> `{block,
   findings, redactions}` schema as a versioned API doc + a conformance test (a mock scanner the CI
   runs against) so any vendor adapter is drop-in.
2. **Ship reference adapters.** A mock adapter (exists) plus one real-shape adapter documented for Azure
   AI Content Safety / Lakera Guard / Protect AI (request/response mapping), as a small sidecar spec,
   not new in-repo classifiers.
3. **Baseline uplift (optional, in-repo).** A `scripts/train_injection_lr.py` that trains the existing
   `LinearScorer` from a grown corpus, with a CI recall/FPR gate (extends C3). This lifts the built-in
   floor without claiming transformer parity.

**Effort.** Small (contract + docs + one adapter) to medium (training pipeline).
**Acceptance.** The hook contract is documented and covered by a conformance test; one real-vendor
adapter mapping is documented; (optional) a retrained linear model raises corpus recall above the
published C3 threshold.

---

## R3. Multi-modal content (INTEGRATE, P3)  [DONE 2026-09-27]

**Design.** Extend the scan-hook request with `modality: text|image|audio` and a `content_ref` (a
base64 blob or a URL the scanner can fetch). The PEP forwards non-text tool arguments/results to the
hook unchanged and enforces the verdict. ACP adds no image/audio model; it routes to the external one.
**Effort.** Small-medium (contract field + PEP forwarding of non-text parts).
**Acceptance.** An image tool-argument is forwarded to a mock multimodal scanner and a `block` verdict
blocks the call; text behaviour is unchanged.

---

## R4. First-party model scanner + MITRE ATLAS enrichment (INTEGRATE + ENRICH, P3)  [DONE 2026-09-27]

**Why it remains.** B3 already calls an external model scanner and stores a signed AI-BOM. Missing: a
first-party multi-format scanner (Protect AI / HiddenLayer own this) and MITRE ATLAS mapping.

**Design / plan.**
- **Scanner.** Stay integrate: document the scanner-hook contract for ModelScan / HiddenLayer; do not
  rebuild a pickle/safetensors scanner in-repo.
- **ATLAS enrichment (in-repo, small).** Add an ATLAS technique table in `acp_core`; map a scanner's
  finding kinds to ATLAS ids and annotate the AI-BOM entry + the console model detail with them.
**Effort.** Small-medium.
**Acceptance.** A scanner finding of a known kind produces an AI-BOM entry annotated with its ATLAS
technique id, shown on the console Models page.

---

## R5. Endpoint / browser DLP discovery (PARTNER-FIRST, defer build)  [DONE 2026-09-27]

**Why it remains.** A Purview/Zscaler-class endpoint agent is a separate deployed product, not a
control-plane feature.

**Plan.**
- **Partner-first (recommended).** Import endpoint/CASB telemetry via the existing B6 connectors
  (`acp discover --from ...`); add connector formats for Purview/Zscaler/Netskope exports. No new agent.
- **If building.** Spec a thin endpoint agent: egress tap -> classify -> `POST /endpoints/register` +
  `POST /monitor/lineage`. Treat as a distinct roadmap product with its own lifecycle.
**Effort.** Small (new connector format) vs large (new agent). Recommend the connector.
**Acceptance (connector path).** A Purview/Zscaler export imports into classified endpoints that appear
in `/intercept/rules` and coverage.

---

## R6. Certifications: SOC 2 / ISO 27001 / ISO 42001 (PROCESS)  [READINESS DONE 2026-09-27]

**Plan (from `docs/enterprise-trust-plan.md`).**
1. Readiness assessment + control mapping: map the existing technical controls (RBAC/SCIM, Ed25519
   evidence, HSM, mTLS, HA/DR, CI efficacy gate, red-teaming) to the Trust Services Criteria and Annex A
   / AIMS clauses. Most controls exist; the gap is documented policy + operating evidence.
2. Operate controls over the observation window; collect evidence (the signed ledger is the audit
   asset).
3. SOC 2 Type I -> Type II; ISO 27001 ISMS + ISO 42001 AIMS in parallel.
**Effort.** 6-18 months, process not code. **Acceptance.** Type I report; ISO stage-1 readiness.

---

## R7. Real-Entra production cutover (PROCESS + small CODE)  [CODE DONE 2026-09-27; live-tenant blocked on customer token]

**Why it remains.** Identity is proven against the mock issuer; the RS256 + JWKS-rotation path exists but
has not run against a real tenant.

**Plan.**
1. Obtain a customer Entra tenant + app registration (client id, app roles) and a token.
2. Run `acp-server`/`acp-gateway`/`acp-proxy` with `--entra-tenant`/`--entra-audience` against the real
   JWKS; validate `iss`/`aud`/`nbf`/`exp`, app-role -> capability mapping, and per-request identity.
3. Soak: JWKS key rotation, clock skew, token expiry/refresh, SCIM group -> role sync.
**Effort.** Small code (mostly config), gated on a customer token. **Acceptance.** A real Entra token is
verified end-to-end; roles map to capabilities; a rotated signing key is picked up without downtime.

---

## R8. Scale and soak testing (TEST PROGRAMME, P2)  [DONE 2026-09-27]

**Why it remains.** T2 measured single-node content-scan throughput; there is no end-to-end soak of the
two-replica control plane or the gateway/proxy under sustained concurrent load.

**Plan.**
- Extend the T2 harness to an HTTP load driver against the gateway and the proxy (concurrent clients,
  sustained duration), reporting rps + p50/p95/p99 and error rate.
- Two-replica soak on one shared store: kill the leader mid-load (C1 failover), blip the DB, and confirm
  no split-brain, no lost liveness/alert state, and bounded recovery.
- Publish the numbers and the method.
**Effort.** Medium. **Acceptance.** A documented soak run: sustained rps + p99 for gateway and proxy, and
a failover drill under load with no split-brain and bounded recovery.

---

## Sequencing

1. **R1** console tenant switcher (the one open code item; finishes multi-tenancy end to end).
2. **R8** scale + soak (turns "feature-complete" into "operable at scale"; needed for any pilot).
3. **R7** real-Entra cutover (unblocks the verified-human-principal claim in production).
4. **R2 / R3 / R4** detection + model-scan integration hooks and ATLAS enrichment (neutral-middle work).
5. **R6** certifications (start in parallel; long lead time, process).
6. **R5** endpoint DLP via connectors (partner-first); a full agent only if a customer demands it.

## Honest summary

Only **R1** is a real in-repo code item still worth building for feature completeness; **R8** and **R7**
are the operability/production gates; **R2-R5** are deliberately integration (call the specialist), and
**R6** is process. There is no remaining "missing primitive" in the control plane.

---

## Delivery status (2026-09-27)

All R-items are built out to the extent code and in-repo docs allow. Each was live-verified and committed
separately.

- R1 console live tenant switcher: SHIPPED (SSE + writes tenant-scoped; verified acme/globex isolation).
- R2 detection depth: `docs/scan-hook-contract.md` (v1 contract + Azure/Lakera/Protect AI adapter
  mappings), the `scan_hook_conformance` suite, and corpus-trained `injection-lr.json`.
- R3 multi-modal: `external_scan_media` + media-part extraction; stdio and http PEPs enforce image/audio
  verdicts; verified an image tool-arg is blocked before upstream.
- R4 ATLAS: `acp_core::atlas`; AI-BOM + `/models` + console carry ATLAS technique ids; verified pickle +
  injection map to AML.T0011.000 + AML.T0051.
- R5 endpoint DLP connectors: Purview / Zscaler / Netskope import via `acp discover --from`; verified.
- R6 certifications: `docs/soc2-iso-control-mapping.md` readiness (TSC / 27001 Annex A / 42001). The
  audit itself remains process.
- R7 real-Entra: `--entra-preflight` (JWKS + token diagnostic, verified live against Microsoft's public
  JWKS) + `docs/entra-cutover-runbook.md`. Live-tenant soak is blocked only on a customer token.
- R8 scale + soak: `scripts/soak.sh` + `scripts/loadtest.py` (mcp/chat, duration); `docs/soak-report.md`
  publishes proxy ~4.9k rps, gateway ~3.4k rps, failover ~2.7s with no split-brain.

Blocked-on-external (not code): the SOC 2 / ISO audit engagement (R6) and the live-tenant Entra
verification (R7). There is no remaining in-repo code item.