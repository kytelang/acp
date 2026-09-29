# Model suitability audit: Varman

An audit of Varman's data model and enforcement architecture against how mature AI governance and AI
security products are built, and against what the governing standards actually require. It covers the
governance (GRC) model, the identity model, and the content-firewall topology.

Provenance: the competitive research in this audit was done with live web access DENIED in this
environment, so vendor-specific claims are from working knowledge (training through early 2026) and
should be re-verified against current product documentation before external use. The standards analysis
(EU AI Act, ISO/IEC 42001, NIST AI RMF) and the code-level findings are grounded and reliable.

---

## 1. Verdict

Varman is a sound MVP with two genuine, differentiating strengths (signed, tamper-evident evidence and
an exhaustive embedded control catalogue, both on-prem). But the audit finds two structural issues that
will limit it as it scales, plus a set of engineering-consistency gaps.

- **Governance model:** the flat `grc_records` table keyed by a free-text `subject` string is the right
  shape for signed attestations, but it is missing the relational spine every mature governance product
  and every standard is built around: a first-class **AI system / use-case** entity, roles per system,
  a persisted **Statement of Applicability**, **evidence with freshness and owner**, and a real
  **control crosswalk**. This is already anticipated by Part B0 of the plan; the audit strongly
  validates that direction and sharpens it.
- **Firewall topology (the more important new finding):** the single-egress-proxy is the correct choice
  for the stated operational pain and for coarse shadow-AI DLP, but it is NOT the model the mainstream
  AI-security products use for identity-rich enforcement. At a generic egress proxy you have an IP and a
  host name, not an agent or a human, so the rich policy model (match on app, agent, group, tool) is
  starved of the identity it needs. The mainstream model is a **reverse LLM gateway with per-agent
  virtual keys**, with an egress forward proxy as a complementary DLP net. Varman already has the pieces
  (an LLM gateway, an MCP/tool proxy that carries identity, and the egress intercept); the fix is to be
  explicit about which plane does identity-rich policy and which does coarse egress DLP.

Bottom line: the primitives are right (signed records, catalogue, on-prem, two enforcement layers). The
gaps are relational structure on the governance side and identity-plane clarity on the firewall side.
Neither requires a rewrite; both are additive.

---

## 2. What is genuinely suitable (keep these)

- **Signed, immutable evidence and `report_snapshots`.** This maps to the "factsheet / immutable
  snapshot" layer every serious platform has, and being cryptographically signed and on-prem is ahead of
  several SaaS incumbents. Keep it as the top layer.
- **Embedded YAML control catalogue (12 frameworks, 494 controls) + conformance engine.** A legitimate
  "author once, grade many" corpus, versioned with the binary and un-tamperable per tenant. Keep YAML as
  the signed source of truth.
- **Two explicit enforcement layers** (policy authorization vs content firewall). The separation is
  correct and matches how the field thinks about it.
- **Single egress proxy for shadow-AI discovery and coarse DLP.** For catching unsanctioned AI
  destinations, blocking known-bad hosts, secrets scanning on outbound text, and a site-wide violation
  trail, one deployment per site is the right operational call. The pain it solves (per-workstation =
  ticket flood) is real.
- **App to Agent identity with per-agent credentials.** The credential model (one-time token, only the
  hash stored) is sound.

---

## 3. Governance model findings

The consensus spine across Credo AI, Holistic AI, IBM watsonx.governance, ServiceNow, OneTrust and
Microsoft Purview, and the requirements of EU AI Act / ISO 42001 / NIST AI RMF, is the same: a
normalised inventory plus control library plus evidence join tables, with an immutable snapshot layer on
top. Measured against that:

| # | Finding | Severity |
| :-- | :-- | :-- |
| G1 | **No first-class AI-system entity.** `subject` is a free string, so role, versions, incidents and evidence cannot be reliably joined to one system; a typo forks the file. Every standard is system-anchored. | P0 |
| G2 | **Role is not per-system.** `SubjectProfile` carries a single role, but the EU AI Act makes role a per-(system, market, jurisdiction) fact. An org that is provider of one system and deployer of another cannot be represented without duplicating subjects. | P0 |
| G3 | **No persisted Statement of Applicability.** The engine computes applicable controls and grades a checklist, but ISO 42001 requires a stored SoA with justification for inclusion AND exclusion. A computed set with no stored rationale will fail an ISO audit. | P0 |
| G4 | **Evidence has no freshness or owner.** Evidence is buried in record bodies with no valid-from / expiry / next-review or owner. Reporting green off a two-year-old test is exactly what auditors reject; freshness must gate the grade. | P1 |
| G5 | **Crosswalk is a per-control string field, not a relation.** "Author evidence once, satisfy many frameworks" cannot be queried. This is the single feature that most distinguishes a governance product from a checklist, and it is under-built. | P1 |
| G6 | **Incident and post-market monitoring not linked to a system.** `incident` is a record kind with no FK to a system, so it cannot feed EU AI Act Art. 72/73 or close the Art. 9 risk loop. | P1 |
| G7 | **No change-history / audit trail of the governance records themselves.** Signing gives snapshot integrity, not a mutation log ("who downgraded this control from applicable to N/A, and when"). ISO internal audit and management review need it. | P2 |
| G8 | **Latest-only, not time-series.** If the engine grades "latest", the EU AI Act Art. 9 iterative risk process and NIST MEASURE-over-time are lost. Need versioned assessments and "as at date" projection. | P2 |
| G9 | **Catalogue-recompute immutability leak.** Applicable controls are recomputed at render time, so a catalogue upgrade can retroactively change what a past signed record "should have" contained. Pin the catalogue version into each record and snapshot. | P1 |

Governance recommendations (prioritised):

1. Introduce a first-class `ai_system` entity (`id, tenant_id, name, purpose, owner, lifecycle_state, risk_tier, sector, versions[]`) and make `grc_records.subject` a FK. (P0, fixes G1)
2. Model role as `(system, role, jurisdiction, market_date)` rows, not a scalar. (P0, fixes G2)
3. Persist the SoA: per control, applicable flag + inclusion/exclusion justification + status. Keep the engine to PROPOSE the set. (P0, fixes G3)
4. Materialise the catalogue into DB tables at load (`framework`, `control`, `crosswalk(control_id, maps_to, citation)`) keyed by catalogue version; keep YAML authoritative. Turns crosswalk into a query. (P1, fixes G5, part of G9)
5. Promote evidence to a first-class table (`id, system_id, control_id, source, produced_at, valid_until, owner, artefact_ref, signature`); make freshness gate grading. (P1, fixes G4)
6. Add system FKs on incidents and a post-market-monitoring-plan entity. (P1, fixes G6)
7. Add an append-only change log over governance records; add catalogue_version to records and snapshots; support as-at-date projection. (P2, fixes G7/G8/G9)

Most of this is Part B0 of the existing plan. The audit confirms Part B0 is the right next investment
and adds G2 (role per system), G4 (evidence freshness), G7 (change log) and G9 (version pinning) as
explicit requirements.

---

## 4. Firewall topology findings

The mature LLM-security products are overwhelmingly either (a) an OpenAI-compatible reverse proxy that
IS the model endpoint (LiteLLM, Portkey, Cloudflare AI Gateway) with identity carried by per-agent
virtual keys, or (b) an in-process SDK / co-located microservice (NeMo Guardrails, LLM Guard, Lakera).
A true egress forward proxy with TLS interception is used only by the shadow-AI / CASB DLP products
(Prompt Security, Zscaler / Netskope families), and they accept its limits. The code confirms Varman's
egress intercept works on network signals (block/pass on HTTPS at the CONNECT stage by host, plain-HTTP
body inspection, TLS MITM as a later phase).

| # | Finding | Severity |
| :-- | :-- | :-- |
| F1/F2 | **Egress identity: PARTIALLY RESOLVED.** The workstation agent now signs a short-lived egress-identity assertion (acp_core::egress::EgressIdentity); the egress intercept verifies it (optionally pinned via --identity-pubkey) and attributes deny events to a real agent+principal instead of an IP. Remaining: wiring the agent to inject the header on every outbound request, TLS-MITM body inspection quality, and HA. Original finding: identity attribution at egress, With everyone behind one proxy you have a workstation IP, not an agent or a human. The policy manifest matches app/agent/group/tool, but a raw TLS flow cannot populate those fields. The rich policy model is starved of identity. | P0 |
| F2 | **Application vs host granularity.** `host_contains/sni/path` cannot tell "payroll-agent calling OpenAI" from "marketing-bot calling OpenAI": same host. Per-application policy degrades to per-destination policy at egress. | P0 |
| F3 | **TLS interception cost and risk.** Content inspection needs MITM: a CA on every client, breakage on cert-pinned / mTLS / QUIC-HTTP3 endpoints, and one box becomes a plaintext honeypot of every prompt, a high-value target and a compliance concern. | P1 |
| F4 | **Single choke point.** One proxy is an availability and latency SPOF with no HA story yet. | P1 |
| F5 | **Bypass.** Any flow not routed through the proxy (DoH, direct IP, VPN, a container with its own egress) is invisible. `block_on_scanner_error` fails closed on inspection, but not on bypass. A trivially bypassable firewall gives false assurance. | P1 |
| F6 | **Inspection quality on the wire.** At egress you see chunked SSE, gzip/br, tool-call JSON, not the app's clean prompt/completion. Injection and toxicity classifiers are far less reliable on reassembled streams. | P2 |

Firewall recommendations (prioritised):

1. **Add a reverse LLM-gateway mode alongside egress.** Let `acp-agent` expose an OpenAI/Anthropic-compatible endpoint that sanctioned apps and agents target with a per-agent virtual key. This is where you get real identity, clean prompt/response, per-application policy and reliable classification, and it is exactly what makes the existing app/agent/group/tool manifest usable. Keep egress as the shadow-AI net. (P0, fixes F1, F2, F6 for sanctioned traffic)
2. **Fix identity at egress now.** Require authenticated proxy sessions: a per-agent client certificate or a signed identity header injected by the workstation-side `acp-agent`, so violations and policy carry a real principal, not an IP. Reject unauthenticated egress when policy demands attribution. (P0, mitigates F1)
3. **Classify LLM traffic explicitly** from a managed endpoint catalogue (tenants add self-hosted models), tag flows `llm` vs `web`, and deep-inspect only the former to bound latency. (P1, fixes F2/F6 partially)
4. **HA and scale plan:** active/active proxies over a shared policy+event store, health-checked; document fail-open vs fail-closed per rule. (P1, fixes F4)
5. **Close bypass gaps:** pair the proxy with network-layer default-deny egress (only the proxy reaches the internet), block DoH, detect direct-IP LLM connections. (P1, fixes F5)
6. **Offer a thin SDK/sidecar tier** for the highest-value in-house agents needing conversation-aware rails (tool-arg inspection, response grounding) the wire cannot provide. (P2)

The framing to adopt: **egress proxy = shadow-AI discovery and coarse DLP (best-effort, network-level);
reverse LLM gateway + MCP/tool proxy = identity-rich, per-app, per-agent enforcement (the primary
plane).** They are complementary layers, not substitutes. Varman already ships the gateway and the
identity-carrying MCP proxy, so this is positioning and wiring, not new invention.

---

## 5. Cross-cutting engineering findings (code-level)

| # | Finding | Severity |
| :-- | :-- | :-- |
| E1 | **Resolved (documented two-plane model).** Governance/config is tenant-scoped; the enforcement/telemetry plane (firewall_rules, endpoints, violations, drift, lineage) is deployment-scoped by design, because a single egress proxy enforces one domain (`intercept_rules` has no tenant). See docs/schema.md section 6. Original finding: inconsistent multi-tenancy, `apps`, `agents`, `models`, `grc_records`, `report_snapshots`, `firewall_config` carry `tenant_id`, but `firewall_rules`, `violation_events`, `endpoints`, `drift_counts`, `lineage_edges`, `ingested_evidence`, `control_packs` do NOT. So firewall rules, violations, the governed endpoint set and monitoring are effectively global, not per tenant. Either commit to single-tenant-per-deployment (which fits the on-prem, one-egress-proxy-per-site direction and is the simpler, honest choice) or add `tenant_id` everywhere. Half-there tenancy is the worst option. | P1 |
| E2 | **Resolved (write-time validation).** An agent app_id must reference an existing app; a system sub-resource (role, SoA, evidence) must reference an existing ai_system; dangling references are rejected. Original finding: no referential integrity, `agents.app_id` is not validated against `apps`; `grc_records.subject` is a free string; `linked_refs` is free JSON. SQLite FKs are not enforced here, so dangling references are possible. This is the "ownership-by-string = corruption" hazard. | P1 |
| E3 | **Human principals are not in the control-plane store.** They are attributed per call and live in the registry/enrolment, with no principals table in the governance DB. Consistent identity querying and group-based reporting want them persisted. | P2 |
| E4 | **Evidence ledger scale at egress.** If every governed decision at a site-wide egress proxy is a Merkle leaf, volume and verification cost grow fast. Define what is ledgered vs sampled/aggregated (violations are already a bounded table); add rotation/compaction with retained tree heads. | P1 |

---

## 6. Prioritised roadmap

**P0 (structural, do first):**
- Governance: `ai_system` entity + role-per-system + persisted SoA (G1, G2, G3). This is Part B0.
- Firewall: reverse LLM-gateway mode with per-agent virtual keys, and egress identity injection (F1, F2).

**P1 (correctness and scale):**
- Governance: catalogue-in-DB + crosswalk relation, evidence-as-entity with freshness, incident/post-market FKs, catalogue-version pinning (G4, G5, G6, G9).
- Firewall: LLM-traffic classification, HA, bypass closure (F3, F4, F5).
- Engineering: decide the tenancy model and make it consistent; add referential integrity; define ledger scale strategy (E1, E2, E4).

**P2 (audit-grade and depth):**
- Governance: change-history log, as-at-date projection, time-series assessments (G7, G8).
- Firewall: SDK/sidecar tier, streaming inspection quality (F6).
- Engineering: persist human principals (E3).

The reassuring conclusion: Varman's genuine advantages (signed evidence, exhaustive catalogue, on-prem,
two enforcement layers) are the right primitives and are worth keeping. The work is to add relational
structure under the governance records and to make the identity plane explicit in the firewall, both
additive, and both already partly anticipated by the plan.
