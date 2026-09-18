# ACP platform architecture: governing the AI landscape end to end

Date: 2026-09-18
Status: reference architecture and north-star. It extends `docs/positioning.md` (the wedge) and `docs/design/model-v2.md` (the enforcement-and-evidence core) upward into a full org AI-governance platform. Honesty markers on every component: [BUILT] shipped and tested, [PARTIAL] some of it exists, [TO BUILD] not started, [INTEGRATE] connect a best-of-breed system rather than build it.

## 0. The core idea

Governing "the AI landscape" looks impossibly broad until you see the pattern: **one control plane, many enforcement points**. A single brain (policy + identity + evidence + emergency) drives many thin adapters, each of which intercepts one class of AI action, builds a trusted context, asks the shared decision point, enforces the answer, and writes the same tamper-evident evidence. Adding coverage of a new AI surface is adding an enforcement point (a PEP), not building a new platform. ACP already is this brain and one PEP (the MCP proxy). The platform is that brain plus a PEP for every surface.

This is what keeps the effort finite and keeps ACP in its defensible lane: it stays the neutral authorization-identity-evidence core and integrates outward for content safety and compliance, rather than trying to become a content firewall or a GRC suite.

## 1. The AI landscape surface (what must be governed)

| Surface | Example | Governed by |
|---|---|---|
| Agentic tool calls (MCP) | a coding agent calling `db.query`, `charge_card` | ACP MCP proxy [BUILT] |
| Agent non-MCP powers | the same agent running shell, editing files, direct HTTP | agent-native sandbox, driven by ACP-generated config [TO BUILD] |
| Direct model API access | an app/service calling OpenAI/Anthropic/Bedrock directly | ACP LLM gateway [TO BUILD] |
| Enterprise chat assistants | ChatGPT Enterprise, Copilot Chat, Gemini | vendor admin APIs + DLP connectors [INTEGRATE] |
| Embedded SaaS AI | Notion AI, Salesforce Einstein | CASB / DLP / Purview connectors [INTEGRATE] |
| RAG / data access | retrieval over a vector store, training data | resource-model governance via a data gateway [PARTIAL] |
| Model lifecycle | which models are approved, their risk class | GRC plane [TO BUILD / INTEGRATE] |
| Shadow AI | un-sanctioned AI tools staff adopt | discovery plane [TO BUILD] |

The point of the table: ACP's model (subject, resource, operation, context) already generalises across all of these. The action differs (tool call vs completion request vs file read), but "which identity may perform which operation on which resource, under what conditions, with what evidence" is the same question everywhere.

## 2. Governance dimensions (what governance means)

Every surface needs some subset of: authorization (allow/deny/step-up/obligations), content safety (injection, PII, toxicity, data-leak), identity (verified agent and human, delegation), evidence (tamper-evident, non-repudiable), emergency control (kill-switch), compliance (framework mapping, attestation), discovery (find it first). ACP owns authorization, identity, evidence, and emergency; it integrates content and compliance; it must grow discovery.

## 3. The plane architecture

```
                        ┌───────────────────────── GOVERNANCE / GRC PLANE ─────────────────────────┐
                        │  use-case inventory · EU AI Act / NIST RMF mapping · risk register ·      │  [TO BUILD/INTEGRATE]
                        │  attestations · reports         (or feed Credo / OneTrust)                │
                        └───────────────────────────────▲──────────────────────────────────────────┘
                                                         │ signed evidence projection
   ┌──────────────── CONTROL PLANE (the brain) ─────────┼───────────────────────────────────────────┐
   │  registry: teams · agents · humans · resources     │   policy: authoring · signing · versioning │
   │  [BUILT, single-tenant]                             │   · distribution  [BUILT]                  │
   │  taxonomy admin (tool->resource, impact) [PARTIAL]  │   RBAC + multi-tenant [TO BUILD]           │
   │  console [BUILT]                                    │   emergency: fleet kill-switch [BUILT-MCP] │
   └───────┬───────────────────┬───────────────────┬────┴─────────────────┬──────────────────────────┘
           │ same PDP          │ same identity      │ same evidence ledger │ same kill-switch
   ┌───────▼──────┐  ┌─────────▼────────┐  ┌────────▼───────┐  ┌───────────▼──────────┐   ENFORCEMENT PLANE
   │ MCP proxy    │  │ LLM gateway      │  │ agent-native   │  │ SaaS / data          │   (many PEPs, one brain)
   │ [BUILT]      │  │ [TO BUILD]       │  │ policy sync    │  │ connectors           │
   │ tool calls   │  │ completion calls │  │ [TO BUILD]     │  │ [INTEGRATE]          │
   └───────┬──────┘  └─────────┬────────┘  └────────┬───────┘  └───────────┬──────────┘
           │ obligation hooks  │                    │                      │
   ┌───────▼───────────────────▼────────────────────▼──────────────────────▼──────────┐  CONTENT PLANE
   │  injection detection · PII / DLP · toxicity · groundedness   (Lakera, Azure AI     │  [INTEGRATE]
   │  Content Safety, Llama Guard)  called as obligations, never rebuilt                │
   └────────────────────────────────────────────────────────────────────────────────────┘
           ▲                                                                         ▲
   ┌───────┴──────────────┐                                          ┌───────────────┴────────────┐
   │ IDENTITY PLANE        │                                          │ DISCOVERY PLANE            │
   │ Entra/Okta OIDC (human)│                                         │ egress telemetry · MCP     │
   │ SPIFFE (workload)      │  [PARTIAL: acp-auth, Entra mocked]      │ discovery · shadow-AI      │  [TO BUILD]
   │ SCIM provisioning      │                                          │ -> feeds the registry      │
   └────────────────────────┘                                          └────────────────────────────┘
                                        │ evidence export
                                 ┌──────▼───────┐
                                 │  SIEM / SOC  │  [INTEGRATE]
                                 └──────────────┘
```

### Control plane (the brain) [BUILT, to harden]
The single source of truth. Registry of teams/agents/humans/resources, the signed and versioned policy store, the taxonomy, RBAC, and the console. Built today as single-tenant; the platform needs multi-tenant isolation and role-based access (who may author policy, who may trip the kill-switch, who may register agents). One brain, so every enforcement point decides the same way and every action lands in one ledger.

### Policy plane (the shared PDP) [BUILT for tool calls]
The model-v2 engine: `(subject, resource, operation, context) -> effect + obligations`, default-deny, deny-overrides. The same policy language compiles to each PEP's evaluation. Extending to new surfaces means teaching the context builder the new action's facts (a completion request has a model, a prompt, a token budget; a file read has a path and a data class), not inventing a new language.

### Enforcement plane (the PEPs) [one BUILT, others TO BUILD/INTEGRATE]
The thin adapters. Each intercepts a class of AI action and calls the shared PDP. The set:
- MCP proxy [BUILT]: agent tool calls.
- LLM gateway [TO BUILD]: a reverse proxy in front of model APIs. Governs direct model access (which app/human may call which model), enforces token/cost budgets, and calls the content plane on prompts and responses. This is how the platform covers all non-agentic direct usage.
- Agent-native policy sync [TO BUILD]: compile the same ACP policy DOWN into each coding agent's native managed-settings (Copilot/Claude/Gemini), so the agent's non-MCP powers (shell, file, direct network) are governed by the same source of truth the org already authored. ACP becomes the single policy origin; the agents remain the enforcers of their own sandbox. This bridges the exclusion-map gap without re-implementing sandboxing.
- SaaS / data connectors [INTEGRATE]: for embedded SaaS AI and data-plane governance, connect CASB/DLP/Purview rather than sit inline.

### Content plane [INTEGRATE]
Content safety as obligations the PEPs invoke: injection detection, PII/DLP, toxicity, groundedness. Best-of-breed (Lakera, Azure AI Content Safety, Llama Guard). ACP already models obligations (redact is built); wiring an external classifier as a `scan`/`redact` obligation is the integration. Never rebuilt.

### Identity plane [PARTIAL]
Verified agent identity [BUILT] plus a human principal [BUILT, degrades to unattributed]. The platform wires this to the org IdP: OIDC (Entra/Okta) for the human subject, workload identity (SPIFFE) for agents and services, SCIM for provisioning and deprovisioning. acp-auth exists; Entra is mocked. Real IdP wiring is the step that makes the human principal always verified rather than best-effort.

### Evidence plane [BUILT for MCP, to unify]
The tamper-evident Merkle ledger with signed tree heads, already recording agent, human, resource, operation, and verdict per decision. The platform unifies every PEP's events into this one ledger and exports to SIEM and to the GRC plane. Extending it to gateway and native events is additive: same record shape, new sources.

### Emergency plane [BUILT for MCP, to extend]
The scoped, signed, persistent kill-switch. Today it fans out to MCP proxies. The platform extends the same grant model to every PEP type, so "freeze all payments access across every surface" is one action.

### Discovery plane [TO BUILD]
Governance starts with knowing what exists. Egress telemetry to spot calls to model APIs, MCP-server discovery, and SaaS-AI detection, all feeding the registry so shadow AI becomes sanctioned-or-blocked. Without this, the platform only governs what was registered.

### GRC plane [TO BUILD / INTEGRATE]
Projects the ledger and policy into compliance artifacts: an AI use-case inventory, EU AI Act / NIST RMF / ISO 42001 control mapping, a risk register, attestations, and audit-ready reports. ACP is uniquely placed to make these *evidence-backed* rather than questionnaire-backed, because it holds the signed runtime record. Build a light layer, or feed Credo/OneTrust as their missing runtime source.

## 4. The enforcement-point (PEP) pattern

Every PEP, regardless of surface, is the same five steps:
1. Intercept one class of AI action in its path.
2. Establish the trusted identity (agent and/or human) from the transport, never from the payload.
3. Build the trusted context: classify the action into subject, resource, operation, and derived facts.
4. Ask the shared PDP; receive verdict plus obligations.
5. Enforce (allow / deny / step-up / obligations) and write the decision to the evidence ledger; honour the kill-switch.

Because the pattern is fixed, a new PEP is a small adapter, and every surface inherits identity, policy, evidence, obligations, and the kill-switch for free. This is the whole reason the platform is finite.

## 5. Coverage matrix

| AI surface | PEP | Status | What closes the gap |
|---|---|---|---|
| MCP agent tool calls | MCP proxy | [BUILT] | done |
| Agent shell/file/network | native policy sync | [TO BUILD] | compile ACP policy to vendor managed-settings |
| Direct LLM API | LLM gateway | [TO BUILD] | reverse proxy + budget + content hooks |
| Chat assistants | vendor admin + DLP | [INTEGRATE] | Purview / vendor enterprise controls |
| Embedded SaaS AI | CASB / DLP connector | [INTEGRATE] | connectors feed policy + evidence |
| RAG / data access | data gateway | [PARTIAL] | resource-model governance on retrieval |
| Model lifecycle / risk | GRC plane | [TO BUILD] | inventory + control mapping over the ledger |
| Shadow AI | discovery plane | [TO BUILD] | egress telemetry -> registry |

## 6. Making it unavoidable at org scale

Coverage on paper is not governance; the enforcement points must be the only path.
- Route all MCP agent traffic through ACP proxies (agent config via MDM; the enforcement attestation guard on tool servers, per `docs/design/enforcement.md`).
- Route all model API traffic through the LLM gateway (network egress policy: only the gateway may reach model endpoints; app config points at the gateway).
- Push agent-native config via MDM so the developer cannot loosen it.
- Discovery continuously checks for traffic that bypassed a PEP and alarms (the liveness/bypass detector already models this for MCP).
Unavoidability is an org rollout (network policy + MDM + gateway), enabled by the platform, not a single toggle. Say so plainly to anyone evaluating it.

## 7. Build vs integrate vs never

- Build: the control plane, the PDP, the PEPs (MCP proxy, LLM gateway, native policy sync), the evidence ledger, the identity wiring, discovery, and a light GRC projection.
- Integrate: content safety (Lakera/Azure/Llama Guard), the IdP (Entra/Okta), SIEM, CASB/DLP for SaaS, and optionally a full GRC suite (Credo/OneTrust) as an evidence consumer.
- Never: re-implement a content classifier, an IdP, a SIEM, or a coding agent's own sandbox. Those are other people's moats; ours is the neutral authorization-identity-evidence core across every surface.

## 8. Phased roadmap (core to full platform)

- Phase A (done): the MCP enforcement-and-evidence core. Model-v2 landed.
- Phase B: platform-ready control plane. Real IdP (OIDC + SPIFFE + SCIM), multi-tenancy, console RBAC, SIEM export. Makes the human principal always verified and the platform safe for many teams.
- Phase C: the LLM gateway PEP. Covers direct model API usage, the largest uncovered surface, with the same policy/identity/evidence/kill-switch.
- Phase D: agent-native policy sync. One authored policy compiles to Copilot/Claude/Gemini managed-settings, governing the agents' non-MCP powers from the same source of truth.
- Phase E: discovery plane. Egress telemetry and shadow-AI detection feeding the registry, so the platform governs what it finds, not only what was registered.
- Phase F: GRC projection. Evidence-backed use-case inventory and control mapping, exportable to auditors or to Credo/OneTrust.

Each phase is independently valuable and ships on the same brain; none requires a rewrite.

## 9. Honest status today

Phase A is real and tested. Everything in B to F is design, not code, with the honest markers above. The platform's credibility rests on not overclaiming: today ACP governs MCP agent tool calls end to end, with verified identity, tamper-evident evidence, obligations, tool-integrity, and a hardened kill-switch. The architecture here is how that core becomes full-landscape coverage without leaving its defensible lane, and the roadmap is the order to build it in.
