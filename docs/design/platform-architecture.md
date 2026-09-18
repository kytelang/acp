# ACP platform architecture: governing the AI landscape end to end

Date: 2026-09-18
Status: reference architecture and north-star. Extends `docs/positioning.md` (the wedge) and `docs/design/model-v2.md` (the shipped enforcement-and-evidence core) into a full org AI-governance platform. Per-phase designs live in `phase-b-control-plane.md` ... `phase-f-grc.md`; the sequenced build is in `platform-plan.md`. Honesty markers: [BUILT], [PARTIAL], [TO BUILD], [INTEGRATE].

## 0. The core idea

Governing "the AI landscape" is finite because of one pattern: **one control plane, many enforcement points**. A single brain (policy, identity, evidence, emergency) drives many thin adapters (PEPs), each intercepting one class of AI action, building a trusted context, asking the same decision point, enforcing, and writing the same tamper-evident ledger. Covering a new surface is adding a PEP, not building a new platform. ACP already is the brain plus one PEP (the MCP proxy).

## 1. Context: what must be governed, and how ACP sits

```mermaid
flowchart TB
  subgraph LAND["Org AI landscape"]
    direction LR
    A1["Agentic tool calls<br/>(MCP)"]
    A2["Agent non-MCP powers<br/>shell / file / net"]
    A3["Direct LLM API<br/>calls"]
    A4["Chat assistants<br/>ChatGPT / Copilot / Gemini"]
    A5["Embedded SaaS AI"]
    A6["RAG / data access"]
  end
  subgraph ACP["ACP platform"]
    PEP["Enforcement plane<br/>(PEPs)"]
    CP["Control plane<br/>policy · identity · evidence · emergency"]
    PEP --> CP
  end
  subgraph EXT["Integrate, do not rebuild"]
    CF["Content firewall<br/>Lakera / Azure AI CS"]
    IDP["IdP<br/>Entra / Okta"]
    GRC["GRC<br/>Credo / OneTrust"]
    SIEM["SIEM / SOC"]
  end
  A1 --> PEP
  A2 --> PEP
  A3 --> PEP
  A4 --> PEP
  A5 --> PEP
  A6 --> PEP
  PEP -. "content obligations" .-> CF
  CP -. "verified identity" .-> IDP
  CP -. "signed evidence" .-> GRC
  CP -. "decision stream" .-> SIEM
```

## 2. The planes

```mermaid
flowchart TB
  subgraph GRCP["GRC / compliance plane  ·  TO BUILD / INTEGRATE"]
    G1["Use-case inventory"]
    G2["EU AI Act / NIST RMF mapping"]
    G3["Risk register · attestations · reports"]
  end

  subgraph CTRL["Control plane (the brain)  ·  BUILT, harden"]
    R["Registry: teams · agents · humans · resources"]
    POL["Policy: author · sign · version · distribute"]
    TAX["Taxonomies: tool→resource · impact"]
    RBAC["RBAC (BUILT)  ·  single-tenant on-prem"]
    KILL["Emergency: fleet kill-switch"]
    CON["Console"]
  end

  subgraph PDP["Policy plane - shared PDP  ·  BUILT"]
    ENG["model-v2 engine<br/>subject · resource · operation · context → effect + obligations"]
  end

  subgraph ENF["Enforcement plane - many PEPs, one brain"]
    P1["MCP proxy<br/>BUILT"]
    P2["LLM gateway<br/>TO BUILD"]
    P3["Agent-native policy sync<br/>TO BUILD"]
    P4["SaaS / data connectors<br/>INTEGRATE"]
  end

  subgraph CONT["Content plane  ·  INTEGRATE"]
    C1["injection · PII/DLP · toxicity · groundedness"]
  end

  subgraph IDN["Identity plane  ·  PARTIAL (Entra mocked)"]
    I1["OIDC human · SPIFFE workload · SCIM"]
  end

  subgraph EVD["Evidence plane  ·  BUILT for MCP"]
    E1["Merkle ledger + signed tree heads → SIEM"]
  end

  subgraph DIS["Discovery plane  ·  TO BUILD"]
    D1["egress telemetry · shadow-AI → registry"]
  end

  GRCP --> CTRL
  CTRL --> PDP
  PDP --> ENF
  ENF --> CONT
  IDN --> ENF
  ENF --> EVD
  DIS --> CTRL
```

Per-plane detail (purpose, components, status) is in the phase design docs. The one-line reading: the control plane authors and signs one policy, the shared PDP decides, and every PEP enforces the same decision and writes the same ledger.

## 3. The enforcement-point (PEP) pattern

Every PEP, whatever the surface, is the same five steps. This is why the platform is finite: a new surface is a small adapter that inherits identity, policy, evidence, obligations, and the kill-switch for free.

```mermaid
sequenceDiagram
  autonumber
  participant Caller as "Agent / app / user"
  participant PEP as "Enforcement point"
  participant IDP as "Identity plane"
  participant PDP as "Policy decision point"
  participant CONT as "Content plane"
  participant LOG as "Evidence ledger"

  Caller->>PEP: AI action (tool call / completion / file op)
  PEP->>IDP: resolve trusted identity (never from payload)
  IDP-->>PEP: agent + human principal (verified / unattributed)
  PEP->>PEP: classify → subject, resource, operation, context
  PEP->>PDP: evaluate(context)
  PDP-->>PEP: verdict + obligations
  opt obligation: scan / redact
    PEP->>CONT: inspect args / prompt / response
    CONT-->>PEP: findings (mask / block)
  end
  PEP->>LOG: append signed decision
  PEP-->>Caller: allow / deny / step-up / rewritten
```

## 4. Coverage matrix

| AI surface | PEP | Status | Closes the gap |
|---|---|---|---|
| MCP agent tool calls | MCP proxy | [BUILT] | done |
| Agent shell / file / network | native policy sync | [TO BUILD] | compile ACP policy to vendor managed-settings |
| Direct LLM API | LLM gateway | [TO BUILD] | reverse proxy + budgets + content hooks |
| Chat assistants | vendor admin + DLP | [INTEGRATE] | Purview / vendor enterprise controls |
| Embedded SaaS AI | CASB / DLP connector | [INTEGRATE] | connectors feed policy + evidence |
| RAG / data access | data gateway | [PARTIAL] | resource-model governance on retrieval |
| Model lifecycle / risk | GRC plane | [TO BUILD] | inventory + control mapping over the ledger |
| Shadow AI | discovery plane | [TO BUILD] | egress telemetry → registry |

## 5. Making it unavoidable at org scale

Coverage on paper is not governance; the PEPs must be the only path.

```mermaid
flowchart LR
  DEV["Developer / app"] -->|MDM-locked config| MCP["MCP proxy"]
  DEV -->|egress policy: only gateway reaches models| GW["LLM gateway"]
  MCP --> TOOL["Tool server<br/>(attestation guard rejects un-proxied)"]
  GW --> MODEL["Model API"]
  BYP["Bypass attempt"] -.->|blocked by network policy| MODEL
  BYP -.->|no attestation → 401| TOOL
  DIS["Discovery"] -->|alarms on any bypass| CP["Control plane"]
```

Unavoidability is an org rollout (network policy plus MDM plus gateway plus the attestation guard from `docs/design/enforcement.md`), enabled by the platform, not a single toggle. Stated plainly to anyone evaluating it.

## 6. Build / integrate / never

- Build: control plane, PDP, the PEPs (MCP proxy, LLM gateway, native sync), evidence, identity wiring, discovery, a light GRC projection.
- Integrate: content safety (Lakera / Azure AI Content Safety / Llama Guard), the IdP (Entra / Okta), SIEM, CASB/DLP for SaaS, and optionally a GRC suite (Credo / OneTrust) as an evidence consumer.
- Never: re-implement a content classifier, an IdP, a SIEM, or a coding agent's own sandbox. Those are other people's moats; ours is the neutral authorization-identity-evidence core across every surface.

## 7. Honest status

Phase A (the MCP core) is shipped and tested; everything else is design, not code, with the markers above and full designs in the per-phase docs. Today ACP governs MCP agent tool calls end to end with verified identity, tamper-evident evidence, obligations, tool-integrity, and a hardened kill-switch. This architecture is how that core becomes full-landscape coverage without leaving its lane; `platform-plan.md` is the order to build it.
