# AI governance and AI firewall: feature and gap analysis

Date: 2026-09-20
Status: research synthesis. Reads with `docs/positioning.md` (the anchor) and `docs/research/policy-model-study.md` (the policy-model study). Where those two documents make a call, this one defers to them.

## 1. Purpose

Enterprises buying "AI governance" or an "AI firewall" today assemble two separate product categories and still find their real need unmet. This document does three things:

1. A feature analysis of the two incumbent categories: AI governance and GRC platforms (the Credo AI class) and AI security and AI firewall products (the Aegis and Lakera class).
2. A gap analysis: what neither category delivers, stated as the specific capability that is structurally absent from the market.
3. A clear statement of what an enterprise needs badly, fulfilled in one single product, and an honest map of where ACP already meets that need and where ACP still has to build or harden.

The one-line reading, which the rest of the document supports: the market sells paperwork (governance) or content filtering (firewalls), and neither is unbypassable, per-action, identity-bound authorization with verifiable evidence. That missing middle is what enterprises need and what ACP is built to be.

## 2. Method and confidence

Findings come from two parallel research passes over vendor product and documentation pages, fetched September 2026, plus limited third-party framing. Claims are the vendors' own stated capabilities, not independently verified in production. Independent analyst reports (Gartner, Forrester, IDC) could not be fetched, so any competitive ranking here is a vendor self-report and is flagged as such.

Two accuracy caveats to carry forward:

- The name "Aegis" is a collision. There is no single dominant "Aegis AI firewall". The nearest full commercial product is Neysa's Aegis LLM Shield (a content firewall). Forrester also publishes an "AEGIS" framework for agentic guardrails, which is an analyst framework, not a product. If a specific customer means a specific "Aegis", confirm the vendor before relying on the profile.
- The category has consolidated hard. Most named independents are now acquired and rebranded: Lakera into Check Point, Robust Intelligence into Cisco AI Defense, Protect AI into Palo Alto Prisma AIRS, Prompt Security into SentinelOne, CalypsoAI into F5. Fairly.ai has rebranded to Asenion.ai. Treat product names as moving targets.

## 3. Category A: AI governance and GRC platforms (the Credo AI class)

Representative products: Credo AI, Holistic AI, IBM watsonx.governance, OneTrust AI Governance, Microsoft Purview and Azure AI governance, Monitaur, Collibra, Fairly (Asenion), plus ServiceNow, SAS, Dataiku on the periphery.

### 3.1 What they do well

- Inventory and registration. Model, agent and use-case registries with discovery, agent cards, dependency graphs and lineage. Strong across OneTrust, Holistic AI, Microsoft Foundry, IBM factsheets and Credo AI.
- Risk management. Risk registers, risk scoring, impact assessments and conformity assessments. IBM (the AI Risk Atlas plus OpenPages) and Holistic AI are the strongest here.
- Framework mapping. EU AI Act, NIST AI RMF and ISO 42001 templates and control libraries are near universal across the majors.
- Evidence, audit and reporting. Automated evidence capture, audit trails and regulator-ready report exports. IBM, OneTrust and Monitaur lead.
- Lifecycle governance. Approval gates, sign-off workflows, versioned model cards. IBM's roughly 18-state use-case workflow and OneTrust's intake-to-production gates are the deepest.
- Model monitoring. Bias and fairness, drift, performance and explainability dashboards. Monitaur, Holistic AI and IBM (OpenScale) lead; Credo and OneTrust are thin here.
- Third-party and shadow-AI discovery. Vendor AI risk plus discovery of ungoverned AI. Microsoft (concrete data-path discovery) and Holistic AI (down to the endpoint) lead.

### 3.2 What they structurally do not do

- They sit beside the request path, not in it. The core governance product is a side-car: it registers, assesses, scores, documents and monitors. It does not authorize or deny a live action.
- Their "runtime" additions are new, opt-in and content-scoped. Where governance vendors have added inline enforcement, it is delivered through an SDK the developer must call (OneTrust AI Guard, Holistic AI Guardian, Fairly Enterprise Agent Management) or a text filter at the model boundary (IBM AI guardrails, Microsoft Content Safety). The decision is on content and behaviour ("does this text look unsafe"), not an authorization check on a concrete tool invocation. Credo AI's Agent Governor is the only one that describes deterministic per-action verdicts (block, allow, escalate, advise) wired into the agent harness, and it is a Claude Code only research preview with no SLA and no bring-your-own-policy yet.
- Their evidence is trustworthy because access-controlled, not because verifiable. Across the whole category the audit trail is a database log plus dashboards plus report exports. Hash-chaining, append-only ledgers, signed decisions and externally verifiable proof are absent. Monitaur hashes model and production files (versioning integrity, not a signed decision ledger). Holistic AI claims "immutable policy versions". Fairly claims "tamper-resistant assurance" with no published mechanism. None lets a regulator verify the evidence without trusting the vendor's store.

## 4. Category B: AI security and AI firewall products (the Aegis and Lakera class)

Representative products: Neysa Aegis, Lakera (Check Point), Prompt Security (SentinelOne), Cisco AI Defense, Protect AI (Prisma AIRS), HiddenLayer, Azure AI Content Safety, AWS Bedrock Guardrails, NVIDIA NeMo Guardrails, CalypsoAI (F5), plus the agent-security specialists Zenity, Noma, Astrix and WitnessAI.

### 4.1 What they do well

- Prompt-injection and jailbreak detection on inputs, including indirect injection from RAG content and tool responses. Near universal.
- Output safety. Toxicity, PII and DLP, data-leakage detection, and in a few cases groundedness or hallucination checks (Azure, Bedrock, Protect AI, NeMo). Most others do not check hallucination.
- Content policy. Topical allow and deny, custom categories, blocklists.
- Inline blocking. Unlike the governance category, these products genuinely sit in the path (proxy, gateway, SDK or endpoint) and block.
- Agent and MCP tool-call security is the fast-moving frontier. Zenity, Noma, Protect AI, CalypsoAI and Lakera discover MCP servers and agents, maintain a registry, and do tool-level allow and deny, tool-poisoning and rug-pull detection, and excessive-agency checks.
- Model and supply-chain scanning. Protect AI and HiddenLayer lead, with model-artifact scanning across many file formats, an AI bill of materials and MITRE ATLAS mappings.
- Air-gapped deployment exists but is rare: HiddenLayer, CalypsoAI (F5), NeMo (open source) and Azure containers (a subset only). Cisco and Bedrock are SaaS only.

### 4.2 What they structurally do not do

- They decide on content, not on authorization. The overwhelming majority are classifiers, regex and topic models answering "is this text or behaviour malicious", not an authorization engine answering "is this actor allowed to perform this operation on this specific resource". Noma is the single real exception (its own example: architects may drop tables through the Postgres MCP server while developers may not), and even that is expressed at MCP-tool granularity keyed to IdP groups, not a general per-secret, per-file, per-row policy.
- Tool-call governance, where present, is inspection-based not capability-based. HiddenLayer, Azure Task Adherence, Cisco and Bedrock inspect the content of tool inputs and outputs (and Bedrock and Azure PII filters skip tool arguments and results entirely). Only Zenity, Noma, CalypsoAI, Lakera and Prompt Security do genuine tool allow and deny, and those are tool-level, not resource-level.
- Identity is caller-asserted or correlation-based, not attested. Cisco and HiddenLayer take an opaque caller-supplied identity string ("as supplied by the caller"). Zenity, Noma and Astrix bind an agent to a human owner, but by correlation against Okta or Entra inside their own control plane, not by cryptographic attestation and not as a portable cross-vendor token a downstream system can verify.
- Evidence is ordinary logs. Zero products in this category document signed, hash-chained or tamper-evident audit trails. Some actively undermine evidence: Bedrock stores the original unmasked PII and blocked content in plain text in its logs.
- The kill-switch is fragmented. Only Zenity documents an agent shut-down action, and it is capped by whatever each integrated platform supports. No product offers a single authenticated cross-surface kill-switch honoured everywhere.
- One policy stops at one control plane. Each vendor enforces its own policy within its own reach and its own language (CEL, Colang, natural-language guardrails, an "AI constitution"). There is no shared portable policy artifact honoured identically across clouds, gateways and agent frameworks. Interoperability today is shared vocabulary (OWASP LLM Top 10, MITRE ATLAS), not shared enforcement.

## 5. The gap: the un-served five-way intersection

Both research passes converge on the same conclusion, independently. Each of these five capabilities exists partially, in different products. No vendor in either category combines all five:

1. An unbypassable inline chokepoint. Not an SDK the developer may or may not call, and not a filter that fails open on outage.
2. Deterministic per-tool-call authorization. This agent, this human, this tool, these arguments, this resource, this operation, then allow, deny, step-up or allow-with-obligations. Not a content or intent score.
3. Scoped entitlements at the resource boundary. Which database, which file, which secret, which egress destination, which model class. Not "which tool", and not "is this text safe".
4. A portable, cross-vendor, cryptographically verified agent identity bound to a delegating human principal. Not a caller-asserted string, and not correlation inside one vendor's console.
5. Tamper-evident, cryptographically signed evidence for every decision, verifiable by a third party without trusting the vendor's store.

This intersection is empty for a structural reason, which is exactly what makes it defensible: the incumbents are not incentivised to build it. Governance vendors sell process and paperwork; adding real inline authorization is a different engineering discipline. Content-firewall vendors sell classifiers; authorization at the resource boundary is a different product. Single-vendor agent makers (Microsoft, Anthropic, OpenAI, Google) will not govern each other's agents. The neutral middle stays open.

The two closest external analogues, and the two to watch:

- Astrix Security ships a product literally named "Agent Control Plane". It goes furthest on identity: just-in-time, short-lived, precisely scoped credentials provisioned at agent creation. It is credential-level, not a live per-action policy check, and it does not do content, evidence-ledger or cross-surface kill.
- Noma Security goes furthest on per-operation authorization (the Postgres example above) and has the best supply-chain story of the agent tier. It is still SaaS or on-prem within its own control plane, correlation-based on identity, and its logs are ordinary, not tamper-evident.

Neither, and no one else, delivers the full five.

## 6. What the enterprise needs badly, in one product

Stated as requirements, this is the single product an enterprise actually needs. It is deliberately the five-way intersection above, made concrete:

1. One signed policy across every AI surface: agent tool calls (MCP), direct model API calls, and the coding agents' own shell, file and network powers. Vendor-neutral, so the same policy governs Copilot, Claude Code, Codex, Gemini and custom agents alike.
2. Authorization at the resource boundary, not the command string and not the content. Governs which database, secret, file and egress, uniform across agents and not defeated by a reworded command.
3. Verified agent identity bound to a verified human principal, per action, un-spoofable, and the same identity across vendors.
4. A tamper-evident evidence ledger of every decision, re-derivable and independently verifiable, so a regulator trusts the cryptography rather than the console.
5. Human approvals with separation of duty, so a sensitive action needs a second person and the requester cannot approve their own request.
6. A single scoped, signed kill-switch that reaches every surface at once.
7. Tool-integrity protection against rug-pull and tool-poisoning.
8. Shadow-AI discovery that brings ungoverned model and agent endpoints under the same policy.
9. Compliance evidence for EU AI Act, NIST AI RMF and ISO 42001 sourced from what agents actually did at runtime, not from questionnaires, and exportable into the GRC platform the enterprise already owns.
10. Unbypassable and fail-closed by construction, deployable on-prem and air-gapped.
11. Content safety when it is needed, by calling an existing content firewall as an obligation, not by rebuilding classifiers.

The reason this is urgent, not merely nice: the regulations that enterprises must satisfy (EU AI Act Articles 12 and 14 on record-keeping and human oversight, NIST AI RMF, ISO 42001) demand demonstrable control over what AI systems actually did. Paperwork platforms cannot prove runtime behaviour, and content firewalls do not record it verifiably. The enterprise is left holding compliance obligations that neither category it has bought can actually discharge.

## 7. Where ACP stands against that need

Mapped honestly against the eleven requirements in Section 6. "Built" means implemented and tested in the current stack; "integrate" means ACP connects to an external system rather than rebuilding it; "gap" means not yet built.

| # | Enterprise need | ACP status |
|---|---|---|
| 1 | One policy across every AI surface, vendor-neutral | Built. MCP proxy (stdio and streamable-HTTP), an LLM gateway reverse-proxy, and one policy compiled into Copilot, Claude Code and Gemini managed-settings. One model-v2 DSL across all. SaaS connectors are integrate. |
| 2 | Authorization at the resource boundary | Built. Subject is agent plus human principal; object is a resource (database, filesystem, secrets, model-class); operation is read, write, delete, egress. Trusted tool-to-resource and model-to-class taxonomies, derived, never agent-asserted. |
| 3 | Verified agent plus human identity, per action | Built. Registry-issued agent tokens (un-spoofable), human principal via OIDC and Entra (RS256 plus JWKS rotation), delegation, per-request identity on both planes. Real-Entra cutover is pending a customer token; the mock path is proven. |
| 4 | Tamper-evident, verifiable evidence | Built. A Merkle ledger with signed tree heads; every decision recorded and re-derivable via `acp verify`. This is the single capability absent from the entire incumbent market. |
| 5 | Human approvals with separation of duty | Built. RBAC on the control plane, an approvals inbox, step-up verdicts, and SoD (a policy admin cannot trip the kill-switch, and the reverse). |
| 6 | Single scoped, signed kill-switch across surfaces | Built. Scoped (global, agent, resource, tool, model), signed, lockdown persists until cleared, TTL-aware, reaching tool calls and model calls alike. |
| 7 | Tool-integrity against rug-pull and poisoning | Built. Tool-integrity pinning, binary fingerprint checks and MCP method-drift detection to quarantine and deny. |
| 8 | Shadow-AI discovery under one policy | Built (network and endpoint classification via `acp discover`). Gap versus the market: no browser or endpoint DLP agent of the Purview or Holistic Endlayer kind. |
| 9 | Runtime-sourced compliance evidence | Built. Evidence-backed EU AI Act, NIST AI RMF and ISO 42001 reports, each control cited by real ledger records, with idempotent export for ServiceNow, Archer and OneTrust. |
| 10 | Unbypassable, fail-closed, on-prem and air-gap | Partially built. Fail-closed posture, credential brokering (the gateway holds the model key) and stdio as a structural chokepoint are built. Enforcement attestation is built but deployment-gated: unavoidability is only as strong as the rollout that forces all traffic through ACP. Production HA, disaster recovery and shared state are documented (see `docs/design/p2-operations.md`) but not yet built. |
| 11 | Content safety by integration | Built as an integration seam. A content-scan obligation calls an external firewall (Lakera, Azure AI Content Safety); ACP deliberately does not build classifiers. |

### 7.1 What ACP is deliberately not, and what it still lacks

Deliberately excluded, because another category owns it and ACP integrates rather than rebuilds (per `docs/positioning.md`):

- Content and prompt-injection detection, DLP and toxicity classifiers. Call an existing content firewall.
- In-IDE interactive approve and deny prompts, per-keystroke confirmation, and OS process sandboxing. The coding agents already do these well.
- Model bias, fairness, drift and explainability dashboards. The GRC monitoring vendors (Monitaur, Holistic AI, IBM OpenScale) own this. ACP produces the runtime-decision evidence they lack, not the statistical monitoring they have.

Genuine gaps to be honest about, if ACP is to be sold as the single product. The gap-closure work (see `docs/design/gap-closure.md`) has since addressed most of these; the status is noted inline:

- Model and supply-chain scanning (the Protect AI and HiddenLayer strength: model-artifact scanning, ML-BOM). CLOSED as a seam: a supply-chain admission gate (`acp_core::supplychain`) and a signed CycloneDX AI-BOM (`acp_core::aibom`, `acp aibom`) now gate registration on provenance and an external scanner verdict. ACP still does not build the scanner (positioning); it calls one.
- The full GRC lifecycle (risk register, impact and conformity assessment workflows, model-card lifecycle). PARTIALLY CLOSED: an evidence-linked risk register (`acp_core::riskregister`, `acp risk`) is now built alongside the existing framework reports. The heavier assessment-workflow product is still correctly left to the GRC platform ACP feeds.
- Breadth of connectors. CLOSED for SIEM: CEF, OCSF and RFC 5424 syslog formatters (`acp_core::siem`, `acp siem`) now join the existing OTLP span, making the SIEM-export claim real. Other connectors (ticketing, CASB) remain integrate; the shadow-AI MDM/CASB export (`acp enroll export-mdm`) is built.
- Unavoidability. CLOSED as a measured posture: the enforcement guard sidecar (`acp-guard`), a signed coverage attestation (`acp_core::coverage`, `acp coverage`), an egress canary (`acp canary-egress`), and gateway base-URL pinning in `native-compile --gateway` together turn "unavoidable is a deployment property" into something measured, probed and provable.
- Shadow-AI. CLOSED: the discovery loop now ends in signed dispositions (`acp_core::enrollment`, `acp enroll`) that feed the coverage report and an MDM/CASB allow+block export.
- Production hardening. STILL OPEN (ops, not code): HA, DR and shared-state operation are designed in `docs/design/p2-operations.md` and remain a deployment task, not an in-process build.

## 8. Conclusion and recommendation

The market gives an enterprise two products and still leaves the core obligation unmet. Category A (governance and GRC) documents and assesses but does not sit in the path. Category B (AI firewalls) sits in the path but decides on content, not authorization, and records to ordinary logs. Across roughly thirty products examined, not one delivers unbypassable, per-action, resource-level authorization bound to a verified agent-and-human identity with tamper-evident evidence. That is the exact shape of what enterprises need to discharge their AI Act, NIST and ISO 42001 obligations, and it is the exact shape ACP already implements.

ACP is not "a Credo plus a firewall". It is the missing middle between them, and it should stay there: neutral and interoperable on both sides, feeding the GRC platform its missing runtime evidence and calling the content firewall as an obligation, while owning the one thing no incumbent is structurally incentivised to build.

Recommended priorities to make ACP genuinely the single product an enterprise can buy for this need:

1. Close unavoidability. Convert enforcement attestation from deployment-gated to a rollout an org cannot route around. This is the north star that makes everything else real.
2. Complete the real-Entra cutover, so the verified-human-principal claim is demonstrated in production, not only against the mock.
3. Build the P2 production infrastructure (HA, DR, shared state) so the chokepoint is dependable at scale.
4. Track Astrix and Noma as the two closest competitors, and integrate rather than rebuild for model scanning, content safety and the GRC lifecycle.
