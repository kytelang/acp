# Varman (ACP) positioning and scope

Date: 2026-09-18
Status: the anchor, revised 2026-09-20. The original wedge-only framing (sections "The gap we fill" through "The failure mode to avoid") is kept for the record but is SUPERSEDED by the "Scope change" section below: the content firewall and the GRC lifecycle are now built into the product. Read the scope change as current; read the wedge sections as history.

## The gap we fill

The market already has content firewalls (Lakera, Azure AI Content Safety), AI governance and GRC platforms (Credo AI, Holistic AI, IBM watsonx.governance, OneTrust), general policy-as-code engines (OPA, Cedar, Cerbos), per-vendor agent permissions (Copilot, Claude Code, Codex, Gemini), and connection-level authorization (the MCP OAuth spec). The `policy-model-study.md` research shows each of these owns its lane well.

What no one owns, and what no incumbent is structurally incentivised to build, is the neutral middle: a vendor-neutral, verifiable, unbypassable runtime authorization and evidence layer for AI-agent tool calls. Microsoft will not govern Claude; Anthropic will not govern Copilot; the GRC platforms produce paperwork, not inline enforcement; MCP authorizes the connection, not the per-call action. That gap is empty for a good reason (cross-vendor, hard, unincentivised for incumbents), which is exactly what makes it defensible.

## Positioning statement

ACP is the verifiable runtime authorization and evidence layer for AI-agent tool calls: one signed policy enforced across every agent, bound to a verified agent and human identity, written to a tamper-evident ledger, with human approvals and a kill-switch, governing at the resource boundary rather than by any single vendor's brittle command-string rules.

## North stars (what makes this real, not advisory)

1. Unavoidable and fail-closed. If an agent is not going through ACP, or ACP is down, the agent must not be able to call governed tools. A chokepoint a developer can route around has no value.
2. Verifiable. Every decision and every piece of evidence is signed and re-derivable, tied to a real identity. Trust lives in the cryptography, not in the console.
3. Vendor-neutral. One policy, one evidence trail, across Copilot, Claude Code, Codex, Gemini and custom agents alike.

## Scope change (2026-09-20): from wedge to complete platform

The sections below describe the original wedge-only scope, kept for the record. On 2026-09-20 the decision was taken to make ACP a complete, single-product AI governance platform: the content firewall and the GRC lifecycle, previously "integrate", are now built in.

What changed, and the honest boundary on each:

- Content firewall: BUILT natively (`acp_core::content`), in-path on both surfaces (the gateway prompt path and the proxy tool-call path). It combines a trained ML injection classifier (`acp_core::content::LinearScorer`) with prompt-injection and jailbreak signatures, PII and secret detection, span-level redaction and denied-topic rules, hardened against obfuscation (base64, zero-width, homoglyph, de-spacing) and indirect injection (tool-result screening). The detection is deliberately lightweight, so the external content-scan hook stays available for stronger ML-grade detection against novel attacks. ACP no longer REQUIRES an external firewall for baseline content protection.
- GRC lifecycle: BUILT natively. Control library (`acp_core::controls`), EU AI Act risk assessment and conformity obligations (`acp_core::assessment`), signed attestations / sign-offs (`acp_core::attestation`), an AI use-case registry with lifecycle gates (`acp_core::usecase`), and the pre-existing evidence-backed framework reports and risk register. ACP can now run a governance programme on its own; it still interoperates with an external GRC platform where one is already in place.
- Still integrate (unchanged): the IdP (Entra/OIDC), the SIEM (ACP exports CEF/OCSF/OTLP/syslog), and model/artifact scanning (ACP runs the admission gate and AI-BOM, and calls an external scanner for the verdict).

The original "failure mode to avoid" note below (do not become Credo plus a firewall) is now explicitly overridden by this decision. The trade accepted: broader scope and more surface to maintain, in exchange for a single product that meets an enterprise's AI-governance needs without assembling three tools.

## Original wedge (historical, superseded 2026-09-20)

The four sections that follow are the original wedge-only scope. They are kept as a record of the earlier decision. Where they say "do not build a classifier" or "do not build a GRC dashboard" or "do not become Credo plus a firewall", that guidance was reversed by the scope change above: the firewall and the GRC lifecycle are now first-party.

## Build (the wedge, and only this)

- Cross-vendor runtime authorization of tool calls, in the call path.
- Verified agent identity, and human-principal delegation (agent acting for a person).
- Resource-level policy (governs which database, filesystem, secret, egress, not command strings).
- Tamper-evident evidence ledger of every decision.
- Human approvals with separation of duty.
- Scoped kill-switch and tool-integrity pinning.
- Making the enforcement point unavoidable and fail-closed.

## Integrate (do not rebuild; connect to what exists)

- Content and prompt-injection detection, DLP, toxicity: call an existing content firewall (Lakera, Azure AI Content Safety, Llama Guard) as an obligation, do not build a classifier.
- Connection authorization: consume the MCP OAuth token and its identity claims, do not reinvent OAuth.
- Compliance reporting and framework mapping: feed the signed ledger to Credo AI or OneTrust as their missing runtime-evidence source, do not build a GRC dashboard.

## Exclude (the coding agents already do these well)

- In-IDE interactive approve and deny prompts, per-keystroke command confirmation.
- OS process sandboxing (filesystem and network jailing of shell commands).
- Per-vendor command allow-list grammars.

## The failure mode to avoid

Trying to be "Credo plus a content firewall". That is two other products and it is what makes the work feel like an endless field of gaps. ACP is the missing middle between the agents and the governance platforms. It wins by being neutral and interoperable on both sides, not by growing into either.
