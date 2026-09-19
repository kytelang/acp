# ACP platform features

What ACP provides to govern the AI landscape. Everything below is built and tested unless tagged
(integrate) = connects an external system, or (deployment) = needs a rollout step to be fully
unavoidable. On-prem, vendor-neutral. See `docs/positioning.md` and `docs/design/*`.

## Coverage: the surfaces it governs
- Agent tool calls (MCP), transparent proxy over stdio and streamable-HTTP
- Direct model API calls, reverse-proxy gateway (OpenAI / Anthropic / Bedrock / Gemini / ...)
- Coding agents' own powers (shell / file / network): one ACP policy compiled into Copilot / Claude / Gemini managed-settings
- SaaS / embedded AI via connectors (integrate)

## Policy and authorization
- One policy language across every surface (model-v2 DSL)
- Subject = agent + human principal; object = resource (database, filesystem, secrets, model-class, ...); operation (read / write / delete / egress / ...)
- Trusted tool-to-resource and model-to-class taxonomies (derived, never agent-asserted)
- Verdicts: allow / deny / step-up / allow-with-obligations
- Obligations: confirm, redact, rate-limit and token/cost budgets
- Default-deny with deny-overrides
- Signed, versioned policy; hot-reload; fail-closed on a bad deploy

## Identity
- Verified agent identity (registry tokens, un-spoofable)
- Verified human principal via OIDC / Entra (RS256 + JWKS auto-fetch and rotation); degrades to unattributed
- Delegation: agent acting for a human
- Per-request identity on both the control plane and the enforcement path

## Access control and human oversight
- RBAC on the control plane (PolicyAdmin / Approver / BreakGlassOperator / Auditor / Registrar)
- Separation of duty (a policy admin cannot trip the kill-switch, and the reverse)
- Step-up approvals, human-in-the-loop with an approvals inbox

## Emergency controls
- Kill-switch (break-glass): scoped (global / agent / resource / tool / model), signed, lockdown persists until cleared, TTL-aware
- Reaches every surface (tool calls and model calls)

## Evidence and audit
- Tamper-evident Merkle ledger with signed tree heads; every decision recorded (who / what / which resource / verdict / obligations)
- Re-derivable and verifiable (acp verify)
- SIEM export: CEF / OCSF files, OTLP, and syslog

## Integrity and anti-tamper
- Tool-integrity pinning: rug-pull / tool-poisoning to quarantine and deny
- Tool-server binary fingerprint check; MCP method-drift detection

## Unavoidability and containment
- Credential brokering: the gateway holds the model key; callers cannot reach the model directly
- Enforcement attestation: guarded tool servers reject un-proxied calls (deployment)
- Fail-closed posture; stdio is a structural chokepoint

## Content safety (integrate)
- Content-scan hook: external firewall (Lakera / Azure AI Content Safety) on prompts; blocks, fail-closed
- Redact obligation for sensitive fields

## Discovery
- Shadow-AI detection: classifies un-governed model-API / MCP endpoints by provider (acp discover) to sanction or block

## Compliance and GRC
- Evidence-backed framework reports: EU AI Act (Art. 14 / 12 / 9), NIST AI RMF, ISO 42001, each control cited by real ledger records (acp grc-report)
- Idempotent control-evidence export for GRC platforms (ServiceNow / Archer / OneTrust)

## Operations and posture
- Admin console: overview, approvals, evidence timeline, teams, agents, policy authoring, kill-switch
- Registration: teams / apps, agents, human principals
- CLI: policy compile / test, verify / export, break-glass, native-compile, discover, grc-report
- Liveness and bypass detection (dead-man's-switch)
- Fully on-prem, no cloud dependency; vendor-neutral (one policy across Copilot / Claude / Codex / Gemini / custom and any model provider)

## The through-line
One policy, one identity model, one tamper-evident ledger, one kill-switch, applied to every place
AI acts, integrating outward for content / IdP / SIEM / GRC rather than replacing them.
