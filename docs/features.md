# Varman (ACP) platform features

What ACP provides to govern the AI landscape. Everything below is built and tested unless tagged
(integrate) = connects an external system, or (deployment) = needs a rollout step to be fully
unavoidable. On-prem, vendor-neutral. See `docs/positioning.md` and `docs/design/*`.

## Coverage: the surfaces it governs
- Agent tool calls (MCP), transparent proxy over stdio and streamable-HTTP
- Direct model API calls, reverse-proxy gateway (OpenAI / Anthropic / Bedrock / Gemini / ...)
- Anything from agents / IDEs / browsers via the config-driven forward proxy (acp-intercept): a signed endpoint registry matches each destination (host / sni / path) and governs or tunnels per rule; optional TLS interception (ACP CA on managed devices) decrypts and inspects body-inspecting HTTPS endpoints, with cert-pinning detected and reported
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
- Enforcement attestation: guarded tool servers reject un-proxied calls
- Enforcement guard sidecar (acp-guard): verifies the x-acp-enforcement attestation in front of a tool server; refused un-proxied attempts are recorded to the ledger
- Coverage attestation (acp coverage): a signed report cross-referencing observed vs governed endpoints; lists ungoverned and leaky paths; --require-full gates a rollout
- Egress canary (acp canary-egress): probes direct model / tool access and fails (exit 3) on any host reachable off-ACP
- Gateway base-URL pinning (native-compile --gateway): forces a coding agent's own model traffic through the gateway
- Fail-closed posture; stdio is a structural chokepoint

## Supply chain and AI-BOM
- Admission gate (acp_core::supplychain): registration fails closed on no provenance (digest), any scanner finding, or an unscanned high-impact artifact; the scanner verdict is supplied by an external scanner (integrate), not built
- Signed AI bill of materials (acp aibom): CycloneDX over every agent / MCP server / tool / model-class with provenance, admission verdict, scan result, integrity pin and policy in force

## Content firewall (first-party, in-path)
- Native content engine (acp_core::content): prompt-injection / jailbreak signature detection, PII and secret detection, span-level redaction, denied-topic rules; block or redact
- Enforced on BOTH surfaces: the gateway prompt path (--content-firewall) and the MCP proxy tool-call arguments (--content-firewall)
- Honest boundary: signatures and regexes, not a trained classifier; the external content-scan hook (Lakera / Azure AI Content Safety) stays available for ML-grade detection
- Redact obligation for sensitive fields

## Discovery and enrollment
- Shadow-AI detection: classifies un-governed model-API / MCP endpoints by provider (acp discover)
- Enrollment loop (acp enroll): signed dispositions (enroll / quarantine / accept-risk with expiry) over discovered endpoints; feeds the coverage report
- MDM / CASB export (acp enroll export-mdm): an allow + block list ACP hands to the org's endpoint tools to enforce on the device

## Compliance and GRC
- Evidence-backed framework reports: EU AI Act (Art. 14 / 12 / 9), NIST AI RMF, ISO 42001, each control cited by real ledger records (acp grc-report)
- Idempotent control-evidence export for GRC platforms (ServiceNow / Archer / OneTrust)
- Evidence-linked AI risk register (acp risk): risk items scored likelihood x impact, with treatment, lifecycle status and links to the controls and ledger decisions bearing on them; signed snapshot
- Control library across EU AI Act, NIST AI RMF and ISO 42001 (acp controls)
- EU AI Act risk assessment and conformity obligations (acp assess): tiers a system unacceptable / high / limited / minimal and lists the controls it must satisfy; signed
- Signed attestations and sign-offs (acp attest): a named attestor and role bound to a subject, non-repudiable
- AI use-case registry with lifecycle gates (acp usecase): proposed -> assessed -> approved -> deployed -> retired, refusing a transition without a linked assessment or a valid attestation
- SIEM export in CEF, OCSF and RFC 5424 syslog, plus OTLP (acp siem)

## Operations and posture
- Admin console: overview, approvals, evidence timeline, teams, agents, policy authoring, kill-switch
- Registration: teams / apps, agents, human principals
- CLI: policy compile / test, verify / export, break-glass, native-compile, discover, grc-report, coverage, canary-egress, aibom, enroll, risk, siem, content-scan, content-eval, redteam, controls, assess, attest, usecase, intercept
- Liveness and bypass detection (dead-man's-switch)
- Fully on-prem, no cloud dependency; vendor-neutral (one policy across Copilot / Claude / Codex / Gemini / custom and any model provider)

## Intent, sequence and data-boundary governance
- Intent / trajectory governance (acp_core::trajectory): denies the action that completes a toxic combination (read a secret then egress) or exceeds a high-impact velocity budget, across the session
- Data-boundary enforcement (acp_core::databoundary): classified data (secret / PII) may not cross to a lower-trust destination (secret to external egress is blocked; PII redacted), destination-aware unlike the content firewall
- Continuous adversarial testing (acp_core::redteam, acp redteam): an obfuscation corpus (base64 / zero-width / homoglyph / despace) with a catch-rate + false-positive gate for CI

## End-to-end vertical
- One acceptance test (demo/vertical/run.sh) proves the spine bulletproof: Agent -> Action -> Policy -> Decision -> Human approval -> Execution -> Evidence -> Independent verification, with fail-closed checks (tampered ledger fails verification; invalid token rejected)

## The through-line
One policy, one identity model, one tamper-evident ledger, one kill-switch, a first-party content
firewall and a full GRC lifecycle, applied to every place AI acts. A single product for AI
governance, still interoperating outward (IdP, SIEM, external content ML, external GRC) where an
enterprise already runs those.
