# Varman evaluation guide: is it fit for your AI governance purpose?

Date: 2026-09-22
Audience: a security, platform, risk or compliance leader evaluating whether Varman (the Agent Control Plane, ACP) fits their AI governance needs. This is a plain-language, honest overview, including where Varman is not the right choice. "ACP" is the internal architecture name; "Varman" is the product.

## 1. What ACP is, in one paragraph

Varman (the Agent Control Plane, ACP) is a vendor-neutral, on-premises layer that sits in the path of what your AI agents and applications actually do, decides whether each action is allowed, and records every decision as tamper-evident evidence that a third party can verify with a public key alone. It governs the action, not just the words: which database, secret, file, model or network an agent may touch, for which human, and in what sequence. It is not a chatbot filter and it is not a compliance spreadsheet. It is a single, complete product that combines what an AI firewall does, what a GRC platform does, and the runtime authorization and verifiable evidence that neither of them provides, so you do not have to assemble three tools.

## 2. The problem it solves

Enterprises deploying AI agents face two tools that each solve half the problem. AI firewalls inspect prompts and responses for unsafe content but do not authorize actions or produce verifiable proof. AI governance and GRC platforms document, assess and report, but do not sit in the request path or block a live action. Neither can answer, with evidence, "what did our agents actually do, and could they have done something they were not allowed to?" ACP is built to answer exactly that.

## 3. What ACP offers, feature by feature

Grouped the way the stack is actually built, from the surfaces it sits in down to operations. Each group is tagged: [enforced] runs in a running component end to end; [opt-in] is enforced when a flag or environment setting turns it on; [primitive] is built and tested but not yet wired into a running component. The tags are the honest part; read them.

### 3.1 Coverage: the surfaces it governs [enforced]
- Agent tool calls over MCP: a transparent proxy over stdio and streamable-HTTP.
- Direct model API calls: a reverse-proxy gateway that holds the upstream key.
- Arbitrary HTTP and API traffic: a configuration-driven forward proxy with a real TLS-interception CA for managed devices; certificate pinning is detected and reported, not silently bypassed.
- The coding agents' own shell, file and network powers: one policy compiled into Claude, Copilot and Gemini managed settings (vendor settings, not machine code; the agent stays the enforcer).

### 3.2 Policy and authorization [enforced]
- One policy language across every surface, compiled to Cedar and fail-closed on any error.
- Subject is the agent plus the human principal; the object is the resource (database, secret, file, model class, network); the operation is read, write, delete, egress and so on.
- Tool-to-resource and model-to-class taxonomies are derived from names, never asserted by the agent.
- Verdicts: allow, deny, step-up, or allow with obligations (confirm, redact, rate-limit, token and cost budgets). Default-deny with deny-overrides.
- Signed, versioned policy with tamper detection and hot-reload, plus a staged path to default-deny (`acp posture` reads real evidence to tell you when it is safe to flip).

### 3.3 Identity and access [enforced]
- Verified agent identity (tokens stored only as a hash, fail-closed, revocable).
- Verified human identity via OIDC or Microsoft Entra (real RS256 and EdDSA, JWKS rotation), degrading to unattributed.
- Delegation: an agent acting for a named human, time-bounded.
- Role-based access control on the control plane with separation of duty, and mutual TLS between components.

### 3.4 Human oversight and emergency control [enforced]
- Step-up approvals with an inbox; each approval is single-use and bound to the session, principal, argument hash and a time limit.
- A scoped, signed kill-switch (break-glass) that halts an agent, resource or tool across both the tool-call and model-call surfaces and stays engaged until cleared.

### 3.5 Evidence and audit [enforced]
- A tamper-evident Merkle ledger with Ed25519 signed tree heads, independently verifiable with the public key alone, so you do not have to trust our store.
- Crash-safe recording, idempotent appends, and right-to-erasure or retention purges that do not break verification.
- Encryption of the sensitive argument payloads at rest (AES-256-GCM, key from a mounted secret), and optional signing on a PKCS#11 HSM.
- SIEM export in CEF, OCSF and syslog, plus OTLP, as a faithful projection of real decisions.

### 3.6 Content firewall, first-party and in-path [enforced]
- A trained prompt-injection classifier plus signatures, PII and secret detection, and denied-topic rules; block or redact.
- Hardened against obfuscation (base64, zero-width, homoglyphs, de-spacing) and against indirect injection in poisoned tool results, not just prompts.
- A continuous adversarial red-team gate and an evaluation gate, so a weakened detector cannot ship.
- Groundedness and hallucination: a zero-dependency baseline for context-grounded faithfulness, with production-grade detection delegated to an external specialist. Honest boundary: detection is defence in depth; the authorization layer is what actually contains a successful attack.

### 3.7 Integrity and anti-tamper [enforced]
- Tool-integrity pinning that detects a rug-pull or tool-poisoning and quarantines the tool until it is re-pinned.
- A self-governance meta-audit of policy, key, role and break-glass changes, appended to the same verifiable ledger.

### 3.8 Unavoidability and containment [enforced and opt-in]
- Credential brokering, so callers cannot reach the model directly.
- An enforcement guard sidecar that refuses and records any un-proxied call.
- A coverage report and an egress canary that measure whether anything is talking to a model or tool without going through ACP.
- Concurrency caps with load-shed and upstream timeouts on the data path.

### 3.9 Sequence and data-boundary governance [opt-in]
- Trajectory governance denies the action that completes a toxic combination of individually-allowed steps (read a secret, then send it out) or exceeds a velocity budget.
- Data-boundary enforcement stops classified data crossing to a lower-trust destination, and is destination-aware, unlike the content filter.

### 3.10 Discovery and enrolment [enforced]
- Shadow-AI detection classifies ungoverned model and agent endpoints by provider.
- A signed enrolment loop brings them under one policy or blocks them, and exports an allow and block list for your MDM or CASB.

### 3.11 Compliance and GRC
Two honestly different strengths of proof:
- Ledger-backed [enforced]: framework reports for the EU AI Act, NIST AI RMF and ISO 42001 graded from real signed records, SIEM export, and warehouse re-verification against Merkle proofs.
- Signed operator documents [enforced, but author-attested]: risk assessment and tiering, a worked conformity checklist, an AI risk register, model cards, a use-case lifecycle registry, attestations and a CycloneDX AI bill of materials. The signature proves the document was not altered; the linked-decision references inside it are free-text today, not cross-checked against the ledger.

### 3.12 Operations and platform [enforced]
- A control-plane console and a web console: approvals, policy view and deploy with a syntax-highlighted editor, kill-switch, evidence timeline, an integrity view and printable reports.
- Structured, leveled logs across every service (JSON option, configured by environment).
- Liveness (dead-man's-switch) and spike detection; Postgres-backed shared budgets and pins, and a tenant-isolated store with a fail-closed guard against a mis-scoped database role.
- Deployment: a complete helm chart (control-plane, gateway, ingress, autoscaling, disruption budget, network policy, optional at-rest key, HSM and backup), docker-compose, and systemd units.

### 3.13 Built but not yet wired [primitive]
Real, tested logic that no running component calls yet, so treat it as a roadmap, not a running feature: high-availability leader lease, staged rollout, fleet registry, classifier tuning and drift, usage metering, crypto-agility, four-eyes dual control, ITSM tickets, SCIM provisioning, tenant offboarding, MCP method-drift, webhook signing, and external transparency anchoring. See `docs/production-readiness.md` for what is closed and what remains.

### 3.14 Deliberately not built
OS-level sandboxing of shell commands (the coding agents enforce their own), a fully-managed cloud SaaS (on-premises by design), and statistical model monitoring such as bias and fairness dashboards. See section 5 for how that affects fit.

## 4. One complete product, with optional interoperability

ACP is designed to be the whole thing, not a piece you bolt onto other tools. It has its own content firewall and its own GRC lifecycle built in, plus the runtime authorization and tamper-evident evidence that neither an AI firewall nor a GRC platform provides. You do not need to buy a separate firewall or a separate GRC platform for ACP to be complete.

Interoperability is optional, for organisations that have already invested:

- If you already run an AI firewall (Lakera, Azure AI Content Safety) and want to keep it, ACP can call it as an obligation instead of, or in addition to, its own content engine.
- If you already run a GRC platform (Credo, OneTrust), ACP can feed it the signed runtime evidence it lacks, so your existing programme keeps working with a better source of truth.

Neither is required. Left to itself, ACP covers all three jobs.

## 5. Is ACP fit for your purpose?

### Strong fit

- You are in a regulated or high-assurance setting (finance, healthcare, pharma, government, defence, sovereign or air-gapped) and must prove control over AI, not just claim it.
- You need on-premises or air-gapped operation with no dependency on a vendor cloud.
- You run more than one agent vendor (Copilot, Claude, Codex, Gemini, custom) and want one policy and one evidence trail across all of them.
- You need control at the resource level (which database or secret), not just content filtering.
- You specifically need cryptographically-verifiable evidence for an audit or a board.

### Weak fit, or not yet

- You want a fully-managed cloud SaaS that you switch on with no deployment. ACP is on-premises by design; you run it.
- You need a turnkey, polished commercial product today with vendor support, certifications and references. ACP is a strong, tested reference implementation, not yet a hardened commercial product (see section 7).
- Your primary, dominant risk is best-in-class ML content detection against novel and evolving attacks. ACP's built-in content firewall (a trained classifier plus signatures, hardened against obfuscation and indirect injection) is complete for most needs, but its detection is deliberately lightweight rather than a heavyweight model. If content detection against novel attacks is your single biggest concern, you can augment ACP's engine with a specialist ML classifier through its built-in hook. This is optional augmentation, not a separate product you must run.
- You are standardised on a single agent vendor and its native, centrally-managed controls already meet your needs. ACP's cross-vendor value is smaller for you.
- You want bias, fairness, drift and explainability dashboards as the product. ACP produces the runtime-decision evidence those tools lack; it does not replace statistical model monitoring.

## 6. Deployment model and requirements

- Runs on-premises (Linux; develop on WSL2 on Windows). Not a cloud service.
- Single node works out of the box. For high availability, a Postgres instance backs shared state (rate-limit budgets and tool-integrity pins), verified across replicas.
- Optional: Microsoft Entra or any OIDC provider for verified human identity (real and wired); mutual TLS between components (real and wired). Encryption of evidence at rest is wired: set `ACP_LEDGER_KEK` to encrypt the sensitive argument blobs with AES-256-GCM envelope encryption (KMS-sourced key delivery is the remaining hardening). PKCS#11 HSM key custody for the signing key is wired (set ACP_PKCS11_MODULE) and verified against SoftHSM; the default remains a file key. Validate against your production HSM before relying on it.
- Governs by sitting in the path: a transparent MCP proxy, an LLM gateway, and a forward proxy; and by compiling one policy into coding agents' managed settings.

## 7. Maturity and honest status

ACP is a complete, tested reference implementation. As of this writing it has a large passing test suite and a ten-of-ten end-to-end acceptance for the core governance vertical. It is not yet a commercially hardened product: it is single-node verified with a mock identity provider by default, has no third-party security certifications (SOC 2, penetration test, independent cryptographic audit) yet, and has no production deployments or customer references. What that path looks like, and what it costs, is documented plainly in `docs/commercial/pre-launch-requirements.md`. Evaluate accordingly: ACP is ready for a proof of concept and a design-partner pilot, not for an unattended production rollout without the hardening steps in that document.

## 8. How to evaluate it yourself

- Run the end-to-end acceptance: `bash demo/vertical/run.sh` proves the whole vertical (identity, decision, human approval, execution, evidence, independent verification) and two fail-closed checks.
- Test the firewall's resilience: `acp redteam <model.json>` reports catch-rate and false-positive rate on an obfuscation corpus.
- Measure unavoidability: `acp coverage` and `acp canary-egress`.
- Generate an audit evidence pack from a live ledger: `bash scripts/evidence-pack.sh <ledger.db>`.
- Read the security and cryptographic design: `docs/security/whitepaper.md`.

## 9. Where to go deeper

- What it is and where it fits: `docs/positioning.md`, `docs/gap-analysis.md`.
- Full feature list: `docs/features.md`.
- Architecture and design: `docs/design/`.
- Security and threat model: `docs/security/whitepaper.md`.
- Commercial readiness: `docs/commercial/pre-launch-requirements.md`.
