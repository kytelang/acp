# ACP evaluation guide: is it fit for your AI governance purpose?

Date: 2026-09-21
Audience: a security, platform, risk or compliance leader evaluating whether ACP fits their AI governance needs. This is a plain-language, honest overview, including where ACP is not the right choice.

## 1. What ACP is, in one paragraph

ACP (Agent Control Plane) is a vendor-neutral, on-premises layer that sits in the path of what your AI agents and applications actually do, decides whether each action is allowed, and records every decision as tamper-evident evidence that a third party can verify with a public key alone. It governs the action, not just the words: which database, secret, file, model or network an agent may touch, for which human, and in what sequence. It is not a chatbot filter and it is not a compliance spreadsheet. It is the enforcement and evidence layer in between.

## 2. The problem it solves

Enterprises deploying AI agents face two tools that each solve half the problem. AI firewalls inspect prompts and responses for unsafe content but do not authorize actions or produce verifiable proof. AI governance and GRC platforms document, assess and report, but do not sit in the request path or block a live action. Neither can answer, with evidence, "what did our agents actually do, and could they have done something they were not allowed to?" ACP is built to answer exactly that.

## 3. What ACP offers

In buyer terms, grouped by outcome:

- Control what agents can do. Per-action authorization at the resource boundary (which database, secret, file, model class, network destination), with allow, deny, require-human-approval, or allow-with-obligations. Default-deny is available with a staged path to it.
- Prove what happened. A tamper-evident evidence ledger of every decision, cryptographically signed and independently verifiable without trusting ACP's own store. This is the capability no incumbent has, and it is the reason to look at ACP.
- Stop content attacks (defence in depth). A first-party content firewall for prompt injection, jailbreaks, PII and secrets, hardened against obfuscation (base64, unicode tricks, de-spacing) and indirect injection (poisoned tool results). Honest boundary: detection is best-effort; the authorization layer is what actually contains a successful attack.
- Govern sequences and data flow. Catch a toxic combination of individually-allowed actions (read a secret, then send it out) and block classified data from crossing to a lower-trust destination.
- Keep a human in control. Step-up approvals with separation of duty, and a scoped, signed kill-switch that halts an agent across every surface.
- Make enforcement unavoidable and measurable. Credential brokering, an enforcement guard, a coverage report and an egress canary that measure whether anything is talking to a model or tool without going through ACP.
- Discover and enrol shadow AI. Find ungoverned model and agent endpoints and bring them under one policy, or block them.
- Cover every surface. Agent tool calls (MCP), direct model API calls, arbitrary HTTP/API traffic (a configuration-driven forward proxy with optional TLS interception), and the coding agents' own shell, file and network powers.
- Satisfy the auditors. Evidence-backed reports for the EU AI Act, NIST AI RMF and ISO 42001, a control library, risk assessments, a worked conformity checklist, model cards, and SIEM export, all sourced from what actually happened at runtime.

## 4. Where ACP fits alongside what you may already have

ACP is the neutral middle between the two categories, and it interoperates with both rather than replacing them.

- With an AI firewall: ACP has its own content engine, and can also call an external firewall as an obligation if you have standardised on one. Use the firewall for content, ACP for authorization and evidence.
- With a GRC platform (Credo, OneTrust): ACP feeds them the signed runtime evidence they lack. Keep your GRC programme, add ACP as its source of truth for what agents did.

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
- Your primary need is best-in-class ML content detection against novel attacks as the main line of defence. ACP's detection is deliberately lightweight defence in depth; pair it with a specialist firewall if content is your core risk.
- You are standardised on a single agent vendor and its native, centrally-managed controls already meet your needs. ACP's cross-vendor value is smaller for you.
- You want bias, fairness, drift and explainability dashboards as the product. ACP produces the runtime-decision evidence those tools lack; it does not replace statistical model monitoring.

## 6. Deployment model and requirements

- Runs on-premises (Linux; develop on WSL2 on Windows). Not a cloud service.
- Single node works out of the box. For high availability, a Postgres instance backs shared state (rate-limit budgets and tool-integrity pins), verified across replicas.
- Optional: Microsoft Entra or any OIDC provider for verified human identity; an HSM or KMS (PKCS#11) for key custody; mutual TLS between components.
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
