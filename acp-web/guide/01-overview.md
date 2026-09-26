# 1. Overview and architecture

Varman sits in the path of what AI agents do and turns each action into a governed, recorded event.
It is built around one idea: an agent should only be able to touch a resource if a policy allows it
for the human it acts for, and every one of those decisions should leave a proof an outsider can
check. Everything else in the stack serves that idea.

## The six-step spine

Every action, whether a tool call, a model call, or an outbound HTTP request, passes through the
same six steps.

1. **Identify.** Establish the verified agent identity and, where configured, the human principal it
   acts for. Identity is never taken from the agent's own claims.
2. **Authorize.** One policy decides at the resource boundary: which database, secret, file, model
   class or network destination, for this subject and operation.
3. **Decide.** The verdict is allow, deny, step up to a human, or allow with obligations (confirm,
   redact, rate-limit, or a token and cost budget). The default is deny-overrides, and any error
   fails closed.
4. **Contain.** A scoped, signed kill-switch can halt an agent or resource; sequence governance
   catches a toxic combination of individually-allowed steps; a data boundary stops a classified
   value crossing to a lower-trust destination.
5. **Prove.** The decision becomes a leaf in a Merkle log with an Ed25519 signed tree head, and the
   sensitive argument payload is encrypted at rest.
6. **Verify.** Anyone can re-derive the tree and check the signature with the public key alone, so
   the proof does not depend on trusting the store that produced it.

## The components

Varman is a control plane and a set of enforcement points. You deploy a PEP wherever agents act; all
PEPs consult the same signed policy and append to the same ledger.

- **`acp-proxy`** governs **MCP tool calls**. It is transparent: it relays the JSON-RPC verbatim and
  only intervenes to deny, hold, or rewrite. Runs over stdio (wrapping a child MCP server) or as an
  HTTP reverse proxy. See [chapter 3](03-proxy.md).
- **`acp-gateway`** governs **direct model API calls**. It holds the upstream key, so a caller cannot
  reach the model off-ACP (credential brokering). See [chapter 4](04-gateway.md).
- **`acp-intercept`** governs **arbitrary HTTP/API traffic** as a forward proxy, with an optional
  ACP certificate authority for TLS interception on managed devices. See [chapter 5](05-intercept.md).
- **`acp-guard`** is a sidecar in front of a tool server that **refuses any call that did not come
  through ACP**, closing the "just call the server directly" bypass. See [chapter 6](06-guard.md).
- **`acp native-compile`** governs a coding agent's **own shell, file and network powers** by
  compiling one policy into the vendor's managed settings. See [chapter 7](07-native-compile.md).
- **`acp-server`** is the control plane: the approvals inbox, signed policy deploy, break-glass,
  health and the evidence API. See [chapter 14](14-operations.md).
- **`acp-cli`** (invoked as `acp`) is the operator's tool for policy, identity, evidence, discovery,
  red-team and the GRC surface. See [chapter 13](13-cli.md).

## Deploy where

Two deployment surfaces, and it matters which is which.

**On a server (run as services):**

- `acp-server`, the control plane. This is the hub. Identity, AI endpoints, policy, approvals,
  break-glass and the GRC records are created and stored here, and the console talks to its API.
- `acp-gateway`, the LLM gateway.
- `acp-console`, the browser UI.

**On developer machines or in CI (run on demand):**

- `acp-proxy`, launched per session in front of a local MCP server.
- `acp-intercept` (also deployable as a shared egress gateway) and `acp-guard`.
- `acp`, the CLI, for authoring and testing policy, verifying and exporting evidence, red-teaming, and
  compiling coding-agent settings.

You register agents, AI endpoints, policy and governance records through the console or the
control-plane API, and they are stored centrally; you do not hand-edit files on each machine. The CLI
exists for verification, CI gates, and offline or air-gapped work, not as the primary way to change
governance state. Install the two sides with `install.sh` (workstation) and `install-server.sh`
(server); see chapter 16.

## Where it fits

Varman is a strong fit when you must **prove** control over AI, not just claim it: regulated or
high-assurance settings (finance, healthcare, pharma, government, defence, sovereign or air-gapped),
on-premises or air-gapped operation, more than one agent vendor under one policy and one evidence
trail, control at the resource level rather than content filtering alone, and cryptographically
verifiable evidence for an audit or a board.

It is a weaker fit if you want a fully-managed cloud SaaS (it is on-premises by design), a turnkey
commercial product with certifications today (it is a tested reference implementation, see
[chapter 15](15-security.md) and the repository's `docs/production-readiness.md`), or best-in-class
heavyweight ML content detection as your single dominant need (the built-in firewall is a trained but
deliberately lightweight classifier that you can augment through an external hook).

## One product, optional interoperability

Varman is designed to be the whole thing: it has its own content firewall and its own GRC lifecycle,
plus the runtime authorization and tamper-evident evidence that neither an AI firewall nor a GRC
platform provides. Interoperability is optional: it can call an external content classifier as an
obligation, and it can feed signed runtime evidence into an existing GRC platform. Neither is
required.

## What is deliberately not built

Being honest about the edges matters for a governance product.

- **OS-level sandboxing** of shell commands is not Varman's job; the coding agents enforce their own
  sandboxes and Varman is the policy origin, not a second seccomp layer.
- **A managed cloud** service does not exist; you run it.
- **Statistical model monitoring** (bias, fairness, drift dashboards) is out of scope; Varman
  produces the runtime-decision evidence those tools lack, it does not replace them.

There is also a set of governance modules that are implemented and tested but not yet wired into a
running binary (high-availability leases, SCIM, dual-control, webhook signing, and others). They are
called out as not-yet-integrated primitives rather than shipping features, so nobody mistakes one
for the other.

## Glossary

A quick reference for the terms this guide coins. Each is expanded in the chapter noted.

- **PEP (policy enforcement point).** A component that sits in the path of an agent action and applies
  the policy: the MCP proxy, the LLM gateway, the interceptor and the guard.
- **Control plane.** The central service (`acp-server`) that holds identity, endpoints, policy,
  approvals, break-glass and the evidence API. See [chapter 14](14-operations.md).
- **Evidence ledger.** The append-only, tamper-evident Merkle log of every decision, verifiable with a
  public key alone. See [chapter 9](09-evidence.md).
- **Verdict.** The policy outcome for a call: `allow`, `deny`, `step_up` (hold for a human) or `shadow`
  (record only, do not block). See [chapter 2](02-policy.md).
- **Obligation.** A side condition attached to an allow: `confirm` (route to step-up), `rate_limit`
  (deny once exhausted) or `redact` (rewrite the frame). See [chapter 2](02-policy.md).
- **Step-up.** A human-in-the-loop hold: the call pauses until an authorised person approves or denies
  it. See [chapter 11](11-containment.md).
- **Break-glass (kill-switch).** A signed emergency grant that overrides normal policy to lock down,
  disable enforcement or bypass. See [chapter 11](11-containment.md).
- **Shadow mode.** Running a PEP so it evaluates and records but never blocks, to observe real traffic
  before enforcing. See [chapter 3](03-proxy.md).
- **Fail-closed / fail-open.** Fail-closed (the default) refuses to forward a call it cannot record;
  fail-open forwards ungoverned on an evidence-write failure. See [chapter 3](03-proxy.md).
- **Trajectory governance.** Denying the action that completes a toxic combination of individually
  allowed steps. See [chapter 11](11-containment.md).
- **Data boundary.** Destination-aware DLP: may this class of data cross to that destination. See
  [chapter 11](11-containment.md).
- **Content firewall.** Argument and response scanning for injection, PII and secrets. See
  [chapter 10](10-content-firewall.md).
- **Endpoint registry.** The set of governed destinations the interceptor matches traffic against. See
  [chapter 5](05-intercept.md).
- **Tool-integrity pin (rug-pull detection).** A fingerprint of a tool definition or binary; a mismatch
  means it changed under a live agent. See [chapter 3](03-proxy.md).
- **Enforcement attestation.** The signed `x-acp-enforcement` token a guard checks to reject un-proxied
  calls. See [chapter 6](06-guard.md).
- **Coverage / posture.** Coverage is how much observed traffic a rule matches; posture is whether that
  coverage is high enough to switch safely to default-deny. See [chapter 2](02-policy.md).
- **Meta-audit.** The control plane's own ledger of its governance actions (policy, keys, RBAC,
  break-glass), so the governor is itself governed. See [chapter 9](09-evidence.md).
