# The Varman (ACP) guide

**Varman** (the Agent Control Plane, ACP) is a vendor-neutral, on-premises layer that authorises
what your AI agents and applications actually do, at the resource boundary, and records every
decision as tamper-evident evidence a third party can verify with a public key alone. It governs
the action, not just the words: which database, secret, file, model or network an agent may touch,
for which human, and in what sequence.

"ACP" is the internal architecture name and the prefix on the crates and binaries. "Varman" is the
product. This guide uses both.

## How the stack fits together

Varman deploys as **three binaries**: the control plane, the console, and one workstation agent. The
agent is a single binary whose enforcement role is configuration, so there is nothing to install
per-PEP. A control plane, the console, and one `acp-agent` are all a deployment needs; an optional
server-side gateway and two offline tools round it out.

| Component | Binary | Runs on | What it does |
| --- | --- | --- | --- |
| Control plane | `acp-server` | **server** (service) | the hub: identity, endpoints, policy, approvals, break-glass, GRC, evidence, health, and the API the console calls |
| Web console | `acp-console` | **server** (service) | the browser UI over the control plane: dashboards, approvals, policy, kill-switch, register agents and AI endpoints |
| Workstation agent | `acp-agent` | **workstation** | one binary, one `--control-plane` URL; its enforcement role is set by the capability you run: `mcp` (govern an MCP tool server), `firewall` (egress + content firewall), or `guard` (tool-server sidecar). Run several at once with `acp-agent run`. |

Two more binaries are optional or offline, not part of the core three:

| Component | Binary | Runs on | What it does |
| --- | --- | --- | --- |
| LLM gateway (optional) | `acp-gateway` | **server** (service) | governs direct model API calls, holding the upstream key |
| CLI and verifier | `acp` / `acp-verify` | **workstation / CI** | offline tooling: author and test policy, verify and export evidence, red-team, compile agent settings |

The rule of thumb: the **control plane and console are services you run on a server** (plus the optional
gateway); the **agent runs on developer machines**, and the **CLI/verifier are for CI and offline work**.
The one thing an operator sets on the agent is `--control-plane <url>`, which expands into the
per-capability control-plane URLs, so the workstation carries no local rule or model files.
Registrations and governance records (agents, AI endpoints, policy, GRC) are made through the console or
the control-plane API and stored centrally. Chapter 16 is the step-by-step runbook for both sides.

## Chapters

| # | Chapter | Covers |
| --- | --- | --- |
| 0 | [Quickstart](00-quickstart.md) | one governed call in five minutes, then where to go next |
| 1 | [Overview and architecture](01-overview.md) | what ACP is, the six-step spine, the components, where it fits, what is not built |
| 2 | [Policy and authorization](02-policy.md) | the model-v2 DSL, subjects and objects, verdicts, obligations, Cedar, signing, default-deny |
| 3 | [The MCP proxy](03-proxy.md) | `acp-agent mcp` stdio and HTTP, the enforcement pipeline, every flag |
| 4 | [The LLM gateway](04-gateway.md) | `acp-gateway`, credential brokering, model classes, budgets, streaming |
| 5 | [Forward and TLS interception](05-intercept.md) | `acp-agent firewall`, PAC files, the ACP CA, feeding rules from enrolment |
| 6 | [The enforcement guard](06-guard.md) | `acp-agent guard`, the enforcement attestation, making bypass impossible |
| 7 | [Governing coding agents](07-native-compile.md) | `acp native-compile` into managed settings, gateway pinning |
| 8 | [Identity, registry and access](08-identity.md) | agents, human principals, OIDC / Entra, RBAC, delegation, mTLS |
| 9 | [The evidence ledger](09-evidence.md) | the Merkle log, signing, verify and export, encryption at rest, HSM, backup |
| 10 | [The content firewall](10-content-firewall.md) | injection detection, PII / secrets, obfuscation, red-team, groundedness |
| 11 | [Sequence, boundary, break-glass](11-containment.md) | trajectory governance, the data boundary, the kill-switch |
| 12 | [Discovery, enrolment and GRC](12-grc.md) | shadow-AI discovery, coverage, the framework reports and GRC surface |
| 13 | [Command-line tools](13-cli.md) | acp-verify and the CI/offline helpers; what moved to the console and API |
| 14 | [Operations and deployment](14-operations.md) | the server, the console, helm, Postgres, logging, backup, production readiness |
| 15 | [Security and verification](15-security.md) | the trust model, the threat model, how to verify the claims yourself |
| 16 | [Setting it all up (runbook)](16-setup.md) | the end-to-end install and configuration runbook, plus the checks that prove it works |
| 17 | [Console reference](17-console-reference.md) | every console page, field, button, the server endpoint it calls and the RBAC capability it needs |

> **Version:** tracks `acp version` (Beta 0.1.0). This is a tested reference implementation; read
> chapter 14 for the honest maturity picture.
