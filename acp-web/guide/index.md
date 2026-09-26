# The Varman (ACP) guide

**Varman** (the Agent Control Plane, ACP) is a vendor-neutral, on-premises layer that authorises
what your AI agents and applications actually do, at the resource boundary, and records every
decision as tamper-evident evidence a third party can verify with a public key alone. It governs
the action, not just the words: which database, secret, file, model or network an agent may touch,
for which human, and in what sequence.

"ACP" is the internal architecture name and the prefix on the crates and binaries. "Varman" is the
product. This guide uses both.

## How the stack fits together

Varman is one control plane and several enforcement points (PEPs). You put a PEP in the path of each
place an agent acts, and they all consult the same signed policy and write to the same signed ledger.

| Component | Binary / crate | What it governs |
| --- | --- | --- |
| MCP proxy | `acp-proxy` | agent tool calls over MCP (stdio and streamable-HTTP) |
| LLM gateway | `acp-gateway` | direct model API calls, holding the upstream key |
| Forward / intercept proxy | `acp-intercept` | arbitrary HTTP and API traffic, with optional TLS interception |
| Enforcement guard | `acp-guard` | refuses un-proxied calls in front of a tool server |
| Native compile | `acp-nativecompile` | compiles one policy into Claude / Copilot / Gemini settings |
| Control plane | `acp-server` | approvals, policy deploy, break-glass, health, evidence API |
| CLI | `acp-cli` (`acp`) | policy, identity, evidence, GRC, discovery, red-team |
| Web console | `acp-console` | a read-only dashboard over the control plane |

## Chapters

| # | Chapter | Covers |
| --- | --- | --- |
| 1 | [Overview and architecture](01-overview.md) | what ACP is, the six-step spine, the components, where it fits, what is not built |
| 2 | [Policy and authorization](02-policy.md) | the model-v2 DSL, subjects and objects, verdicts, obligations, Cedar, signing, default-deny |
| 3 | [The MCP proxy](03-proxy.md) | `acp-proxy` stdio and HTTP, the enforcement pipeline, every flag |
| 4 | [The LLM gateway](04-gateway.md) | `acp-gateway`, credential brokering, model classes, budgets, streaming |
| 5 | [Forward and TLS interception](05-intercept.md) | `acp-intercept`, PAC files, the ACP CA, feeding rules from enrolment |
| 6 | [The enforcement guard](06-guard.md) | `acp-guard`, the enforcement attestation, making bypass impossible |
| 7 | [Governing coding agents](07-native-compile.md) | `acp native-compile` into managed settings, gateway pinning |
| 8 | [Identity, registry and access](08-identity.md) | agents, human principals, OIDC / Entra, RBAC, delegation, mTLS |
| 9 | [The evidence ledger](09-evidence.md) | the Merkle log, signing, verify and export, encryption at rest, HSM, backup |
| 10 | [The content firewall](10-content-firewall.md) | injection detection, PII / secrets, obfuscation, red-team, groundedness |
| 11 | [Sequence, boundary, break-glass](11-containment.md) | trajectory governance, the data boundary, the kill-switch |
| 12 | [Discovery, enrolment and GRC](12-grc.md) | shadow-AI discovery, coverage, the framework reports and GRC surface |
| 13 | [The acp CLI](13-cli.md) | every subcommand, grouped by job |
| 14 | [Operations and deployment](14-operations.md) | the server, the console, helm, Postgres, logging, backup, production readiness |
| 15 | [Security and verification](15-security.md) | the trust model, the threat model, how to verify the claims yourself |

> **Version:** tracks `acp version` (Beta 0.1.0). This is a tested reference implementation; read
> chapter 14 for the honest maturity picture.
