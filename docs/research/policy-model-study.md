# Policy model study: what "policy" means across the field, and where ACP fits

Date: 2026-09-18
Status: research input for the ACP policy-model redesign (agent as subject, resource as object). No code has changed on the back of this document; it exists to inform the design decision.

## Sourcing caveat (read first)

This study was assembled with general web search disabled in the working environment. Some primary sources were still reachable by direct fetch and are genuinely verified:

- The **Model Context Protocol** specification (`modelcontextprotocol.io`, rev 2025-06-18 and security best-practices rev 2025-11-25).
- Vendor product and documentation pages for **Credo AI, Microsoft, IBM, Holistic AI, OneTrust**.
- The official documentation repositories for **Claude Code, GitHub Copilot, OpenAI Codex, Google Gemini CLI** (fetched from their doc repos and raw endpoints).

Everything grounded in those is treated as verified. Anything drawn from model knowledge rather than a fetched page is flagged in the working notes as "from knowledge, unverified". The structural conclusions (how each system models policy) are stable; treat specific config key names and version-specific behaviour as needing a final documentation check before we depend on them.

---

## 1. Executive summary

Three findings shape the design.

1. **"Policy" means two different things in this market, and they are architecturally distinct.**
   - In the **AI governance / GRC platforms** (Credo AI, Holistic AI, IBM watsonx.governance, OneTrust) a policy is a *control bundle*: obligations mapped to a framework (EU AI Act, NIST AI RMF, ISO 42001), the assessments and evidence required to satisfy them, and the approval gates around a *registered use case or model*. Enforcement means review gates, evidence capture and audit trails. It is documentation and process, not an inline allow or deny of a live call.
   - In **policy-as-code / runtime authorization** (OPA, AWS Cedar, Kyverno, Cerbos) a policy is a *decision rule* of the shape `(subject, action, resource, context) then effect`, evaluated inline at a decision point. This is the shape ACP needs.

2. **The proven authorization shape maps almost exactly onto agent tool-call governance.** Subject = the agent (and the human it acts for), action = the tool, resource = what the tool touches, context = run metadata, effect = allow / deny / step-up / allow-with-obligations. The standard combining algorithm is default-deny with deny-overrides, and the standard deployment is a signed, versioned, hot-reloadable bundle pulled by a local decision point that writes a decision log per call. ACP already implements most of this.

3. **The coding agents already enforce a great deal natively, and the old "config is per-developer-machine only" assumption is now partly outdated.** Copilot, Claude Code and Gemini all ship admin-deployable central policy in 2026. So ACP must not position itself as "these tools have no central policy", nor re-implement their in-session approval, sandboxing or per-tool allow-lists. ACP's defensible ground is the layer none of them provide: one policy enforced across every agent, that the developer cannot edit or bypass, tied to a verified identity, written to a tamper-evident ledger, with separation-of-duty approvals, governing at the resource boundary rather than by brittle command-string matching.

The one-line strategic read: **ACP is the runtime-enforcement rigour of policy-as-code, plus the verifiability the GRC platforms lack, aimed at the per-tool-call layer that MCP deliberately leaves unspecified and that no single-vendor agent can cover across the whole fleet.**

---

## 2. What "policy" means across the field

### 2a. AI governance / GRC platforms: policy is a control bundle, not a runtime rule

Placed on a spectrum from pure governance to pure runtime enforcement:

```
GOVERNANCE / GRC  --------------------------------------->  RUNTIME INLINE ENFORCEMENT
(control packs, framework maps,                             (per-call allow/deny,
 assessments, approvals, evidence)                           thresholds, blocklists)

Credo AI            *   (almost entirely governance; agent "Governor" is preview)
Holistic AI         *   (governance + offline audit/red-team; "Guardian Agents" emerging)
IBM watsonx.gov     *-->  (GRC core via OpenPages, plus HAP/PII detector guardrails)
OneTrust            *---->  (GRC intake/risk/approval, plus a claimed runtime layer)
MS Purview (DSPM)         *-->  (data-axis policy: labels/DLP, partly inline)
Azure AI Content Safety         * (pure inline filter; not even called "policy")
```

- **Credo AI.** The unit is a **Policy Pack**: governance requirements derived from a regulation or standard, decomposed into controls and checkpoints ("what to measure, how to measure it, what documentation is needed"), with evidence mapping from technical outputs (model cards, bias metrics) to requirements. Attached to a *use case* in the AI Registry; drives evidence collection, workflow stages, approvals and reporting. Controls are versioned by key plus version. Nothing blocks a live call. No cryptographic signing of policies; "attestation" is a workflow sign-off recorded in an audit trail.
- **Holistic AI.** Organised as Identify / Protect / Enforce. Policy content is regulatory and operational alignment plus risk controls, evaluated against an AI inventory. Strong on offline audits and red-teaming. "Policy Enforcement, automatically" and "Guardian Agents" hint at automated action, not a documented inline proxy.
- **IBM watsonx.governance.** GRC core (obligation mapping, evidence capture, a governance graph relating systems, risks, controls and policies), powered by OpenPages. The vendor pushes hardest toward runtime with detector guardrails (hate/abuse/profanity, PII, Granite Guardian), but the native mode is monitor-evaluate-flag; blocking is left to the customer's application integration.
- **OneTrust.** GRC intake, risk scoring, approvals and attestations, extended with explicit "runtime enforcement" and "guardrails" messaging (shadow-AI detection, data-leak prevention). The runtime layer is real in the marketing but the mechanism is unspecified and thinner than the governance core.
- **Microsoft** splits the two ideas cleanly. **Purview / DSPM for AI** is data-axis policy: sensitivity labels and DLP, enforced partly inline on the data (content the user cannot access is not returned to the model). **Azure AI Content Safety** is the purest inline enforcement of the whole set (Prompt Shields, groundedness, a task-adherence API that detects misaligned agent tool use, category severity thresholds and blocklists), and tellingly Microsoft does not call it "policy" at all.

**Takeaway.** In the governance category the governed object is a *business use case or registered system*, not a request; enforcement is *process*, not inline. Versioning and audit are strengths; **cryptographically signed, verifiable policy is absent across the whole set.** That absence is a concrete differentiator for ACP.

### 2b. Policy-as-code / runtime authorization: the shape ACP should adopt

Mature authorization engines converge on one model.

- **The canonical tuple:** `(subject/principal, action, resource, context/environment) then effect`, with optional attribute conditions on top (ABAC over RBAC). Cedar formalises this as principal / action / resource / context; OPA expresses it through the `input` document; Cerbos and the Kubernetes admission controllers mirror it.
- **Combining algorithms:** default-deny everywhere, with **deny-overrides / forbid-overrides** as the dominant, recommended default because it is deterministic and order-independent (Cedar forbid-overrides, Cerbos deny-overrides, Gatekeeper and Kyverno "any violation blocks"). Explicit-allow-required is the companion rule. First-match and most-specific/priority exist but are secondary and used mainly for tenant or principal overrides. OPA is the outlier: it gives you primitives and you write the combining algorithm yourself.
- **Deployment mechanics:** policy-as-code in Git, reviewed and tested in CI; compiled into **versioned bundles** with a revision identifier; **pulled by local decision points** with **hot-reload** on a new revision (no restart, low latency, survives control-plane outage); **signed and verified** (OPA ships JWT-signed bundles); rolled out in stages (dry-run or audit mode, then enforce); and a **decision log per call** shipped to a sink for audit and replay.
- **PDP vs PEP:** the Policy Decision Point is a pure, side-effect-free function (policies plus entity data plus request, in; decision plus reasons, out). The Policy Enforcement Point lives in the request path and enforces the result. A third role, the Policy Administration Point, authors and distributes policy.

Cedar example, to fix the shape:

```
permit (
    principal == User::"alice",
    action    == Action::"viewPhoto",
    resource  in Album::"vacation"
)
when { resource.owner == principal };
```

**Takeaway.** ACP is building exactly this, for agent tool calls. The subject is an agent identity, the action is a tool, the resource is what the tool touches, the context is run metadata, and the effect extends beyond binary allow/deny to include step-up and allow-with-obligations. ACP already has signing, versioning, hot-reload and a decision ledger, which is the deployment half of this model.

### 2c. Content safety and guardrail frameworks: a different layer, not ours

NeMo Guardrails, Guardrails AI, Llama Guard and Prompt Guard are **content** enforcers: they answer "is this text safe, on-topic, free of PII, not a jailbreak?", not "is this identity authorized for this action on this resource?". Some (NeMo execution rails, LangGraph interrupts) can sit in the tool-call path, but the decision they render is a content or intent check. None provide agent identity, token validation or a tamper-evident audit trail. ACP can optionally call such a classifier on arguments or results, but content moderation is not ACP's wedge and should not be re-implemented.

---

## 3. The MCP and agent layer (verified against the spec)

- **MCP already standardises connection-level authorization.** It is OAuth 2.1 based, optional, and scoped to HTTP transports (stdio takes credentials from the environment). The MCP server is an OAuth resource server; discovery is via Protected Resource Metadata (RFC 9728) and a `WWW-Authenticate` challenge; PKCE and exact redirect-URI matching are required. The core anti-confused-deputy control is **token audience binding** (RFC 8707 resource indicators): a server must reject any token not issued specifically for it, and must never pass a client token through to a downstream API.
- **MCP deliberately does not specify per-tool-call authorization.** Scopes exist (a `403` for insufficient scope) but scope-to-tool mapping is left to implementers. Tool-level allow-listing and human consent are described as *client-side* SHOULD-level guidance, not protocol enforcement. Tool descriptions and annotations (including `readOnlyHint` / `destructiveHint`) are explicitly **untrusted** and advisory.
- **The spec names the exact attack surface a proxy must handle:** confused-deputy via consent cookies, token passthrough (forbidden, partly because it breaks the audit trail), session hijacking, SSRF during discovery, and local-server compromise / tool "rug-pull". These are MUST-level engineering obligations for any proxy that terminates OAuth, not novel product surface.
- **Agent identity is a stack, and no standard binds it end to end yet:** workload identity (SPIFFE/SPIRE, via attestation), delegated user-to-agent tokens (OAuth token-exchange, RFC 8693; emerging IdP "agent identity" work), a policy engine (Cedar / OPA / OpenFGA, with the OpenID AuthZEN working group standardising the PDP/PEP API), and a tamper-evident ledger (hash-chained, transparency-log style). MCP carries only an opaque OAuth token at the connection edge.
- **Prompt injection splits cleanly:** *detection* of malicious instructions inside tool results is a content-layer problem (best-effort classifiers, spotlighting, dual-LLM patterns); *containment* of what the agent may do even if fooled is an authorization problem. A proxy should rely on containment, not detection alone. Tool-description pinning (hash the schema and description at approval, diff on change) is a concrete integrity control a transparent proxy is well placed to own.

**Takeaway.** MCP has solved *connection* authorization and documented (but not enforced) the proxy attack surface. The open, defensible space for a transparent MCP proxy is **inline per-call authorization tied to a verified agent identity, tool-integrity pinning, and a tamper-evident audit ledger.** That is precisely ACP's lane.

---

## 4. What the coding agents already enforce (the exclusion map)

This is the most scope-relevant section, and it carries a correction to our starting assumption.

### 4a. Comparison

| Dimension | GitHub Copilot | Claude Code | OpenAI Codex | Gemini CLI |
|---|---|---|---|---|
| File access scope | Read/Edit/Write selectors (workspace root, home, globs); workspace-scoped | Read/Edit path rules with globs; working dir plus additional dirs; can fence reads outside working dirs | Sandbox modes read-only / workspace-write (writable roots, cwd plus temp); .git kept read-only | Tool allow-list incl. file tools; folder trust; sandbox allowed paths |
| Command execution and approval | Per-command auto-approve map (regex); permission levels; Autopilot/YOLO | Per-command-prefix Bash rules (allow/ask/deny), subcommand-aware, wrapper-stripping; modes | Approval policy (untrusted / on-failure / on-request / never) crossed with sandbox mode | Per-shell-command allow-list plus a Policy Engine with allow/deny/ask and priority; approval modes; YOLO |
| Network access | Sandbox network filter with allow/deny domains (preview); cloud-agent firewall allow-list | Sandbox network allow/deny domains; web-fetch domain rules feed the sandbox | Disabled by default; opt-in in workspace-write | Sandbox network off by default; domain control via policy |
| Tool / MCP allow-list | Allowed/denied MCP servers; per-tool approval; managed allow-list can be made authoritative | Fine-grained MCP tool rules and globs; connector "ask" overrides | Tool toggles and MCP server config; no per-tool allow/deny grammar | Tool allow-list and MCP allowed set; Policy Engine MCP wildcards |
| Org-level central policy | Yes: managed settings via MDM / server / file across IDE and CLI; cloud-agent repo controls | Yes: managed settings via MDM / file / server; can make managed rules the only source | Weak or none for the CLI; config is developer-owned; cloud governed by seat controls | Partial: system-override settings has highest precedence but is soft-enforced (spoofable) |
| Tamper-evident audit | No (session logs, OpenTelemetry) | No (session logs, hooks, OpenTelemetry) | No | No |
| Who can change the config | Developer edits local files; admin locks via managed settings/MDM | Developer edits local files; admin locks via managed settings | Developer owns the config file | Developer edits local files; admin sets soft system overrides |

### 4b. What they already do well (ACP must NOT re-implement)

1. In-session tool, command and file approval prompts and auto-approve allow-lists.
2. OS-level command sandboxing (filesystem and network) for shell commands.
3. Per-tool and per-MCP-server allow and deny lists, and read/edit path scoping.
4. Default-safe posture (read-only defaults, risky-command deny lists, network-off defaults, plan modes).
5. Vendor-native central policy where it exists (Copilot and Claude Code managed settings, Gemini system overrides). For an org standardised on one agent, this already delivers admin-set policy for that agent.
6. Repo and pull-request controls on the Copilot cloud agent (branch scoping, human review before merge, requester cannot approve, Actions approval gate). This is real separation of duty, but only for that one surface.

### 4c. The gaps an org-level control plane uniquely fills (ACP's scope)

1. **One policy across every agent.** Each vendor's policy is siloed and covers only its own tool, in its own format. ACP expresses policy once and enforces it across all agents, including those with no central mechanism.
2. **Enforcement the developer cannot edit or bypass.** Vendor central policy holds only where MDM is deployed and only for that vendor; Codex config is developer-owned; Gemini's system override is soft. A proxy that mediates the actual tool traffic enforces regardless of local edits.
3. **Verified, non-repudiable agent and human identity.** None of the four cryptographically attest which agent, user and session is acting in a way an org can trust across tools.
4. **Tamper-evident, append-only evidence.** Session logs and telemetry are mutable and vendor-scoped. None offer an independent, cross-agent, tamper-evident ledger of every tool call, approval and data access.
5. **Human-in-the-loop approval with separation of duty.** In-terminal prompts are single-user self-approval. Only Copilot's cloud PR gate enforces a second person, and only for PRs. ACP provides segregated-approver workflows (requester not equal to approver, role-based approval, break-glass) for arbitrary sensitive actions.
6. **Resource-level governance independent of each vendor's grammar.** Native rules are command-string and path pattern matching, documented by the vendors themselves as fragile and bypassable. Governing at the resource boundary (which database, which secret, which egress destination) is uniform across agents and not defeated by a reworded command.

---

## 5. Implications for the ACP policy model

Bringing the four threads together, the design the evidence supports:

- **Subject = agent identity** (the proxy already authenticates as one verified, registry-issued agent), ideally extended over time to carry the human principal it acts for (delegation), since the MCP and identity research shows that binding is the genuinely open problem and a differentiator.
- **Action = the tool** being invoked (the MCP `tools/call` name).
- **Resource = what the tool touches** (database, filesystem, source code, network, secrets, and so on). This is the object of the rule and validates the direction already under discussion. The authorization literature is unanimous that resource is a first-class dimension.
- **Context = run metadata** (arguments as attributes, environment, derived impact, prior-call state, approval state), all proxy-injected and trusted, never agent-asserted.
- **Effect = allow / deny / step-up / allow-with-obligations.** The agent setting differs from classic access control in that arguments are free-form and semantically rich, and "allow with an obligation" (require human confirmation, redact, rate-limit) is more central than a binary decision.
- **Combining algorithm = default-deny with deny-overrides**, matching Cedar, Cerbos and the admission controllers, and matching ACP's current precedence (deny over step-up over shadow over allow). Keep this as the safe default; treat most-specific-wins as an explicit, opt-in mode if ever needed.
- **Deployment = signed, versioned, hot-reloadable policy plus a decision log per call.** ACP already has the signed store, versioning, hot-reload and the Merkle-chained evidence ledger, which is the part the GRC platforms conspicuously lack.

**What ACP deliberately excludes**, on the strength of the exclusion map:

- Content moderation and prompt-injection *detection* (a content layer served by existing guardrail libraries).
- In-IDE interactive approve/deny UX and per-keystroke command prompts (the agents do this well).
- OS process sandboxing (the agents ship this).
- Re-implementing any single vendor's per-command allow-list grammar.

ACP sits **above** the per-agent runtime permissions as the org control plane: one signed policy, enforced in the tool-call path across every agent, bound to a verified identity, written to a tamper-evident ledger, with separation-of-duty approvals, governing at the resource boundary.

---

## 6. Open questions to resolve before building

1. **How is a tool mapped to a resource?** A central tool-to-resource taxonomy (glob patterns, proxy-derived and trusted, so one `resource: database` rule governs every database tool) is the powerful option and mirrors ACP's existing impact taxonomy. Alternatives are operator-named per rule, or agent-declared at registration. This is the pivotal mechanism decision.
2. **What happens to "app"?** Either remove it and make the agent the sole subject, or keep it only as a display-only organisational label that is never matched by policy. The research favours the agent (and, later, the human principal) as the subject; an org grouping is optional and cosmetic.
3. **Resource vocabulary.** Fixed starter set (database, filesystem, source-code, network, secrets, payments, other) versus freeform. A small, extensible, documented set is the pragmatic middle.
4. **Delegated identity.** How far to go now toward binding "agent X acting for user U on task T" into the verified identity, given no industry standard exists yet. This is where ACP can lead, but it is also the hardest.
5. **Obligations model.** Formalising "allow with obligations" (confirm, redact, rate-limit) as first-class effects, since the agent setting needs them more than classic access control does.

---

## 7. Working notes on source confidence

- Verified by direct fetch: the MCP specification pages; Credo AI SDK and product pages; Microsoft Purview and Azure AI Content Safety docs; the Claude Code, Copilot, Codex and Gemini documentation repositories.
- From model knowledge, unverified this run (general search was blocked): the internal policy schemas of Holistic AI and OneTrust; the exact inline-versus-monitor behaviour of IBM's detectors; the guardrail-framework and agent-identity details in section 3 beyond the MCP spec; a small number of Codex config keys taken from an older repository tag whose approval and sandbox model is unchanged.
- Recommended follow-up when search is available: re-verify section 3 (guardrails and identity) against vendor docs, and confirm current config key names for each coding agent before any integration work depends on them.
