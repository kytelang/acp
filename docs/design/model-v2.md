# ACP domain model v2

Date: 2026-09-18
Status: design spec. This is the model the policy DSL, the enforcement path, and the console are all built from. It supersedes the thin `App / Agent / Rule / When` model. It is anchored to `docs/positioning.md` and informed by `docs/research/policy-model-study.md`.

## 0. Why v1 was too thin

The current model expresses only: an `App` owns `Agent`s, and a flat `Rule` matches `when { tool, app, agent, arg }`. It cannot express who the human behind an agent is, what class of system a tool touches, whether an action reads or writes, or any outcome richer than allow/deny/step-up. None of the wedge in the positioning doc (verified human identity, resource-level policy, obligations, scoped emergency stop) fits into it. v2 fixes the model first, on purpose, because you cannot write a policy language or a console for concepts the domain cannot hold.

## 1. Decisions taken

These four decisions set the schema. They are taken here with rationale so the build does not stall on them.

### D1. Subject is the agent AND the human principal it acts for (delegation). Identity is proxy-injected, never agent-asserted.

Governance that cannot say which person is behind a call is not governance, and the study named delegation ("agent X acting for user U on task T") as the differentiating, industry-open problem. So the human principal is first class.

The hard part is sourcing the human identity verifiably. The rule is: **the human identity is established by the proxy, from a trusted source, and stamped onto every call. An agent can never assert its own principal.** Sourcing degrades gracefully by transport:

- Remote / HTTP agents: from the MCP OAuth token's verified subject claim, issued by the org identity provider (Entra today). This is the strong, verifiable path.
- Local / stdio agents: from an explicit enrolment that binds the launching OS or SSO user to the agent session at proxy start. Verifiable to the extent the host login is.
- No verified human available: the delegation is marked `unattributed`. Policy can then deny or step-up high-risk or high-impact actions when the principal is unattributed, so the gap is visible and governable rather than silent.

This makes the model work today (it degrades, it does not block) while giving the verifiable path first-class status where identity exists.

### D2. Resource is modelled as a class now; a specific instance is an optional refinement.

The primary object of a rule is the resource class (`database`, `filesystem`, ...). A specific target (`prod-db`, `github.com/org/repo`) is an optional `instance` attribute on the match, so "prod database" is expressible but v1 is not blocked on a full instance registry.

### D3. Operation is a first-class, derived dimension.

"Read database" and "delete database" are different governance events. `operation` (`read | write | delete | execute | egress | admin`) is derived from the tool (and where needed its arguments) by the same trusted taxonomy that derives the resource. Rules can match on `resource + operation` without listing individual tools.

### D4. Obligations are first-class effects. v1 ships three.

The agent setting needs "allow but ..." far more than classic access control. v1 effects: `allow`, `deny`, `step_up`, and `allow_with_obligations`, where the obligation set in v1 is:
- `confirm`: require human approval before proceeding (unifies with today's step-up and the approvals inbox).
- `redact`: transform matched arguments or results before they pass (for example mask a field a tool would return).
- `rate_limit`: cap call frequency per (agent, resource) window.
Further obligations (extra-log, budget caps, content-scan-via-integration) are additive later.

## 2. The model, by layer

Notation is illustrative, not final Rust. Fields marked (trusted) are proxy-injected and may never be set from agent-supplied data.

### Layer A. Subject (who is acting)

```
Agent
  id            string        stable id
  name          string
  kind          enum          copilot | claude | codex | gemini | custom
  status        enum          active | revoked
  token_sha256  string        registration secret hash (verified identity)

HumanPrincipal
  id            string        stable id (maps to IdP subject where available)
  display       string
  source        enum          oauth | os_login | sso | unattributed
  verified      bool          (trusted)

Delegation (the per-session envelope)
  agent_id      string        (trusted)
  principal_id  string        (trusted; may be the unattributed principal)
  task          string        free-text task label for the session
  scope         [Resource]    optional declared resource scope for the session
  issued_ms     int
  expires_ms    int
```

Optional, display only, never matched by policy:
```
Team   id, name, owner        an organisational grouping for the console
```
"App" from v1 collapses into Team, and is removed as a policy dimension.

### Layer B. Resource (what is touched)

```
Resource        one of a small, extensible vocabulary:
  database | filesystem | source-code | network | secrets |
  payments | messaging | compute | identity | other

Operation       read | write | delete | execute | egress | admin

ResourceRef (the trusted, derived object stamped on a call)
  resource      Resource      (trusted)
  operation     Operation     (trusted)
  instance      string?       optional specific target, e.g. "prod-db" (trusted where derivable)
```

### Layer C. Action classification (tool -> resource + operation)

The taxonomy is the trusted classifier. It maps MCP tool-name globs to a `(resource, operation)` and optional instance extractor. It is the same shape as the existing impact taxonomy and lives beside it.

```
taxonomy.yaml (illustrative)
  rules:
    - match: "db.*"          resource: database    operation: read
    - match: "db.exec*"      resource: database    operation: write
    - match: "sql.delete*"   resource: database    operation: delete
    - match: "read_file"     resource: filesystem  operation: read
    - match: "write_file"    resource: filesystem  operation: write
    - match: "git.*"         resource: source-code operation: write
    - match: "http.*|fetch"  resource: network     operation: egress
    - match: "secret.*|vault.*" resource: secrets  operation: read
    - match: "charge_*"      resource: payments    operation: execute
  default:                   resource: other       operation: execute
```

Because classification is trusted and central, one rule `resource: database, operation: delete` governs every database-delete tool across every agent, which is the whole point of resource-level policy.

### Layer D. Policy and decision

```
Policy (signed, versioned; exists today)
  version   int
  default   Verdict          allow | deny
  rules     [Rule]

Rule
  id         string
  when       Match
  effect     Effect
  reason     string?

Match (all optional except at least one selector; absent = any; exact or glob)
  agent      string?         (trusted) registered agent
  principal  string?         (trusted) human principal, or the token "unattributed"
  team       string?         (trusted) org grouping
  resource   Resource?       (trusted)
  operation  Operation?      (trusted)
  instance   string?         (trusted where derivable)
  tool       string?         the raw tool name, for fine overrides
  arg        {name: Matcher} agent-supplied arguments (untrusted; the only untrusted namespace)
  env        Matcher?        (trusted)
  impact     Matcher?        (trusted)

Effect
  verdict     enum           allow | deny | step_up | allow_with_obligations
  obligations [Obligation]   for allow_with_obligations
  approvers   [string]       for step_up / confirm

Obligation
  kind        enum           confirm | redact | rate_limit
  params      map            e.g. redact: {fields:[...]}; rate_limit: {max, window_ms}
```

Combining algorithm is unchanged and deliberate: default-deny, deny-overrides (`deny > step_up > allow_with_obligations > allow`). Most-specific-wins stays out unless explicitly requested later.

```
Decision (written to the tamper-evident ledger; extends today's record)
  subject     {agent_id, principal_id, verified}
  action      {tool, operation}
  resource    {resource, instance}
  context     {args-summary, env, impact}
  verdict     Verdict
  obligations [Obligation]      what was applied
  matched     rule-id
  hlc, ts, seq                  ordering + ledger position
```

### Layer E. Emergency and integrity

```
KillSwitch grant (hardens today's break-glass)
  mode        lockdown | disable_enforce | emergency_bypass
  scope       global | agent:<id> | resource:<class> | tool:<name>   (new: scoped)
  reason      string        (required)
  actor       string        (required; bound to a break-glass role)
  issued_ms   int
  ttl_ms      int
  sig         bytes         (new: signed, proxy-verified, like the policy store)

TTL semantics by mode (correction to today):
  lockdown         persists until explicitly cleared (fail-safe = stay locked)
  emergency_bypass auto-reverts on TTL (fail-safe = re-lock)
  disable_enforce  auto-reverts on TTL

ToolIntegrityPin
  server, tool, schema_hash, description_hash, pinned_ms
  on change -> alert + configurable deny (poisoning / rug-pull defence)
```

## 3. Trust boundary (the one rule that keeps this sound)

Exactly one namespace is agent-controlled and therefore untrusted: `arg` (the tool arguments). Everything else the policy matches on, agent, principal, team, resource, operation, instance, env, impact, is derived and stamped by the proxy from verified identity and the trusted taxonomy. This is the invariant that makes resource-level, identity-bound policy un-spoofable, and it is the same principle that already protects `context.app` and `context.impact` today.

## 4. What changes in the code

| v1 | v2 |
|---|---|
| `acp-registry`: App, Agent(app_id) | Agent (standalone), HumanPrincipal, Delegation; App -> optional Team (display only) |
| `acp-policy` dsl `When {tool, app, agent, arg, env, impact}` | `Match {agent, principal, team, resource, operation, instance, tool, arg, env, impact}` |
| verdict only | `Effect {verdict, obligations, approvers}` |
| impact taxonomy only | add tool -> (resource, operation) taxonomy beside it |
| `build_context_identified(tool,args,env,agent,app,tax)` | stamp principal + resource + operation (trusted) as well |
| break-glass: global, unsigned, lockdown auto-reverts | scoped, signed, mode-aware TTL |
| console: Apps + Agents | Subjects (agent + human), Resources, richer policy authoring, kill-switch |

## 5. Phased build order

1. Model types and taxonomy (this spec, in code): `HumanPrincipal`, `Delegation`, `Resource`, `Operation`, the tool -> (resource, operation) taxonomy; registry made agent-standalone with delegation. Unit-tested, no behaviour change yet.
2. Policy DSL and evaluation: extend `Match` and `Effect`, compile resource/operation/principal conditions, stamp the trusted context, keep default-deny + deny-overrides. Obligations parsed and represented (execution comes in phase 3).
3. Enforcement wiring in the proxy: classify each call via the taxonomy; extend the identified context with principal + resource + operation; execute obligations (confirm -> approvals, redact, rate_limit); scoped, signed kill-switch.
4. The moat: unavoidable, fail-closed enforcement (agent cannot call governed tools when the proxy is absent or down) and tool-integrity pinning.
5. Console: subject view (agent + human), resource view, policy authoring over resource/operation/obligations, evidence with principal and resource, kill-switch control.

Each phase is independently shippable and leaves the tree green. Phase 1 is pure addition and safe to start immediately.
