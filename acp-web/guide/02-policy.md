# 2. Policy and authorization

One policy language governs every surface. It is a small YAML DSL (the "model-v2" DSL), it compiles
to [Cedar](https://www.cedarpolicy.com/) for evaluation, and it is signed and versioned so a PEP only
loads a policy whose signature it can verify. This chapter is the reference for writing one.

## The shape of a policy

```yaml
version: 1
default: allow          # allow or deny; see "default-deny" below
rules:
  - id: no-prod-delete
    when: { resource: database, operation: delete }
    verdict: deny
    reason: destructive bulk delete is never allowed
```

A policy is a `version`, a `default` verdict for unmatched actions, and an ordered list of `rules`.
Each rule has an `id`, a `when` matcher, a `verdict`, and optional `obligations`, `approvers` and
`reason`.

## Subject, object, operation

Every request is described by a **subject**, an **object** and an **operation**, and a rule matches
on any combination of them.

- **Subject:** the `agent` (its registered identity or label), the human `principal` it acts for
  (`unattributed` when there is no verified human), and the principal's directory `group` (see below).
- **Object:** the `resource`. Resources are a trusted taxonomy derived from the tool or model name,
  never asserted by the agent: `database`, `filesystem`, `secrets`, `payments`, `network`,
  `model-class` and so on.
- **Operation:** `read`, `write`, `delete`, `execute`, `egress`, and the like, again derived, not
  agent-supplied.
- **Arguments and environment:** `arg` matches structured argument fields (with `eq`, `gt`, `in`,
  and similar), and `env` matches the deployment environment (for example `env: { eq: "prod" }`).
- **Tool and app:** `tool` matches the tool name with globs (`db.*`), `app` scopes a rule to a
  registered application.

```yaml
  - id: cap-spend
    when:
      tool: "payments.charge"
      arg: { amount_cents: { gt: 50000 } }
    verdict: step_up
    approvers: ["finance"]
  - id: anon-cannot-read-secrets
    when: { resource: secrets, principal: unattributed }
    verdict: deny
```

Because the resource and operation are derived from a trusted taxonomy, a rule about `resource:
database` governs every tool that touches a database, without you enumerating tool names. The
taxonomy is configurable, and it fails safe to the most-privileged classification on ambiguity.

## Differentiating by directory group

`group` matches a directory group or role the human principal belongs to, taken from the identity
provider (Entra app roles or group claims, or an OIDC `groups`/`roles` claim). It is how **one
org-wide policy treats different teams differently without a config per user**: membership lives in
the IdP, which the organisation already manages for thousands of people, and a rule keys on the group.

```yaml
  - id: finance-no-external-shell
    when: { group: finance, tool: shell.exec, resource: external_network }
    verdict: deny
  - id: contractors-writes-need-approval
    when: { group: contractors, operation: write }
    verdict: step_up
```

Move a person between groups in the IdP and their governance changes automatically, with nothing to
edit in Varman. The match is exact set-membership against the trusted `principal_scopes` the
enforcement point receives from the verified identity (never argument content), so an agent cannot
spoof a group. The gateway fills `principal_scopes` from the verified bearer token's roles; a
workstation proxy takes them from its declared `--principal-groups` (the same way it declares
`--principal`). This is the recommended way to scale one policy across a large organisation: keep the
firewall config and policy org-wide, and let `group` rules express the per-team differences.

## Verdicts

- **`allow`** lets the action through.
- **`deny`** blocks it, fail-closed.
- **`step_up`** holds the action for a human decision (see [chapter 11](11-containment.md) and the
  approvals inbox in [chapter 14](14-operations.md)). Name the approver groups with `approvers`.
- **`allow`** with **`obligations`** lets it through subject to conditions.

## Obligations

Obligations attach conditions to an allow.

```yaml
    obligations:
      - kind: redact
        fields: [ssn, card]          # mask these argument fields on the way through
      - kind: rate_limit
        max: 1000
        window_ms: 60000             # a token bucket per subject
      - kind: confirm                # require an interactive confirmation
      - kind: disclose                # label the response as AI-generated (transparency)
```

`redact` masks the named fields (and anything the classifier flags as PII or a secret) while leaving
the evidence argument-hash over the original intact. `rate_limit` is enforced with a token bucket,
shared across replicas when Postgres is configured (see [chapter 14](14-operations.md)). `disclose`
is the transparency obligation (EU AI Act Art. 50): the PEP annotates the response as AI-generated and,
when an enforcement key is set, attaches a signed content credential (see [chapter 10](10-content-firewall.md)).
The four obligation kinds are `confirm`, `redact`, `rate_limit` and `disclose`.

## Precedence and default-deny

When several rules match, precedence is **deny > step_up > shadow > allow**, so the most restrictive
outcome wins. `shadow` is a special verdict used during rollout: the rule is evaluated and recorded
as would-block, but the action still passes, so you can watch a policy before it bites.

`default` sets the verdict for an action no rule matches. The starter scaffold uses `default: allow`
so you can observe first. The goal is `default: deny`. The staged path is: run real traffic, then
check coverage and readiness:

```sh
acp coverage observed.txt governed.txt        # how much of the estate a rule matches
acp posture evidence.db --required 0.8         # is coverage high enough to flip safely?
```

`acp posture` reads real decisions from the ledger, reports the rule coverage and the exact set of
tools that would newly block under default-deny, and tells you whether it is safe to flip. When it
says READY and you have added explicit allow rules for the would-block set, switch `default` to
`deny`.

## Enforcement mode: observe before you enforce

`shadow` above shadows a single rule. To roll ACP into a production path with **zero risk of blocking
anything** while you build confidence, set a manifest-wide enforcement mode instead:

```yaml
version: 1
enforcement_mode: observe   # observe | enforce (default enforce); "mode" is accepted as a short alias
default: deny
rules:
  - id: no-external-egress
    when: { resource: external_network, operation: egress }
    verdict: deny
```

In `observe` mode every rule (and every downstream check: content firewall, delegation, memory-write,
trajectory, data-boundary and rate-limit or confirm obligations) is still evaluated and the intended
verdict is recorded in the signed evidence, but a would-be `deny` or `step_up` is **downgraded to
`shadow`, so the action proceeds**. The evidence reason records what would have happened, for example
`observe mode: would deny (content firewall: prompt-injection)`, and these show up as `shadow` in the
governance report's verdict split, so you can watch exactly what enforcing would do before it bites.
When the shadow count is what you expect, switch to `enforcement_mode: enforce` (or drop the line) to
turn on blocking. One safety carve-out: a tool quarantined by tool-integrity (its definition changed
since it was pinned) is still hard-blocked in observe mode, because ACP can no longer trust what it does.

This is the difference from `default: allow`: `default: allow` lets *unmatched* actions through but
still enforces your explicit `deny` rules; `observe` enforces nothing, so you can deploy a strict
default-deny manifest and see the full would-block set before a single call is stopped.

## Least-privilege policy from observed traffic

You do not have to write the allow-list by hand. Once agents have run through a PEP (shadow mode is
ideal), ACP can synthesise the smallest default-deny policy that permits exactly what was observed and
denies everything else.

In the console, open **Policy**. The **Suggested least-privilege policy** card shows the proposal
synthesised from the observed decisions: a default-deny policy with one rule per tool that was allowed
(or held for step-up), a would-block check confirming it blocks nothing that was actually allowed, and
an **Approve and deploy** button. Approving deploys the proposal through the signed policy store, so the
policy that goes live is versioned and signed, and the approval is your PolicyAdmin identity. Review the
proposal before approving: it is a starting point, and you can tighten it further in the editor.

> API (for automation and CI): `acp learn <ledger.db> --least-privilege` prints the same synthesised
> policy from a local ledger, and `GET /policy/suggest` returns it (with the would-block check) from the
> control plane. Deploy it with `POST /policy-store/deploy`, which signs and versions it.

## Authoring a rule in plain English

On the **Policy** page, the "Author from a description" card takes a rule in plain English (for example
"No agent may delete from the database"), drafts the model-v2 DSL, and shows the verification matrix,
the concrete allow/deny outcome for a set of example requests, before you deploy. The verification is
the point: even a draft written by an LLM is shown as an exact allow/deny table you must confirm, and a
draft that does not compile is reported, never deployed.

> API: `POST /policy/author {text, tests?}` returns the draft and the matrix. Point the drafter at a
> real LLM by starting the server with `--author-llm-url`, `--author-llm-key` and `--author-llm-model`
> (an OpenAI-compatible chat-completions endpoint); without them a deterministic pattern drafter is the
> offline fallback, and either way the verification matrix runs before deploy.

## Compiling, testing and deploying

```sh
acp policy-compile policy.yaml      # compile to Cedar and report errors, without deploying
acp policy-test policy.yaml tests   # evaluate example requests against the policy
```

A policy is deployed through the control plane, which validates it, versions it, signs it with the
deploy key, and writes it to the policy store the PEPs watch. A PEP hot-reloads a new version **only
after verifying the signature**; a policy that does not compile is rejected and nothing is written,
and a bad deploy leaves the last good policy serving. Evaluation itself is fail-closed: any error
building the request context or evaluating Cedar results in a deny, never an accidental allow.

### How to deploy a policy version from the console (step by step)

1. Select **Policy** in the sidebar. The card has two tabs: **Deployed policy** (the current signed version) and **Editor**.
2. Click the **Editor** tab. Either edit the policy directly in the syntax-highlighted editor, or click **Upload .yaml** and pick a file; its contents load into the editor for review.
3. Set the **Author** field (who is deploying).
4. Click **Deploy policy**. The control plane validates, versions and signs it, then writes it to the policy store. A PEP hot-reloads it only after verifying the signature; a policy that does not compile is rejected and the last good policy keeps serving. The **Deployed policy** tab and version badge refresh on the next tick.

See [chapter 8](08-identity.md) for who is allowed to deploy a policy (the `PolicyAdmin` capability)
and [chapter 15](15-security.md) for how the signed policy chain is verified.

## Changing policy safely

A policy change is a change to what your agents may do, so treat it like a code change: see the diff,
test it, and be able to reproduce old decisions. Three tools make this safe.

### See exactly which decisions a change flips

`acp policy-test --diff` evaluates the same set of example calls against the old and the new policy and
prints **only** the calls whose verdict changes, so a reviewer sees the behavioural diff, not a text
diff:

```sh
acp policy-test --diff old.yaml new.yaml calls.jsonl
# flip call#3 payments.charge: Allow -> StepUp
# 1 of 42 calls change verdict
```

Each line of `calls.jsonl` is one call, `{"tool":"...","args":{...},"env":"..."}`, turned into a
request context exactly as the proxy would build it. Run this in CI on every policy pull request and
fail the build if the flips are not the intended ones. Plain `acp policy-test policy.yaml calls.jsonl`
prints the verdict (and matched rule) for every call.

### Reproduce a past decision

`acp replay` re-evaluates a recorded decision from the ledger against a policy and tells you whether the
verdict is reproduced or has drifted:

```sh
acp replay evidence.db <seq> policy.yaml
# REPRODUCED: record #128 (payments.charge) re-evaluates to 'step_up', matching the ledger
# or: DRIFT: record #128 recorded 'allow' but now evaluates to 'deny'
```

It warns if the supplied policy's hash differs from the one recorded with the decision, so you can tell
whether a difference is because the policy changed since. This is how you answer "would this call still
be allowed under today's policy?" from evidence, and it exits non-zero on drift.

### Draft a policy from real traffic

`acp learn` reads the decisions in a ledger (run the proxy in `--shadow` first to observe without
blocking) and emits a compilable draft policy that gates the high- and medium-impact tools it saw behind
a step-up, leaving the rest at default-allow:

```sh
acp-agent mcp stdio --shadow ... -- your-mcp-server   # observe real traffic first
acp learn evidence.db > draft-policy.yaml          # a starting policy to review, not to deploy blind
```

Review the draft before enforcing it: it is a starting point derived from what actually happened, not a
finished policy. Pair it with `acp posture` (above) to decide when coverage is high enough to move to
default-deny.

## Policy schema reference

This section is the authoritative field list for the policy YAML, taken straight from the parser
(`crates/acp-core/src/policy/dsl.rs`) and the compiler (`policy/compile.rs`). If a field is not listed here, it is
not understood by the engine.

### A complete annotated example

```yaml
version: 1                       # schema version (required, integer)
default: deny                    # verdict when no rule matches (allow | deny | step_up | shadow)
mode: enforce                    # optional free-form label, parsed and carried, not interpreted
metadata:                        # optional, purely descriptive
  name: production-guardrails
  owner: platform-security

rules:
  # A deny that governs every database delete, whatever the tool is called.
  - id: no-db-delete
    when:
      resource: database         # trusted, derived from the tool name, not from arguments
      operation: delete
    verdict: deny
    reason: destructive deletes are never allowed in prod

  # A step-up (human approval) for large payments, matched on an argument value.
  - id: cap-spend
    when:
      tool: "payments.charge"    # exact, or a glob such as "payments.*", or "*" / absent for any
      arg:
        amount_cents: { gt: 50000 }
      env: { eq: prod }          # trusted environment matcher
    verdict: step_up
    approvers: [finance, oncall] # groups routed to the approvals inbox
    reason: high-value charge needs sign-off

  # Unattributed callers (no verified human) may not read secrets.
  - id: anon-cannot-read-secrets
    when:
      resource: secrets
      principal: unattributed
    verdict: deny

  # Allow a database read, but with obligations attached to the allow.
  - id: read-with-guardrails
    when:
      resource: database
      operation: read
    verdict: allow
    obligations:
      - kind: redact
        fields: [ssn, card]      # mask these argument fields on the way through
      - kind: rate_limit
        max: 1000
        window_ms: 60000         # at most 1000 calls per 60s window for this subject
      - kind: confirm            # require an interactive confirmation
```

### Top-level fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | integer | yes | Schema version of the policy document. |
| `default` | verdict | no (defaults to `allow`) | Verdict applied when no rule matches. One of `allow`, `deny`, `step_up`, `shadow`. |
| `mode` | string | no | Free-form label. It is parsed and kept, but the evaluation engine does not interpret it. |
| `metadata` | object | no | Descriptive only. Holds `name` and `owner`, both optional strings. |
| `rules` | list | yes | Ordered list of rules (see below). May be empty, in which case every action takes the default. |

### Rule fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Must be non-empty (an empty id is rejected at validation). Stamped into evidence as the matched rule. |
| `when` | object | yes | The match predicates. All present predicates must hold (AND). An empty `when` matches every action. |
| `verdict` | verdict | yes | One of `allow`, `deny`, `step_up`, `shadow`. An `allow` compiles to a Cedar `permit`, everything else to a `forbid`. |
| `approvers` | list of strings | no | Approver groups for a `step_up`. Empty by default. |
| `reason` | string | no | Human-readable explanation, carried into the decision and evidence. |
| `obligations` | list | no | Conditions applied when the rule allows (see below). Empty by default. |

### The `when` predicates

Every predicate is optional. An absent predicate is ignored (matches anything). Fields marked
*trusted* are injected by the proxy from the verified identity or the taxonomy, so an agent cannot
spoof them through its arguments.

| Predicate | Matches on | Form | Trusted |
|---|---|---|---|
| `tool` | the tool or model name | exact, glob (`db.*`), `*`, or absent | derived |
| `app` | the registered application id | exact, glob, or absent | yes |
| `agent` | the registered agent id | exact, glob, or absent | yes |
| `principal` | the human the agent acts for | exact, glob, or absent. Use `unattributed` to match calls with no verified human | yes |
| `group` | a directory group / role of the human principal (from the IdP) | exact group name, or absent for any | yes |
| `resource` | the resource class the tool touches | a taxonomy value: `database`, `filesystem`, `source-code`, `network`, `secrets`, `payments`, `messaging`, `compute`, `identity`, `other` | yes |
| `operation` | the operation the tool performs | a taxonomy value: `read`, `write`, `delete`, `execute`, `egress`, `admin` | yes |
| `arg` | agent-supplied argument fields | a map of field name to a matcher (see below), evaluated against the `context.args` namespace | no (agent data) |
| `env` | the deployment environment | a single matcher, e.g. `{ eq: prod }`, evaluated against `context.env` | yes |
| `impact` | the proxy-derived impact level | a single matcher against `context.impact`, whose values are `low`, `medium`, `high` | yes |

### Matchers

A matcher is a single-key map, `{ <op>: <value> }`. These are the operators the compiler understands:

| Operator | Meaning | Example |
|---|---|---|
| `eq` | equal to | `{ eq: prod }` |
| `ne` | not equal to | `{ ne: test }` |
| `gt` | greater than (numeric) | `{ gt: 50000 }` |
| `gte` | greater than or equal (numeric) | `{ gte: 100 }` |
| `lt` | less than (numeric) | `{ lt: 10 }` |
| `lte` | less than or equal (numeric) | `{ lte: 9 }` |
| `in` | value is in a list | `{ in: [prod, staging] }` |
| `contains` | substring match | `{ contains: "@example.com" }` |
| `exists` | the field is present at all | `{ exists: true }` |
| `contains_class` | a data-class check against the trusted `derived` namespace, not the raw argument. Values are `pii` or `secret` | `{ contains_class: pii }` |

The `regex` matcher is deliberately not supported in this version: a rule that uses it is rejected at
validation time rather than compiled into something inert. An empty matcher (no operator) is also
rejected.

### Obligations

An obligation attaches a condition to an allowing rule. It is parsed here and executed by the proxy at
enforcement time.

| `kind` | Extra fields | Meaning |
|---|---|---|
| `redact` | `fields`: list of strings | Strip or mask the named argument or result fields before the call proceeds. |
| `rate_limit` | `max`: integer, `window_ms`: integer | Cap the call frequency to `max` per `window_ms` for this subject and resource. |
| `confirm` | none | Require a human confirmation before proceeding (routed to the approvals inbox, like a step-up). |

These three (`redact`, `rate_limit`, `confirm`) are the only obligation kinds the parser accepts today.

### Precedence

When several rules co-determine an action, the most restrictive wins:
**deny > step_up > shadow > allow**. `shadow` records a would-block without enforcing it, which is how
you roll a rule out safely. Evaluation is fail-closed: any error building the context or evaluating a
rule results in a `deny`, never an accidental allow.
