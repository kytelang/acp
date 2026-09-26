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

- **Subject:** the `agent` (its registered identity or label) and the human `principal` it acts for
  (`unattributed` when there is no verified human).
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
      - kind: budget
        tokens: 2000000              # a token / cost budget across the session
```

`redact` masks the named fields (and anything the classifier flags as PII or a secret) while leaving
the evidence argument-hash over the original intact. `rate_limit` and `budget` are enforced with a
token bucket, shared across replicas when Postgres is configured (see [chapter 14](14-operations.md)).

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

See [chapter 8](08-identity.md) for who is allowed to deploy a policy (the `PolicyAdmin` capability)
and [chapter 15](15-security.md) for how the signed policy chain is verified.
