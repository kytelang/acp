# 11. Sequence, boundary and break-glass

Some risks are not visible in a single call. An agent can read a secret (allowed) and then send an
email (allowed) and the combination is exfiltration. Some risks need an instant, blunt stop. This
chapter covers the three containment controls: sequence governance, the data boundary, and the
kill-switch.

## Trajectory: governing sequences

Trajectory governance watches a session's history and denies the action that **completes a toxic
combination** of individually-allowed steps, or that exceeds a high-impact velocity budget.

```sh
acp-proxy stdio --trajectory trajectory.yaml ... -- your-mcp-server
```

The classic combination is read-a-secret then egress: each step is fine alone, but the second one,
after the first, is blocked. The monitor keeps a bounded per-session history and evaluates each new
action against it within a time window. It is enabled per PEP with `--trajectory`.

## The data boundary: destination-aware DLP

The [content firewall](10-content-firewall.md) asks "is this content sensitive?". The data boundary
asks a different question: "may this class of data cross to *that* destination?". It is
destination-aware.

```sh
acp-proxy stdio --data-boundary boundary.yaml ... -- your-mcp-server
```

A rule keys on the data class (secret, PII) and the destination resource, and the most-restrictive
outcome wins (deny beats redact beats allow). So a secret in the body of an outbound fetch is blocked,
while PII to an internal store might be redacted rather than denied.

## Break-glass: the kill-switch

Break-glass is the emergency stop. It is a signed grant that overrides normal policy, and it reaches
every surface (tool calls and model calls).

Operate it from the console's **Kill-switch** control (the **Engage or clear the kill-switch** popup,
with Mode, Scope, Reason and TTL fields), or the control-plane API for scripting:

```sh
# engage: mode is lockdown_all | disable_enforce | emergency_bypass
curl -X POST http://<host>:8787/break-glass/engage \
  -d '{"mode":"lockdown_all","scope":"global","reason":"incident 4821","ttl_ms":3600000}'
curl -X POST http://<host>:8787/break-glass/engage \
  -d '{"mode":"lockdown_all","scope":"resource:database","reason":"db incident","ttl_ms":1800000}'
curl -X POST http://<host>:8787/break-glass/clear
```

- **Modes:** `lockdown_all` denies matching calls; `disable_enforce` observes without blocking;
  `emergency_bypass` allows held calls (use with care).
- **Scope:** global, or narrowed to an `agent:`, `resource:` or `tool:`, so you can contain one
  resource or agent without downing the fleet.
- **Fail-safe TTL:** an engaged grant carries a TTL and auto-reverts, **except** `lockdown_all`,
  which persists past its TTL until you explicitly clear it. A lockdown should not quietly lift
  itself.
- **Signed:** the grant is Ed25519-signed and can be pinned to a key; a PEP verifies the signature
  before honouring it, and rejects a tampered or unsigned grant, keeping the current state.

Engaging or clearing break-glass is gated on the `BreakGlass` capability (granted by the `BreakGlassOperator` role) and is recorded in
the [meta-audit](09-evidence.md), so the emergency stop is itself governed and evidenced. In the web
console it is a single control with a live status ([chapter 14](14-operations.md)).

### How to engage or clear the kill-switch from the console (step by step)

1. Select **Kill-switch** in the sidebar, then click **Engage / clear**. The **Engage or clear the kill-switch** popup opens with the live status.
2. Choose a **Mode**: `lockdown_all` (deny), `disable_enforce` (observe without blocking) or `emergency_bypass` (allow held calls).
3. Set the **Scope** (`global`, or narrow it to `agent:`, `resource:` or `tool:`), a **Reason** (an incident reference), and the **TTL ms** after which a grant auto-reverts (except `lockdown_all`, which persists until cleared).
4. Click **Engage** to write the signed grant, or **Clear** to lift it. Engaging and clearing are gated on the `BreakGlass` capability (granted by the `BreakGlassOperator` role) and are themselves recorded in the meta-audit.

## Approvals: resolving a step-up hold

A `step_up` verdict is the human-in-the-loop control. Instead of allowing or denying outright, the PEP
**holds** the call and waits for a person with the right role to approve or deny it. This section is the
runbook for resolving a hold, and the end-to-end trace of what happens.

### The end-to-end step-up flow

1. **The agent makes a call that matches a `step_up` rule.** The proxy does not forward it. It opens an
   approval keyed to `hash(session, principal, tool, arg_hash)`, so the approval is bound to the exact
   call, and returns a JSON-RPC hold to the agent: `-32001 approval required (step-up); re-issue after
   approval`, with the `approvalId` and a `retryAfter` hint in the error data. A hold is not a failure;
   it is a pause.
2. **The hold appears for a human.** A pending approval carries the presented context an approver
   sees: the tool, its impact, and the argument hash (never the raw arguments). The default approval
   lifetime is fifteen minutes; an unresolved hold expires and the call stays blocked.
3. **A human approves or denies.** Approving marks the approval consumable exactly once; denying (or
   letting it expire) turns it terminal.
4. **The agent re-issues the identical call.** On approve, the same key consumes once and the proxy
   forwards the call to the tool server; the decision and its approval are recorded in the ledger. On
   deny or expiry, the agent gets a structured tool error and the call never runs. Because the key
   includes the canonical `arg_hash`, a re-issue whose arguments differ maps to a different key and
   cannot ride the earlier approval.

### Resolving a hold from the console

The console **Approvals inbox** lists the pending holds held in the control plane's approval store,
each with its tool and presented context and an **Approve** and a **Deny** button.

1. Open the console and select **Approvals** (the control plane also serves a minimal inbox at `/`).
2. Read the presented context: tool, impact and argument hash. Use `acp diagnose <ledger.db> <seq>` if
   you want the redacted decision bundle for the matching record (it never shows raw arguments).
3. Click **Approve** to release the held call, or **Deny** to block it.

### Resolving a hold over the API

The console buttons POST to these routes; use them directly for scripting or from an incident tool:

```sh
# list pending holds
curl -s http://<host>:8787/approvals/pending

# approve or deny one, by id
curl -X POST http://<host>:8787/approvals/<id>/approve -H "Authorization: Bearer <token>"
curl -X POST http://<host>:8787/approvals/<id>/deny    -H "Authorization: Bearer <token>"
```

Both routes are gated on the `Approve` capability (granted by the approver role), so with RBAC enabled
only an authorised human can resolve a hold, and the resolver is attributed on the record. The `acp
approve` / `acp deny` / `acp approvals` CLI commands are **retired**; resolve holds from the console or
these routes.

### Where a hold lives

There are two approval stores, and it matters which one a hold is in:

- **Control-plane store** (`acp-server --approvals`): the holds the console inbox and the
  `/approvals/*` routes see.
- **Proxy-local store** (`acp-proxy --approvals`, default `<ledger>.approvals`): where a workstation
  proxy currently keeps its own holds.

Honest limitation today: a step-up raised at a workstation proxy is held in that proxy's local store,
so it does not yet surface in the console inbox. Run the proxy against the control plane's approval
store, or resolve workstation holds where the proxy keeps them, until the field-approval push lands.
For the self-contained quickstart proxy this is the `<ledger>.approvals` file beside the ledger.
