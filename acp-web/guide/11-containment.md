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

Engaging or clearing break-glass is gated on the `BreakGlassOperator` capability and is recorded in
the [meta-audit](09-evidence.md), so the emergency stop is itself governed and evidenced. In the web
console it is a single control with a live status ([chapter 14](14-operations.md)).

### How to engage or clear the kill-switch from the console (step by step)

1. Select **Kill-switch** in the sidebar, then click **Engage / clear**. The **Engage or clear the kill-switch** popup opens with the live status.
2. Choose a **Mode**: `lockdown_all` (deny), `disable_enforce` (observe without blocking) or `emergency_bypass` (allow held calls).
3. Set the **Scope** (`global`, or narrow it to `agent:`, `resource:` or `tool:`), a **Reason** (an incident reference), and the **TTL ms** after which a grant auto-reverts (except `lockdown_all`, which persists until cleared).
4. Click **Engage** to write the signed grant, or **Clear** to lift it. Engaging and clearing are gated on the `BreakGlassOperator` capability and are themselves recorded in the meta-audit.
