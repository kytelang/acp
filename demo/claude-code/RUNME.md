# RUNME: test ACP with real Claude Code

A one-page, repeatable test that drives real Claude Code through ACP and shows the governed
decisions in the tamper-evident ledger. Run it in your own terminal (not nested inside another
Claude Code session, which cannot wire the MCP server cleanly).

## What this proves

Real Claude Code -> ACP -> tool server, governed live: verified agent identity, resource/operation
policy, allow/deny/step-up, obligations, tool-integrity, kill-switch, and evidence. It does NOT
prove real-Entra identity (uses the registry agent token) or HA/scale.

## Prereqs (from the repo root)

```sh
cargo build --release -p acp-proxy -p acp-cli
cargo build --release --bin mock-mcp-server
./demo/claude-code/setup.sh    # (re)generates registry.json + signing.key + agent token in .mcp.json
```

## The policy (policy.yaml, model-v2)

- `delete_all`  -> DENY (destructive; matched by tool name)
- `resource: payments` (e.g. `charge_card`) -> STEP-UP, approver `finance`
- `write_note` -> ALLOW with a `redact` obligation on fields `secret`, `ssn`

## Test A - MCP tool-call governance

```sh
cd demo/claude-code            # .mcp.json here points Claude Code at acp-proxy
claude                         # a NEW session; a running one cannot reload MCP config
```
Then ask Claude Code:
> Call the echo tool with message "hi". Then call delete_all. Then call charge_card with amount_cents 50000.

Expected: `echo` succeeds, `delete_all` comes back blocked-by-policy, `charge_card` comes back
approval-required (step-up). Read the governed decisions:
```sh
cd ../..                       # repo root
cargo run -q -p acp-cli -- verify  demo/claude-code/evidence.db   # integrity
cargo run -q -p acp-cli -- export  demo/claude-code/evidence.db   # the decision records
cargo run -q -p acp-cli -- grc-report demo/claude-code/evidence.db  # framework view
```

## Test B - LLM gateway (Claude Code's own model traffic)

```sh
# terminal 1: gateway in front of Anthropic, holding the upstream key
./target/release/acp-gateway --policy demo/claude-code/gw-policy.yaml \
  --upstream https://api.anthropic.com --upstream-key env:ANTHROPIC_API_KEY \
  --ledger /tmp/gw.db --addr 127.0.0.1:8799

# terminal 2: run Claude Code through the gateway
ANTHROPIC_BASE_URL=http://127.0.0.1:8799 claude
```
Every completion Claude Code makes now flows through ACP (governed, budgeted, content-scanned,
credential-brokered, logged). `curl 127.0.0.1:8799/metrics` shows the counters;
`acp grc-report /tmp/gw.db` shows the evidence. Costs real tokens.

## Reset between runs

```sh
rm -f demo/claude-code/evidence.db*   # fresh ledger; the proxy recreates it
```
