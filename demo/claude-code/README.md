# Testing ACP with Claude Code

ACP is a transparent MCP proxy; Claude Code is an MCP client. Point Claude Code at
`acp-proxy stdio` in front of a tool server, and every tool call Claude Code makes is gated by
policy and written to the tamper-evident ledger. This demo governs a small mock tool server; swap
the last argument in `.mcp.json` for any real MCP server command to govern that instead.

## What the policy does (policy.yaml)

- `delete_all`  -> DENIED (a destructive tool).
- `charge_card` with amount_cents > 50000 -> STEP-UP (held for human approval).
- everything else -> allowed and forwarded, all recorded.

## Run it

1. Build the binaries: `cargo build --release -p acp-proxy -p acp-cli` (from the repo root).
2. Start a NEW Claude Code session in THIS directory (a running session cannot reload MCP config):
   ```sh
   cd /Users/kamlesh/kytelang/acp/demo/claude-code
   claude
   ```
   Claude Code reads `.mcp.json`, spawns `acp-proxy` (which spawns the tool server), and asks you
   to approve the `acp-governed` MCP server. The tools appear as `mcp__acp-governed__echo`, etc.
3. Ask Claude to use them, for example:
   - "use the echo tool to say hello"  -> allowed, forwarded, recorded.
   - "call delete_all"                  -> ACP returns a policy-blocked error; the call never reaches the server.
   - "charge the card 90000 cents"      -> ACP returns "approval required (step-up)".
4. Inspect the evidence (from the repo root):
   ```sh
   acp-cli verify demo/claude-code/evidence.db          # tamper-evident log verifies
   acp-cli export demo/claude-code/evidence.db | jq .   # every gated call, with its verdict
   ```

## Governing a REAL tool server

Replace the tool-server command at the end of `.mcp.json`'s `args` (after `--`) with any MCP
server, e.g. the filesystem server:
```
"--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/some/dir"
```
Now Claude Code's filesystem tool calls are governed by ACP, held for approval, and recorded.

## Live governance console (optional)

Run `acp-server --policy policy.yaml --ledger evidence.db --addr 127.0.0.1:8787` and then the Kyte
console (`cd ../../acp-console && kyte build && ./build/debug/bin/acp-console`) to watch the
decisions stream live at http://127.0.0.1:8080 while Claude Code drives the tools.
