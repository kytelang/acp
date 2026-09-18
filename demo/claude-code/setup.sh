#!/usr/bin/env bash
# Register this Claude Code as a verified ACP agent, then wire .mcp.json to run the proxy under that
# identity. After this, the proxy proves the agent's identity (fail-closed) and per-agent policy
# rules apply. Re-run to re-register (a fresh token).
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
CLI="$ROOT/target/release/acp-cli"; PROXY="$ROOT/target/release/acp-proxy"; MOCK="$ROOT/target/release/mock-mcp-server"
REG="$(pwd)/registry.json"

[ -x "$CLI" ] || { echo "build first: cargo build --release -p acp-proxy -p acp-cli"; exit 1; }
rm -f "$REG"
APPOUT=$("$CLI" app register "$REG" claude-code-demo you)
APP=$(python3 -c "import json;print(list(json.load(open('$REG'))['apps'].values())[0]['id'])")
AGOUT=$("$CLI" agent register "$REG" "$APP" coding-assistant)
AID=$(echo "$AGOUT" | grep -oE 'agt-[a-f0-9]+' | head -1)
TOK=$(echo "$AGOUT" | grep TOKEN | awk '{print $NF}')
echo "registered agent 'coding-assistant' ($AID) in app 'claude-code-demo' ($APP)"

python3 - "$PROXY" "$(pwd)/policy.yaml" "$(pwd)/evidence.db" "$(pwd)/signing.key" "$REG" "$AID" "$TOK" "$MOCK" <<'PY'
import json,sys
proxy,policy,ledger,key,reg,aid,tok,mock=sys.argv[1:9]
cfg={"mcpServers":{"acp-governed":{"command":proxy,"args":[
  "stdio","--policy",policy,"--ledger",ledger,"--key",key,
  "--registry",reg,"--agent-id",aid,"--agent-token",tok,"--",mock]}}}
open(".mcp.json","w").write(json.dumps(cfg,indent=2)+"\n")
print("wrote .mcp.json with the verified agent identity")
PY
echo "done. Now: start a NEW Claude Code session in this dir ('claude'), approve the server, and use the tools."
echo "The proxy will print 'verified identity app=claude-code-demo agent=coding-assistant' and enforce per-agent policy."
