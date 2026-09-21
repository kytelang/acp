#!/usr/bin/env bash
# End-to-end acceptance for the ACP governance vertical:
#   Agent -> Action -> Policy -> Decision -> Human approval -> Execution -> Evidence -> Verification
# plus fail-closed checks at the seams. Run from the repo root: bash demo/vertical/run.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI="$ROOT/target/debug/acp-cli"
PROXY="$ROOT/target/debug/acp-proxy"
MOCK="$ROOT/target/debug/mock-mcp-server"
W=/tmp/acp-vertical; rm -rf "$W"; mkdir -p "$W"
REG="$W/registry.json"; LEDGER="$W/evidence.db"; KEY="$W/signing.key"; APPROV="$W/evidence.db.approvals"
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

cat > "$W/policy.yaml" <<'YAML'
version: 1
default: allow
rules:
  - id: no-destructive-deletes
    when: { tool: delete_all }
    verdict: deny
    reason: destructive bulk delete is never allowed
  - id: payments-need-approval
    when: { resource: payments }
    verdict: step_up
    approvers: [finance]
YAML

# 1. AGENT IDENTITY: register app + agent (verified, un-spoofable token)
"$CLI" app register "$REG" acme-app you >/dev/null 2>&1
APPID=$(python3 -c "import json;print(list(json.load(open('$REG'))['apps'].values())[0]['id'])")
AGOUT=$("$CLI" agent register "$REG" "$APPID" coding-assistant 2>&1)
AID=$(echo "$AGOUT" | grep -oE 'agt-[a-f0-9]+' | head -1)
TOK=$(echo "$AGOUT" | grep -i TOKEN | awk '{print $NF}')
[ -n "$AID" ] && [ -n "$TOK" ] && ok "Agent identity: registered $AID with a verified token" || no "agent registration"

runproxy(){ # frames on stdin -> proxy stdout
  "$PROXY" stdio --policy "$W/policy.yaml" --ledger "$LEDGER" --key "$KEY" \
    --registry "$REG" --agent-id "$AID" --agent-token "$TOK" -- "$MOCK" 2>>"$W/proxy.err"
}
init(){ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'; printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'; }

# 2. ACTION -> POLICY -> DECISION (deny) + 3. step-up (first issue) in one session
OUT1=$({ init; \
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_all","arguments":{}}}'; \
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"charge_card","arguments":{"amount_cents":50000}}}'; \
  sleep 1; } | runproxy)
grep -q 'verified identity' "$W/proxy.err" && ok "Identity verified in the enforcement path" || no "identity not verified in path"
echo "$OUT1" | python3 -c "import sys,json
deny=held=False; approval_id=None
for l in sys.stdin:
  l=l.strip()
  if not l: continue
  try: m=json.loads(l)
  except: continue
  if m.get('id')==2 and m.get('result',{}).get('structuredContent',{}).get('rule')=='no-destructive-deletes': deny=True
  if m.get('id')==3 and m.get('error',{}).get('code')==-32001: held=True; approval_id=m['error']['data']['approvalId']
open('$W/aid','w').write(approval_id or '')
sys.exit(0 if (deny and held) else 1)" && ok "Decision: delete_all DENIED; charge_card STEP-UP (approval required)" || no "deny/step-up decision"
APPROVAL_ID=$(cat "$W/aid" 2>/dev/null)

# 4. HUMAN APPROVAL (separate operator action)
"$CLI" approve "$APPROV" "$APPROVAL_ID" finance-officer >/dev/null 2>&1 && ok "Human approval recorded for $APPROVAL_ID" || no "human approval"

# 5. EXECUTION: re-issue the identical call -> consumed -> forwarded
OUT2=$({ init; printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"charge_card","arguments":{"amount_cents":50000}}}'; sleep 1; } | runproxy)
echo "$OUT2" | python3 -c "import sys,json
ok=False
for l in sys.stdin:
  l=l.strip()
  if not l: continue
  try: m=json.loads(l)
  except: continue
  if m.get('id')==4:
    r=m.get('result',{})
    # forwarded (executed) = a normal result, not held(-32001) and not isError
    if 'error' not in m and not r.get('isError') and not r.get('structuredContent',{}).get('blocked'): ok=True
sys.exit(0 if ok else 1)" && ok "Execution: approved charge_card was forwarded and executed" || no "execution after approval"

# 6. EVIDENCE: every decision recorded
N=$("$CLI" export "$LEDGER" 2>/dev/null | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('records',[])))")
[ "${N:-0}" -ge 3 ] && ok "Evidence: $N records in the tamper-evident ledger" || no "evidence records ($N)"

# 7. INDEPENDENT VERIFICATION (ledger + standalone pack, pubkey-only)
"$CLI" verify "$LEDGER" >/dev/null 2>&1 && ok "Independent verification: ledger verifies" || no "ledger verify"
"$CLI" export "$LEDGER" > "$W/pack.json" 2>/dev/null
"$CLI" verify-pack "$W/pack.json" >/dev/null 2>&1 && ok "Independent verification: standalone pack verifies (pubkey only)" || no "pack verify"

# 8. FAIL-CLOSED: tamper the ledger -> verification must FAIL. The ledger is append-only (SQLite
#    triggers block UPDATE/DELETE); we simulate an attacker with raw DB access who removes those
#    protections first, then edits a record. Verification must still catch it via the Merkle leaves.
sqlite3 "$LEDGER" "DROP TRIGGER records_no_update; DROP TRIGGER records_no_delete; DROP TRIGGER heads_no_update;" 2>/dev/null
sqlite3 "$LEDGER" "UPDATE records SET canonical = randomblob(length(canonical)) WHERE seq=(SELECT MIN(seq) FROM records);" 2>/dev/null
if "$CLI" verify "$LEDGER" >/dev/null 2>&1; then no "tampered ledger still verified (NOT fail-closed!)"; else ok "Fail-closed: a tampered ledger FAILS independent verification"; fi

# 9. FAIL-CLOSED: invalid agent token -> not verified as the agent
BADOUT=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' | \
  "$PROXY" stdio --policy "$W/policy.yaml" --ledger "$W/l2.db" --key "$W/k2" --registry "$REG" --agent-id "$AID" --agent-token deadbeef -- "$MOCK" 2>&1)
echo "$BADOUT" | grep -qiE 'invalid|unverified|token|refus|principal=unattributed' && ok "Fail-closed: an invalid agent token is not accepted as the agent" || no "invalid token handling"

echo ""; echo "VERTICAL ACCEPTANCE: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
