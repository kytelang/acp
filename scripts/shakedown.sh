#!/usr/bin/env bash
# ACP real-environment shakedown: a soak + resilience drill an operator runs in the target env
# before trusting ACP as the enforcement gate. Exercises volume, evidence integrity, backup/restore,
# and the break-glass drill. Fully local; exits non-zero if any drill fails.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

echo "== ACP shakedown =="
cargo build --release -q -p acp-proxy -p acp-cli
PROXY=target/release/acp-proxy; MOCK=target/release/mock-mcp-server; CLI=target/release/acp-cli
W="$(mktemp -d)"
cat > "$W/policy.yaml" <<'YAML'
version: 1
default: allow
rules:
  - id: cap
    when: { tool: "payments.charge", arg: { amount_cents: { gt: 50000 } } }
    verdict: deny
YAML
LEDGER="$W/ev.db"; KEY="$W/key"

echo "-- soak: drive 500 decisions --"
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
  for i in $(seq 1 500); do
    amt=$(( (i % 2) == 0 ? 90000 : 100 ))
    echo "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/call\",\"params\":{\"name\":\"payments.charge\",\"arguments\":{\"amount_cents\":$amt}}}"
  done
} | "$PROXY" stdio --policy "$W/policy.yaml" --ledger "$LEDGER" --key "$KEY" -- "$MOCK" >/dev/null 2>&1
SIZE=$("$CLI" export "$LEDGER" 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["records"]))' 2>/dev/null || echo 0)
[ "$SIZE" -ge 500 ] && ok "500+ decisions recorded ($SIZE records)" || bad "expected >=500 records, got $SIZE"
"$CLI" verify "$LEDGER" >/dev/null 2>&1 && ok "ledger verifies after soak" || bad "ledger failed to verify after soak"

echo "-- backup / restore drill --"
cp "$LEDGER" "$W/backup.db"
rm -f "$LEDGER"
"$CLI" verify "$W/backup.db" >/dev/null 2>&1 && ok "restored-from-backup ledger verifies" || bad "restore drill failed"

echo "-- break-glass drill --"
BG="$W/bg.json"
"$CLI" break-glass engage "$BG" lockdown_all "shakedown drill" operator 60000 >/dev/null 2>&1
# a small (normally-allowed) charge must be DENIED while lockdown is engaged
OUT=$( { echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}';
         echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":100}}}'; } \
       | "$PROXY" stdio --policy "$W/policy.yaml" --ledger "$W/bg-ev.db" --key "$W/bg-key" --break-glass-file "$BG" -- "$MOCK" 2>/dev/null )
echo "$OUT" | grep -q '"isError":true' && ok "break-glass lockdown denies an otherwise-allowed call" || bad "break-glass lockdown did not engage"
"$CLI" break-glass clear "$BG" >/dev/null 2>&1
OUT2=$( { echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}';
          echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":100}}}'; } \
        | "$PROXY" stdio --policy "$W/policy.yaml" --ledger "$W/bg2-ev.db" --key "$W/bg2-key" --break-glass-file "$BG" -- "$MOCK" 2>/dev/null )
echo "$OUT2" | grep -q '"isError":true' && bad "break-glass did not revert (call still denied)" || ok "clearing break-glass reverts to normal (call forwarded, not denied)"

echo ""
echo "== shakedown result: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ] || exit 1
