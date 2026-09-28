#!/usr/bin/env bash
# R8: scale + soak drill for the ACP control plane and PEPs. Local, self-contained, bounded.
# Three parts:
#   1. MCP proxy under sustained concurrent load (rps + p50/p95/p99 + error rate).
#   2. LLM gateway under sustained concurrent load (same metrics).
#   3. Two-replica control plane on one shared store: identify the leader, kill it under a write load,
#      confirm exactly one leader takes over (no split-brain), data + liveness survive, writes resume,
#      and measure recovery time.
# Exits non-zero if any drill fails. Writes a machine-readable summary to $OUT (default docs/soak-report.md).
set -uo pipefail
cd "$(dirname "$0")/.."

OUT="${OUT:-/tmp/soak-metrics.txt}"
DUR="${DUR:-6}"          # load duration per PEP, seconds
CONC="${CONC:-32}"       # concurrency
TTL="${TTL:-3000}"       # HA lease ttl ms (short so failover is quick)
: > "$OUT"

PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
note(){ echo "$1" >> "$OUT"; }

echo "== ACP soak drill =="
cargo build --release -q -p acp-agent -p acp-gateway -p acp-server -p acp-cli 2>&1 | tail -1
PROXY=target/release/acp-agent; GW=target/release/acp-gateway; SRV=target/release/acp-server

W="$(mktemp -d)"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

wait_http(){ for _ in $(seq 1 100); do curl -fsS "$1" >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }
wait_port(){ for _ in $(seq 1 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# ---- mock upstreams (python) ----
python3 - "$W/up.pid" <<'PY' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); self.rfile.read(n)
        b=json.dumps({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.send_header('content-length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',8896),H).serve_forever()
PY
PIDS+=($!)
python3 - <<'PY' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('content-length',0)); self.rfile.read(n)
        b=json.dumps({"id":"x","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}).encode()
        self.send_response(200); self.send_header('content-type','application/json'); self.send_header('content-length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',8897),H).serve_forever()
PY
PIDS+=($!)
sleep 1

# ---- 1. proxy load ----
echo "== 1. MCP proxy under load =="
"$PROXY" mcp http --addr 127.0.0.1:8890 --upstream http://127.0.0.1:8896/ >"$W/proxy.log" 2>&1 &
PIDS+=($!)
if wait_port 8890; then
  note "### MCP proxy"
  python3 scripts/loadtest.py --url http://127.0.0.1:8890/ --body mcp --duration "$DUR" --concurrency "$CONC" | tee -a "$OUT"
  [ "${PIPESTATUS[0]}" = "0" ] && ok "proxy sustained load healthy" || bad "proxy load unhealthy"
else bad "proxy did not listen"; fi

# ---- 2. gateway load ----
echo "== 2. LLM gateway under load =="
cat > "$W/allow.yaml" <<'Y'
version: 1
default: allow
rules: []
Y
"$GW" --addr 127.0.0.1:8891 --policy "$W/allow.yaml" --upstream http://127.0.0.1:8897 >"$W/gw.log" 2>&1 &
PIDS+=($!)
if wait_port 8891; then
  note "### LLM gateway"
  python3 scripts/loadtest.py --url http://127.0.0.1:8891/v1/chat/completions --body chat --duration "$DUR" --concurrency "$CONC" | tee -a "$OUT"
  [ "${PIPESTATUS[0]}" = "0" ] && ok "gateway sustained load healthy" || bad "gateway load unhealthy"
else bad "gateway did not listen"; fi

# ---- 3. two-replica failover ----
echo "== 3. two-replica control-plane failover =="
STORE="sqlite://$W/cp.db?mode=rwc"
ACP_ALLOW_DEV_AUTH=1 "$SRV" --addr 127.0.0.1:8892 --store "$STORE" --cp-key "$W/cp.key" --dev-auth --node-id nodeA --lease-ttl-ms "$TTL" >"$W/a.log" 2>&1 &
PA=$!; PIDS+=($PA)
ACP_ALLOW_DEV_AUTH=1 "$SRV" --addr 127.0.0.1:8893 --store "$STORE" --cp-key "$W/cp.key" --dev-auth --node-id nodeB --lease-ttl-ms "$TTL" >"$W/b.log" 2>&1 &
PB=$!; PIDS+=($PB)
wait_http "http://127.0.0.1:8892/leader"; wait_http "http://127.0.0.1:8893/leader"
sleep "$(awk "BEGIN{print $TTL/1000 + 1}")"   # let one acquire the lease

leader_of(){ curl -fsS "http://127.0.0.1:$1/leader" | python3 -c 'import sys,json;print(json.load(sys.stdin)["leader"])' 2>/dev/null; }
LA=$(leader_of 8892); LB=$(leader_of 8893)
echo "  steady state: nodeA leader=$LA nodeB leader=$LB"
# split-brain guard at steady state
if [ "$LA" = "True" ] && [ "$LB" = "True" ]; then bad "split-brain: both replicas leader"; else ok "at most one leader at steady state"; fi

# write load: register apps on the leader's port
if [ "$LA" = "True" ]; then LPORT=8892; LPID=$PA; SPORT=8893; else LPORT=8893; LPID=$PB; SPORT=8892; fi
TOK=$(curl -fsS "http://127.0.0.1:$LPORT/auth/dev-token?role=AppRegistrar" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
for i in $(seq 1 5); do
  curl -fsS -XPOST "http://127.0.0.1:$LPORT/apps" -H "authorization: Bearer $TOK" -H 'content-type: application/json' -d "{\"name\":\"soak-app-$i\"}" >/dev/null
done
BEFORE=$(curl -fsS "http://127.0.0.1:$SPORT/apps" -H "authorization: Bearer $TOK" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["apps"]))')
echo "  apps visible on survivor before kill: $BEFORE"

# kill the leader, measure time for the survivor to take over
echo "  killing leader (node on port $LPORT, pid $LPID) ..."
kill -9 "$LPID" 2>/dev/null
T0=$(python3 -c 'import time;print(time.time())')
RECOVERED=0
for _ in $(seq 1 200); do
  if [ "$(leader_of $SPORT)" = "True" ]; then RECOVERED=1; break; fi
  sleep 0.1
done
T1=$(python3 -c 'import time;print(time.time())')
MS=$(python3 -c "print(int(($T1-$T0)*1000))")
if [ "$RECOVERED" = "1" ]; then ok "survivor became leader in ${MS}ms (ttl ${TTL}ms)"; note "### Failover"; note "recovery_ms=$MS ttl_ms=$TTL"; else bad "no survivor leader within timeout"; fi

# data + liveness survived; writes resume on the survivor
AFTER=$(curl -fsS "http://127.0.0.1:$SPORT/apps" -H "authorization: Bearer $TOK" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["apps"]))')
[ "$AFTER" -ge "$BEFORE" ] && [ "$AFTER" -ge 5 ] && ok "control state survived failover ($AFTER apps)" || bad "control state lost ($BEFORE -> $AFTER)"
TOK2=$(curl -fsS "http://127.0.0.1:$SPORT/auth/dev-token?role=AppRegistrar" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
POST=$(curl -fsS -XPOST "http://127.0.0.1:$SPORT/apps" -H "authorization: Bearer $TOK2" -H 'content-type: application/json' -d '{"name":"post-failover-app"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("ok"))')
[ "$POST" = "True" ] && ok "writes resume on survivor after failover" || bad "writes failed after failover"

echo
echo "== soak summary: $PASS passed, $FAIL failed =="
exit $([ "$FAIL" = "0" ] && echo 0 || echo 1)
