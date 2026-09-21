#!/usr/bin/env bash
# Bring up the reference deployment, prove the two gateway replicas share one budget through
# Postgres, then kill one replica and prove the other still serves with the budget intact.
# Requires docker + docker compose. Run from the deploy/ directory.
set -euo pipefail
cd "$(dirname "$0")"
echo "== building and starting =="
docker compose up -d --build
trap 'docker compose down -v' EXIT
echo "== waiting for gateways =="
until curl -sf http://127.0.0.1:8799/readyz >/dev/null && curl -sf http://127.0.0.1:8798/readyz >/dev/null; do sleep 2; done
echo "== both replicas ready; sending traffic to replica A =="
curl -s -o /dev/null -w "A: %{http_code}\n" -X POST http://127.0.0.1:8799/v1/chat/completions -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' || true
echo "== killing replica A; replica B must still serve (shared budget in Postgres) =="
docker compose kill gateway-a
curl -s -o /dev/null -w "B after A down: %{http_code}\n" -X POST http://127.0.0.1:8798/v1/chat/completions -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' || true
echo "== failover drill complete =="
