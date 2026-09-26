# 6. The enforcement guard

A proxy only governs calls that go through it. The obvious bypass is to call the tool server
directly. `acp-guard` closes that: it is a small reverse proxy sidecar you put in front of a tool
server (bound to loopback) that **forwards only requests carrying a valid ACP enforcement
attestation**, and records every refused, un-proxied attempt to the ledger as bypass evidence.

## How the attestation works

When you run the [proxy](03-proxy.md) with `--enforcement-key <hex>`, it stamps each forwarded
request with an `x-acp-enforcement` header: a short token of the form `<issued-ms>.<session>.<sig>`,
signed with the proxy's Ed25519 key and bound to a freshness window. The guard holds the matching
public key and verifies the token: present, fresh, and correctly signed. Anything else is refused,
fail-closed.

```
agent → acp-proxy (stamps x-acp-enforcement) → acp-guard (verifies) → tool server (loopback only)
                                                     │
                                          refused attempts → ledger
```

Because the tool server binds to loopback and only the guard can reach it, and the guard only admits
attested requests, a caller cannot reach the tool server without going through ACP.

## Running it

```sh
acp-guard \
  --listen 0.0.0.0:8801 \
  --upstream http://127.0.0.1:9090 \
  --pubkey <hex> \
  --ledger evidence.db \
  --ledger-key <hex> \
  --max-age-ms 30000
```

The guard exposes `/healthz`, `/readyz` and `/metrics`, so it drops into a Kubernetes deployment
cleanly. A missing, stale, or wrong-key attestation is refused with an error and logged; a valid one
is forwarded to the upstream.

## When to use it

Use the guard for any tool server that holds real power (a database, a payment API, an internal
service) and could otherwise be reached directly on the network. It turns "please route through the
proxy" into a structural guarantee, and it makes an attempted bypass visible in the same evidence
ledger as governed calls.

Pair it with the [coverage report and egress canary](12-grc.md), which measure whether anything is
still reachable off-ACP, and with [credential brokering in the gateway](04-gateway.md), which does
the same job for model calls.
