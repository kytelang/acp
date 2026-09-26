# 3. The MCP proxy

`acp-proxy` governs an agent's **tool calls over MCP** (the Model Context Protocol). It is a
transparent interception proxy: it relays the JSON-RPC stream between the agent and the MCP server
verbatim, parsing out only `tools/call` frames, and it intervenes only to deny, hold for approval,
or rewrite arguments. Invalid or unrelated frames are relayed untouched and are never a point of
failure.

## Two transports

### stdio

The common case: the proxy launches the MCP server as a child process and sits on its stdio.

```sh
acp-proxy stdio \
  --policy policy.yaml \
  --ledger evidence.db \
  --key signing.key \
  --registry-url http://<control-plane-host>:8787 \
  --agent-id agt-abc123 \
  --agent-token <token> \
  -- your-mcp-server --its --args
```

Everything after `--` is the command to launch. The proxy verifies the agent identity against the
registry, then governs every `tools/call` the agent makes to that server.

### HTTP

For a streamable-HTTP MCP server, run the proxy as a reverse proxy:

```sh
acp-proxy http --addr 127.0.0.1:9000 --upstream http://localhost:8080 \
  --policy policy.yaml --ledger evidence.db --key signing.key
```

The HTTP transport adds a concurrency cap: a burst beyond the limit is shed with a 503 and a
`Retry-after`, so the proxy cannot be exhausted, and it can stamp an enforcement attestation header
for the [guard](06-guard.md) to check.

## The enforcement pipeline

For each tool call the proxy runs, in order:

1. **Identity.** Resolve the verified agent (and human principal, if OIDC is configured).
2. **Policy.** Build the request context (subject, resource, operation, args, derived class flags)
   and evaluate the signed policy. Fail-closed on any error.
3. **Break-glass.** Apply any active kill-switch grant, which can override an allow to a deny.
4. **Content firewall.** If enabled, scan the tool arguments for injection, PII and secrets.
5. **Trajectory and data boundary.** If enabled, check the action against the session's history and
   the destination.
6. **Obligations.** Apply confirm (to step-up), rate-limit (to deny when exhausted), and redact
   (rewrite the frame).
7. **Record, then forward.** Write the decision to the ledger **before** forwarding, and fail closed
   if the evidence write fails, so nothing happens without a record.
8. **Response screening.** Screen the tool result for indirect injection in returned content, and
   check tool-integrity pins for a rug-pull.

## Flags

| Flag | Effect |
| --- | --- |
| `--policy <file>` | the policy file to enforce |
| `--policy-dir <dir>` | a signed policy-store directory to watch and hot-reload |
| `--ledger <db>` | the evidence ledger to append to |
| `--key <file>` | the Ed25519 signing key (generated 0600 if absent; see below for HSM) |
| `--registry <file>` | verify the agent against a local registry file |
| `--registry-url <server>` | verify the agent against the control plane's database (no registry file); preferred once agents are registered from the console |
| `--agent-id`, `--agent-token` | the calling agent's identity and one-time token |
| `--trajectory <policy.yaml>` | enable sequence governance ([chapter 11](11-containment.md)) |
| `--data-boundary <policy.yaml>` | enable destination-aware DLP ([chapter 11](11-containment.md)) |
| `--content-firewall` | enable the signature content firewall on tool arguments |
| `--content-ml <model.json>` | also load the trained ML injection classifier |
| `--tool-pins <file>` | enable tool-integrity pinning (rug-pull detection) |
| `--pin-pg <dsn>` | share tool-integrity pins across replicas via Postgres |
| `--enforcement-key <hex>` | stamp the enforcement attestation the guard verifies |
| `--entra-tenant`, `--entra-audience` | resolve the human principal per request via Microsoft Entra |

## Environment

- `ACP_LEDGER_KEK` / `ACP_LEDGER_KEK_FILE`: encrypt argument payloads at rest ([chapter 9](09-evidence.md)).
- `ACP_PKCS11_MODULE` (+ `ACP_PKCS11_SLOT`, `ACP_PKCS11_PIN`, `ACP_PKCS11_LABEL`): sign evidence on
  an HSM instead of the file key ([chapter 9](09-evidence.md)).
- `ACP_LOG` / `RUST_LOG` and `ACP_LOG_FORMAT=json`: logging level and format ([chapter 14](14-operations.md)).

The proxy's operational logs go to stderr; stdout carries only the JSON-RPC protocol, so structured
logging never corrupts the stream.

## Running modes and their safety trade-offs

Beyond the flags above, three modes change how strictly the proxy enforces. Two of them deliberately
weaken the default guarantees, so use them knowingly.

| Flag | Effect | Safety impact |
| --- | --- | --- |
| `--shadow` | evaluate and record every decision, but never block; the call is always forwarded | observe-only. Nothing is enforced. Use to gather real traffic before you enforce (feeds `acp learn` and `acp posture`), never as a steady state |
| `--fail-open` | on an evidence-write failure, forward the call ungoverned instead of failing closed | **weakens the core guarantee.** By default the proxy fails **closed**: if it cannot record a decision, it does not forward. `--fail-open` drops that, so a ledger outage becomes an ungoverned window. The proxy warns loudly at startup; use only for controlled testing |
| `--tool-hash <hex>` | verify the tool-server binary's fingerprint before launching it, and refuse to start if it does not match | strengthens supply-chain safety: a swapped tool binary is caught at launch |

Two more flags wire the proxy into fleet monitoring: `--report-url <control-plane>` makes it post a
heartbeat and non-allow events to the control plane (lighting up the console liveness and violation
views), and `--report-token <token>` presents the shared token those routes require (see
[chapter 14](14-operations.md)). `--otel <endpoint>` streams OTLP traces to an OpenTelemetry collector.

A proxy started with no `--policy` and no `--policy-dir` runs in transparent mode: it forwards every
`tools/call` ungoverned and warns loudly that nothing is being enforced, so an accidental ungoverned run
is visible in the logs rather than silent.
