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
  --registry registry.json \
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
| `--policy <file>` | the policy to enforce (or a policy-store directory to watch and hot-reload) |
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
| `--oidc-jwks`, `--oidc-issuer`, `--oidc-audience` | resolve the human principal per request |

## Environment

- `ACP_LEDGER_KEK` / `ACP_LEDGER_KEK_FILE`: encrypt argument payloads at rest ([chapter 9](09-evidence.md)).
- `ACP_PKCS11_MODULE` (+ `ACP_PKCS11_SLOT`, `ACP_PKCS11_PIN`, `ACP_PKCS11_LABEL`): sign evidence on
  an HSM instead of the file key ([chapter 9](09-evidence.md)).
- `ACP_LOG` / `RUST_LOG` and `ACP_LOG_FORMAT=json`: logging level and format ([chapter 14](14-operations.md)).

The proxy's operational logs go to stderr; stdout carries only the JSON-RPC protocol, so structured
logging never corrupts the stream.
