# 4. The LLM gateway

`acp-gateway` governs **direct model API calls**. It is a reverse proxy in front of a model provider
(OpenAI, Anthropic, Bedrock, Gemini and the like) that applies the same policy engine, obligations
and evidence as the tool-call path, and, crucially, **holds the upstream API key itself**. Callers
send requests to the gateway without a key; the gateway authorises, then adds the key and forwards.
This is credential brokering: even a leaked client cannot reach the model off-ACP.

## Running it

```sh
acp-gateway \
  --addr 0.0.0.0:8799 \
  --policy policy.yaml \
  --upstream https://api.anthropic.com \
  --content-firewall
```

Point your application's model base-URL at the gateway. It streams responses through (server-sent
events pass straight back), applies a load-shed semaphore, and records every decision before
forwarding.

## Model classes

The gateway classifies each request's model into a class (`frontier`, `standard`, `embeddings`,
`image-gen`, ...) using a name taxonomy, and the policy governs by class. So a rule like "the
unattributed principal may not call a frontier model" holds across providers without naming every
model:

```yaml
  - id: no-anon-frontier
    when: { resource: frontier, principal: unattributed }
    verdict: deny
```

## Budgets

Token and cost budgets are an obligation on an allow. Under a single instance they are in-process;
across replicas, point the gateway at Postgres so replicas share one budget and a failover keeps the
limit correct:

```sh
acp-gateway --addr 0.0.0.0:8799 --policy policy.yaml \
  --upstream https://api.anthropic.com \
  --budget-pg "host=pg user=acp password=... dbname=acp" \
  --content-firewall
```

## Content firewall on the prompt path

`--content-firewall` scans the prompt, and `--content-ml <model.json>` adds the trained injection
classifier. Detection is enforced on both the gateway (prompt) and the proxy (tool arguments); see
[chapter 10](10-content-firewall.md). If a content scan is configured and errors, the gateway blocks
(fail-closed), because forwarding an unscanned prompt when scanning was required would be unsafe.

## Identity

Add `--entra-tenant` and `--entra-audience`
to resolve the human principal per request from a bearer token; requests without a valid token
degrade to `unattributed`, which your policy can then treat as it likes. See [chapter 8](08-identity.md).

## Flags

| Flag | Effect |
| --- | --- |
| `--addr <host:port>` | listen address |
| `--policy <file>` | the policy to enforce |
| `--upstream <base-url>` | the model provider to broker to |
| `--budget-pg <dsn>` | shared token/cost budgets via Postgres |
| `--content-firewall` | enable the signature content firewall on prompts |
| `--content-ml <model.json>` | also load the trained ML classifier |
| `--entra-tenant`, `--entra-audience` | Entra identity for the human principal |

Evidence at-rest encryption and HSM signing are configured by the same environment variables as the
proxy ([chapter 9](09-evidence.md)).
