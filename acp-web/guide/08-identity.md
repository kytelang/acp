# 8. Identity, registry and access

Authorization is only as good as the identity behind it. Varman verifies two identities: the
**agent** making the call, and the **human principal** it acts for. Neither is taken from the agent's
own claims.

## Agent identity: the registry

The control plane is the source of truth for applications and agents, stored in the control-plane
database. Register them from the console (Teams and Agents pages) or the control-plane API; each agent
registration issues a one-time token and the store keeps only its SHA-256.

```sh
# from the console: Teams -> Register team, then Agents -> Register agent
# or the API:
curl -X POST http://<host>:8787/apps   -d '{"name":"acme-app","owner":"you"}'
curl -X POST http://<host>:8787/agents -d '{"app_id":"<app-id>","name":"coding-assistant"}'
# the agent response carries a one-time token, shown once
```

Register agents from the console (Teams and Agents pages) or the control-plane API; they are stored
in the control-plane database. At enforcement time the proxy verifies the agent against that database
by pointing `--registry-url` at the control plane (a local registry file via `--registry` is the
offline alternative). Verification is fail-closed: a wrong or revoked token yields no identity, and
the call is denied. Deactivating an agent in the console refuses it immediately, verified end to end.

### How to register a team (step by step)

1. Open the console and select **Teams** in the sidebar.
2. Click **+ Register team** (top right of the Teams and agents card). The **Register a team / application** popup opens.
3. Fill in **Name** (required, for example `acme-app`) and, optionally, **Owner**.
4. Click **Register**. The team appears in the list with its generated id (`app-...`), which you will need when registering agents.

### How to register an agent (step by step)

1. Select **Agents** in the sidebar.
2. Click **+ Register agent**. The **Register an agent** popup opens.
3. Fill in **App ID** (required, the `app-...` id from the team you just registered) and **Name** (required, for example `coding-assistant`).
4. Click **Register**. The result line shows a **one-time token**. Copy it now: it is shown once and only its SHA-256 is stored. The agent presents this token at enforcement time, and the proxy verifies it against the control-plane database.

To revoke an agent, use its **Deactivate** action on the Agents page; enforcement refuses it immediately.

## Human identity: OIDC and Entra

The human principal is established from a verified OIDC/JWT bearer token. Varman verifies EdDSA and
real RS256 signatures, resolves the key by `kid` from a JWKS it fetches and refreshes, and checks the
issuer, audience and expiry. Configure it on the PEP or the control plane:

```sh
# Microsoft Entra
--entra-tenant <tenant> --entra-audience <audience>
# any OIDC provider
--oidc-jwks <url> --oidc-issuer <iss> --oidc-audience <aud>
```

A request without a valid token degrades to the `unattributed` principal, which your policy can
treat as it wishes (for example, denying `unattributed` access to secrets or frontier models). For
local development, `--dev-auth` on the control plane issues mock tokens, gated behind an explicit
environment flag so it cannot be switched on by accident.

## Delegation

A `Delegation` binds an agent to a human for a bounded time, so the ledger records not just "agent X
did this" but "agent X, acting for human Y, did this". This is what lets you answer "who authorised
this action" with a name, not just a service identity.

## Role-based access control

The control plane enforces RBAC with capabilities mapped from OIDC app roles:

| Capability | Who needs it |
| --- | --- |
| `PolicyAdmin` (`EditPolicy`) | deploy a new policy version |
| `Approver` (`Approve`) | resolve a step-up hold |
| `BreakGlassOperator` (`BreakGlass`) | engage or clear the kill-switch |
| `Auditor` (`Export`, `SeeArgs`) | export evidence and read argument payloads |
| `Registrar` | register apps and agents |

**Separation of duty** is enforced across these: a policy admin cannot trip the kill-switch, and the
reverse. With no auth flags the control plane runs RBAC-off for local use; if you request auth and
the JWKS fails to load, the server refuses to start rather than run unprotected (fail-closed).

## mutual TLS between components

Components can require mutual TLS so only enrolled parties reach the control API:

```sh
acp-server --tls-ca ca.pem --tls-cert server.pem --tls-key server.key ...
```

The server then presents its certificate and requires a client certificate signed by the ACP CA; a
client with no certificate or a rogue one fails the handshake.
