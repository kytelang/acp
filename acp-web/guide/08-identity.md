# 8. Identity, registry and access

Authorization is only as good as the identity behind it. Varman verifies two identities: the
**agent** making the call, and the **human principal** it acts for. Neither is taken from the agent's
own claims.

## Agent identity: the registry

`acp-registry` is the source of truth for applications and agents. Register an app, then register an
agent under it, which issues a one-time plaintext token; the registry stores only its SHA-256.

```sh
acp app register registry.json acme-app you       # register an application
acp agent register registry.json <app-id> coding-assistant
# prints the agent id (agt-...) and a one-time TOKEN, shown once
```

Register agents from the console (Teams and Agents pages) or the control-plane API; they are stored
in the control-plane database. At enforcement time the proxy verifies the agent against that database
by pointing `--registry-url` at the control plane (a local registry file via `--registry` is the
offline alternative). Verification is fail-closed: a wrong or revoked token yields no identity, and
the call is denied. Deactivating an agent in the console refuses it immediately, verified end to end.

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
