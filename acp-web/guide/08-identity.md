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
issuer, audience and expiry. Configure Entra on the PEP or the control plane; the generic OIDC flags
are accepted by the control plane:

```sh
# Microsoft Entra
--entra-tenant <tenant> --entra-audience <audience>
# any OIDC provider (control plane)
--oidc-jwks <url> --oidc-issuer <iss> --oidc-audience <aud>
```

A request without a valid token degrades to the `unattributed` principal, which your policy can
treat as it wishes (for example, denying `unattributed` access to secrets or frontier models). For
local development, `--dev-auth` on the control plane issues mock tokens, gated behind an explicit
environment flag so it cannot be switched on by accident.

### Preflighting a real tenant

Before cutting over to a real Entra tenant, verify the setup without starting the server:

```sh
# fetch and parse the tenant's JWKS (no token needed)
acp-server --entra-preflight --entra-tenant <tenant> --entra-audience <audience>
# with a real token: verify iss/aud/nbf/exp/signature and print the roles and effective capabilities
acp-server --entra-preflight --entra-tenant <tenant> --entra-audience <audience> --entra-test-token "<JWT>"
```

It exits 0 on success and 1 on any failure, naming the exact check that failed. The full cutover
procedure (JWKS preflight, token preflight, bring-up, first-window soak covering key rotation, clock
skew, token expiry and SCIM group sync, and rollback) is in `docs/entra-cutover-runbook.md`.

## Delegation

A `Delegation` binds an agent to a human for a bounded time, so the ledger records not just "agent X
did this" but "agent X, acting for human Y, did this". This is what lets you answer "who authorised
this action" with a name, not just a service identity.

## Role-based access control

The control plane enforces RBAC with capabilities mapped from OIDC app roles:

| Role | Capability | What it can do |
| --- | --- | --- |
| `PolicyAdmin` | `EditPolicy` | deploy a new policy version |
| `AppRegistrar` | `RegisterApp`, `RegisterAgent` | register applications and their agents; verify or deactivate an agent |
| `GrcAuthor` | `EditGrc` | create and advance governance records (assessments, conformity, risk, ...) |
| `FirewallAdmin` | `EditFirewall` | change the central content-firewall config and rules |
| `Approver` | `Approve` | resolve a step-up hold |
| `BreakGlassOperator` | `BreakGlass` | engage or clear the kill-switch |
| `Auditor` | `Export` | export the evidence and violation ledger |
| `SecurityOfficer` | `SeeArgs` | read the raw decision detail |

**Separation of duty** follows from this role-to-capability mapping: registration, policy authoring,
GRC authoring, firewall changes, approvals, export, argument visibility and break-glass are each a
distinct capability held by a distinct role. A `PolicyAdmin` alone cannot trip the kill-switch, onboard
an application, author a governance record or export evidence. Grant the roles to different people to
keep the duties separate.

**Enforced today at every mutating route**, each on its own capability: policy deploy (`EditPolicy`);
apps (`RegisterApp`); agents register/verify/deactivate (`RegisterAgent`); GRC create/assess/status/
assign/control (`EditGrc`); firewall config and rules (`EditFirewall`); approvals (`Approve`); the
kill-switch (`BreakGlass`); the meta-audit write (`EditPolicy`). `Export` gates the CSV export of the
violation ledger, and `SeeArgs` gates the raw decision-detail read. When auth is on, each call needs a
bearer token carrying the matching capability, so a token for the wrong role is rejected with 403.
With no auth flags the control plane runs RBAC-off for local use; if you request auth and the JWKS
fails to load, the server refuses to start rather than run unprotected (fail-closed).

**SCIM 2.0 provisioning.** An IdP (or an operator) can read the role catalogue and the user-to-role
directory over SCIM: `GET /scim/v2/Groups` lists the eight ACP roles as SCIM groups (each carrying the
capabilities it grants under `urn:acp:capabilities`), and `GET /scim/v2/Users` lists the provisioned
users with their group memberships. Both are gated on `Export` (a read-only administrative view). The
user directory comes from `--scim-users <file>` (a JSON array of `{id, email, groups}`), defaulting to
a demo directory (one operator per role) under the mocked-IdP dev setup.

## Multi-agent delegation chains

A `Delegation` binds one human to one agent. When an agent calls another agent on the human's behalf,
the whole chain (user to agent A to agent B) is authorised together, and rights can only narrow along
it: agent B can never exercise a scope that agent A did not hold. The full chain is recorded in the
ledger, so "who authorised this" is answerable across hops. `POST /delegation/verify` returns a chain's
effective scopes and whether it permits a given scope, and the proxy enforces it: a call carrying an
`_acp_delegation` chain that widens rights along a hop, or that does not permit the operation, is denied
at the PEP.

## Permission-aware retrieval

When an agent retrieves documents for RAG, ACP can enforce that it only receives documents the acting
human may see, so an assistant cannot become a way around document ACLs. `POST /retrieval/check` decides
per candidate document against the verified principal and their groups; an unattributed caller is
fail-closed. The proxy enforces this on the response path too: documents the acting principal may not
see are filtered out of a retrieval tool result before it reaches the model.

## Multi-tenancy

The control plane is multi-tenant. Tenant-scoped records (GRC, apps, agents, models, vendors) and the
content-firewall config carry a `tenant_id`, and each tenant gets its own Ed25519 signing key derived
from the control-plane key seed, so one tenant's evidence cannot be signed or read as another's. The
tenant for a request is resolved from the `x-acp-tenant` header, else the principal's Entra tenant,
else `default`. `GET /tenants` lists the tenants that have data.

In the console, a tenant selector in the top bar (populated from `/tenants`) re-scopes every panel over
the live SSE stream and applies to writes, so an operator can switch tenants in the browser without
restarting. A single-tenant console instance can also pin its tenant with the `ACP_TENANT` environment
variable.

## mutual TLS between components

Components can require mutual TLS so only enrolled parties reach the control API:

```sh
acp-server --tls-ca ca.pem --tls-cert server.pem --tls-key server.key ...
```

The server then presents its certificate and requires a client certificate signed by the ACP CA; a
client with no certificate or a rogue one fails the handshake.
