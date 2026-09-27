# Real Entra ID cutover runbook (R7)

Identity in Varman is verified against a mock issuer today, and the production path (RS256 signature
verification, JWKS fetch with hourly rotation, iss/aud/nbf/exp validation, app-role to capability
mapping) is fully built and unit-tested. What has not happened is a run against a real customer tenant,
because that needs a customer's Entra tenant, an app registration, app roles, and a token. This runbook
is the step-by-step cutover, with a runnable preflight so most of it can be checked before any traffic
depends on it.

## What the customer provides

1. An Entra **tenant id** (the directory GUID).
2. An **app registration** for Varman with:
   - an **Application ID URI** or client id to use as the token **audience** (for example
     `api://acp-control-plane`),
   - **app roles** matching the ACP role names: `PolicyAdmin`, `AppRegistrar`, `GrcAuthor`,
     `FirewallAdmin`, `Approver`, `Auditor`, `SecurityOfficer` (unknown roles grant nothing, so the set
     can be a subset).
3. A **test token** for a user or service principal that has one or more of those app roles assigned.
   This is the only item that gates the final verification.

## Step 1: preflight the JWKS (no token needed)

Confirm Varman can reach and parse the tenant's signing keys before anything depends on it:

```
acp-server --entra-preflight --entra-tenant <TENANT_ID> --entra-audience <AUDIENCE>
```

Expected: `[ok] JWKS fetched: N key(s)` and `preflight OK` (exit 0). This derives the issuer
`https://login.microsoftonline.com/<TENANT_ID>/v2.0` and the JWKS URL
`.../discovery/v2.0/keys`, fetches the keys, and confirms they parse. A failure here is a network or
tenant-id problem, caught before cutover.

## Step 2: preflight a real token (end-to-end)

With a test token, verify the whole chain and see the effective capabilities:

```
acp-server --entra-preflight --entra-tenant <TENANT_ID> --entra-audience <AUDIENCE> \
    --entra-test-token "<JWT>"
```

Expected: `[ok] token verified`, the principal's `oid` / `preferred_username` / `tid`, the app roles on
the token, and the ACP capabilities they map to. If it prints `[warn] token carries no app roles`, the
app roles are not assigned in Entra: fix the role assignment, not Varman. A `[FAIL]` names the exact
check that failed (unknown signing key, algorithm mismatch, bad signature, wrong issuer, wrong audience,
expired, not yet valid), which points straight at the misconfiguration.

## Step 3: bring up the control plane against the real tenant

Once both preflights pass, start the control plane with the same flags (drop `--entra-preflight`):

```
acp-server --addr <addr> --store <url> --cp-key <path> \
    --entra-tenant <TENANT_ID> --entra-audience <AUDIENCE>
```

Auth is now fail-closed: if the JWKS cannot be loaded at start-up the server refuses to start. The JWKS
is refreshed hourly, so a rotated signing key is picked up without a restart. Point the gateway and the
proxy at the same tenant with their `--entra-tenant` / `--entra-audience` flags.

## Step 4: soak the identity path

Over the first operating window, confirm:

- **Key rotation:** when Entra rotates its signing keys, tokens signed by the new key verify without a
  restart (the hourly JWKS refresh). To force a check, restart and confirm the fresh JWKS loads.
- **Clock skew:** the verifier allows 60 seconds of leeway on `nbf`/`exp`. Confirm this matches your
  environment; tokens outside the leeway are rejected as `NotYetValid` / `Expired`.
- **Token expiry and refresh:** clients refresh their tokens before `exp`; a stale token is rejected
  with `Expired`, which is the expected, safe behaviour.
- **SCIM group to role sync:** if SCIM provisioning is enabled, confirm Entra group membership flows to
  the ACP roles and therefore to capabilities.

## Rollback

Identity is opt-in. To roll back, restart the services without the `--entra-*` flags (RBAC off, local
demo behaviour) or with `--dev-auth` for the mock issuer. No data migration is involved; only the token
verification source changes.

## Status

Code: complete and preflightable today (Step 1 verified live against Microsoft's public JWKS endpoint).
The live-tenant verification (Steps 2 to 4) is blocked only on a customer tenant, app roles, and a token,
which is a customer/process dependency, not a code gap.
