# Entra ID setup and cutover runbook (control-plane RBAC)

Date: 2026-09-19
Status: operator runbook for wiring ACP's control-plane RBAC to Microsoft Entra ID. The verification code (RS256 + JWKS fetch) is built and tested; this is the operator side plus the one-flag cutover. No client secret and no password are ever required.

Current mode: the system runs on the built-in mock issuer (`--dev-auth`) until the real values below are confirmed. Nothing here changes above the JWKS seam when you switch to real Entra.

## The app registration (already created)

- App name: `acp`
- Application (client) ID: `090fef4c-25c4-425a-970e-8e08213ba6ba`
- Directory (tenant) ID: `45ffdb70-a608-4b9c-b1e1-d610f039e319`

Derived, public, no secret:
- Issuer: `https://login.microsoftonline.com/45ffdb70-a608-4b9c-b1e1-d610f039e319/v2.0`
- JWKS URI: `https://login.microsoftonline.com/45ffdb70-a608-4b9c-b1e1-d610f039e319/discovery/v2.0/keys`

## 1. App roles

Define on App registrations to acp to App roles (or via the Manifest). Value strings are what land in the token `roles` claim and map to ACP capabilities:

| Value | Capability | Gates |
|---|---|---|
| PolicyAdmin | EditPolicy | deploy policy |
| BreakGlassOperator | BreakGlass | engage / clear kill-switch |
| Approver | Approve | resolve step-up approvals |
| Auditor | Export | read evidence / reports |
| Registrar | (registration flows) | register / revoke agents |

Manifest form (each needs a unique GUID id):

```json
"appRoles": [
  {"allowedMemberTypes":["User"],"displayName":"Policy Admin","id":"a1111111-1111-1111-1111-111111111111","isEnabled":true,"value":"PolicyAdmin","description":"Deploy policy"},
  {"allowedMemberTypes":["User"],"displayName":"Approver","id":"b2222222-2222-2222-2222-222222222222","isEnabled":true,"value":"Approver","description":"Resolve approvals"},
  {"allowedMemberTypes":["User"],"displayName":"Break-glass Operator","id":"c3333333-3333-3333-3333-333333333333","isEnabled":true,"value":"BreakGlassOperator","description":"Operate kill-switch"},
  {"allowedMemberTypes":["User"],"displayName":"Auditor","id":"d4444444-4444-4444-4444-444444444444","isEnabled":true,"value":"Auditor","description":"Read evidence"},
  {"allowedMemberTypes":["User"],"displayName":"Registrar","id":"e5555555-5555-5555-5555-555555555555","isEnabled":true,"value":"Registrar","description":"Register agents"}
]
```

## 2. Assign users to roles

Assignment happens on the Enterprise application, not the App registration:

Microsoft Entra ID to Enterprise applications to search acp to Users and groups to Add user/group.

- One role per assignment. To give a user several roles, repeat Add user/group once per role; the user then appears once per role, and the token `roles` claim lists all of them.
- Group-based assignment (one group carries a role) needs Entra ID P1/P2; individual user assignment works on any tier.
- Newly created roles can take 5 to 15 minutes to appear in the role picker.

## 3. Audience

Set the audience ACP checks to the client id: `090fef4c-25c4-425a-970e-8e08213ba6ba`. This is the `aud` for ID tokens and for v2 access tokens issued for the app. If you use Expose an API (Application ID URI `api://090fef4c-...`), the access-token `aud` may be that URI instead, in which case set the audience to match. In the app Manifest set `"accessTokenAcceptedVersion": 2` so the issuer is the v2 form.

## 4. Get a token to confirm the claims

```bash
az login --tenant 45ffdb70-a608-4b9c-b1e1-d610f039e319
az account get-access-token --resource 090fef4c-25c4-425a-970e-8e08213ba6ba --query accessToken -o tsv
# if no roles claim appears, try:
az account get-access-token --scope 090fef4c-25c4-425a-970e-8e08213ba6ba/.default --query accessToken -o tsv
```

Paste the token into https://jwt.ms and confirm: `aud` (client id or api:// URI), `iss` (the v2 issuer above), and a `roles` array. Do not paste the token anywhere untrusted; it is a bearer credential.

## 5. Cutover: one command

```bash
acp-server \
  --policy-store ./store --registry ./registry.json --break-glass-file ./grant.json \
  --entra-tenant   45ffdb70-a608-4b9c-b1e1-d610f039e319 \
  --entra-audience 090fef4c-25c4-425a-970e-8e08213ba6ba
```

On startup it logs `OIDC RBAC enabled (issuer ..., aud ...)` after fetching the tenant JWKS, and refreshes the keys hourly (rotation-safe). If the audience turned out to be the `api://` URI, use that as `--entra-audience`. The explicit form `--oidc-jwks <url|file> --oidc-issuer <iss> --oidc-audience <aud>` is also available.

## 6. Verify end to end

```bash
TOKEN='<paste the az token>'
# with a PolicyAdmin token: 200
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{"policy":"version: 1\ndefault: allow\nrules: []\n","author":"me"}' \
  http://127.0.0.1:8787/policy-store/deploy
# without a token: 401
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "content-type: application/json" -d '{}' \
  http://127.0.0.1:8787/policy-store/deploy
```

200 with the token and 401 without means real Entra is verifying your users. Separation of duty still applies: a token without BreakGlassOperator gets 403 on the kill-switch endpoints, and a token without PolicyAdmin gets 403 on deploy.

## What ACP never needs

No client secret, no certificate, no password. Verification uses Entra's public signing keys. A secret would only be needed if ACP itself initiated an interactive login; as a resource server validating incoming tokens it needs none. The interactive console sign-in (so a browser user's own token drives the console) is a later step; today the console uses the dev-token stand-in under `--dev-auth`.
