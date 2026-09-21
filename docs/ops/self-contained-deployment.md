# Self-contained (local, on-prem) deployment

ACP is designed to run **entirely inside the enterprise**, with no cloud account and no network
egress. This is the baseline deployment, not a special mode: every external service is an optional
backend behind an interface, and a local backend ships in the repo for each one. Cloud services
(Azure, AWS) are optional swaps for organisations that want managed backends, never a dependency.

The single external identity option is **Entra ID**, because most enterprises already run Windows
and Entra for identity. Even that is optional: `acp-auth` verifies any OIDC provider via its JWKS,
so a self-hosted Keycloak or Dex works identically, and the test suite uses a mock Entra IdP.

## Proof it runs local

`scripts/run-local.sh` builds the binaries and runs the full flow (gate a denied call, forward an
allowed call to a local tool server, verify the tamper-evident ledger, export a self-verifying pack)
with **zero cloud and zero network egress**. The air-gapped test (`crates/acp-core/tests/airgapped.rs`)
proves the sign -> anchor -> verify chain completes with no network calls at all.

## Minimal footprint

Two binaries and two files:

- `acp-proxy`: sits in front of the agent's MCP tool server, gates every `tools/call`.
- `acp-server`: the control plane: approval inbox, reporting, liveness/alerts, meta-audit.
- a local **SQLite** evidence ledger (embedded, no database server required).
- a local **Ed25519** signing key file (0600).

That is the whole system. It runs on a laptop, a single VM, an on-prem host, or fully air-gapped.

```
acp-proxy stdio --policy policy.yaml --ledger evidence.db --key signing.key -- <tool-server>
acp-server --policy policy.yaml --ledger evidence.db --approvals evidence.db.approvals
acp verify evidence.db          # verify the tamper-evident log, locally
acp export evidence.db > pack.json && acp verify-pack pack.json   # portable, no service
```

## Each component: local backend, and the optional on-prem hardening

| Need | Local backend (ships in repo) | Optional on-prem hardening | Optional cloud swap |
| --- | --- | --- | --- |
| Signing | Ed25519 key file (`sign`, 0600) | PKCS#11 HSM (YubiHSM / Thales / SoftHSM) via the `keymgr` trait | Azure Key Vault / AWS KMS |
| Evidence store | Embedded SQLite ledger | The org's own Postgres (`acp-pgstore`, FORCE RLS) | Azure PG / RDS |
| Anchoring | `LocalAnchor` (internal tamper-evident log) | Self-hosted Rekor or an on-prem RFC 3161 TSA | Azure Confidential Ledger |
| Archive / export | Local filesystem (`acp export`) | On-prem MinIO (self-hosted S3), WORM via filesystem | Azure Blob / S3 object-lock |
| Encryption at rest | Local AES-256-GCM (`acp-encrypt`), KEK from a file | KEK from the PKCS#11 HSM | KEK in Key Vault (BYOK) |
| Identity / SSO | Mock Entra (tests); self-hosted Keycloak/Dex | Real **Entra ID** (the accepted external option) | Entra ID |
| HA control plane | Single binary; or 2 instances + lease in Postgres + nginx/HAProxy | Same, on the org's own hosts | Container Apps, etc. |
| Notifications | none required; Slack/webhook by config | on-prem SMTP / webhook receiver | Teams / PagerDuty / Slack |

Nothing in the left two columns needs a cloud account.

## On the two hardening notes

- The **file-based signing key** is fine for development and small deployments. A serious on-prem
  install should hold the key in a PKCS#11 HSM. The `keymgr` trait already abstracts this, so the
  HSM backend is an implementation behind the existing seam, not a redesign.
- **`LocalAnchor` is in-process.** External anchoring mainly defends against the operator rewriting
  their own history, which matters most for a multi-party SaaS trust model. For a single-org on-prem
  install the signed Merkle log alone is usually sufficient; if the org wants an independent anchor,
  a self-hosted Rekor or an on-prem TSA drops into the `anchor` trait.

## Air-gapped

With no notification sinks and no anchor configured (or an internal one), the proxy and server make
**no outbound network calls** beyond forwarding to the local tool server. Evidence is signed and
verifiable offline; an exported pack verifies on any machine with only the public key inside it.

## HA without a cloud or Kubernetes

The "no single point of failure" requirement is met by running two `acp-server` instances behind a
plain load balancer (nginx / HAProxy) with leader election through `ha::LeaseManager` backed by a
lease row in the org's Postgres. No Kubernetes and no cloud service are involved. A single instance
is a perfectly valid start when HA is not yet required.
