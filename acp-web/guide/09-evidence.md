# 9. The evidence ledger

The ledger is the reason to look at Varman. Every decision a PEP makes is recorded as a leaf in a
tamper-evident Merkle log with an Ed25519 signed tree head, and the whole history is verifiable by a
third party with the public key alone. The store never has to be trusted, because the proof does not
live in the store.

## What it is

`acp-ledger` is a durable, append-only, RFC 6962-verifiable log over SQLite.

- **Merkle log.** Each record is a leaf; the tree head is a single hash over all leaves. The head is
  signed with Ed25519 on every append (never per record), so a signature covers the whole history to
  that point.
- **Append-only.** SQL triggers forbid `UPDATE` and `DELETE` on the records and heads. Even if an
  attacker drops the triggers and edits a row, verification catches it, because it re-derives the
  leaves and the roots.
- **Durable.** Write-ahead logging is on, and an append wraps the argument blob, the record and the
  new signed head in one transaction, so a crash never leaves a record without its signed head.
- **Idempotent.** Appends are keyed by decision id, so a retried batch never creates duplicate leaves.
- **Crash-safe recording.** PEPs spool evidence and replay it, so a decision is never lost between
  being made and being recorded.

## Verifying, independently

```sh
acp verify evidence.db            # re-derive the tree and check every signed head, pubkey-only
acp export evidence.db > pack.json
acp verify-pack pack.json         # verify a standalone export on a clean machine
```

`acp verify` opens the database read-only and needs only the public key stored inside it. It catches
an edited leaf (named by its sequence number) and a history rewrite (a head whose root no longer
matches the leaves, which an attacker cannot re-sign without the key). `verify-pack` does the same for
an exported pack with no database at all, so you can hand a regulator a file and a public key and
they can check it themselves.

## Encryption at rest

The sensitive part of a record is the argument payload. Set a key-encryption key and those payloads
are stored as AES-256-GCM envelopes (a fresh per-blob key wrapped by your KEK, bound to the record),
both in the ledger and in the crash-safe spool (the pre-drain buffer). The decision metadata itself
(principal, agent, tool, resource, verdict) is stored in cleartext by design: the Merkle log must be
verifiable by anyone holding only the public key, with no KEK, so metadata cannot be encrypted without
breaking independent verification. Keep sensitive data in arguments, not in resource or tool names.

```sh
export ACP_LEDGER_KEK_FILE=/etc/acp/kek        # 64 hex chars in a mounted secret file (preferred)
# or, for local use:
export ACP_LEDGER_KEK=<64-hex>
```

The KEK never touches the database. Encryption is orthogonal to verification, because the Merkle
leaves commit to the record, not to the (auxiliary, purgeable) argument blob, so an encrypted ledger
still verifies with the public key alone. A wrong or absent KEK reveals nothing. In the helm chart,
the KEK is mounted from a Kubernetes Secret (see [chapter 14](14-operations.md)).

## HSM signing

By default the ledger signs with an Ed25519 key from a 0600 seed file. To sign on a PKCS#11 HSM
instead, so the private key never leaves the token, set the module in the environment:

```sh
export ACP_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export ACP_PKCS11_SLOT=<slot> ACP_PKCS11_PIN=<pin> ACP_PKCS11_LABEL=acp
```

The proxy, gateway and control-plane meta-ledger all pick this up and sign tree heads on the token,
with the file key as the fallback. An HSM-signed ledger verifies with the exact same public-key path.
Validate against your specific production HSM module before relying on it.

## Right to erasure and retention

Argument payloads are separately purgeable without breaking verification, because the leaf commits to
the record's argument-hash, not the payload:

```sh
acp purge evidence.db <older-than-days>   # drop payloads older than N days (retention)
```

A single decision's payload can be erased for a right-to-erasure request; the signed decision stays
verifiable, only the recoverable value is gone.

## Backup

`acp ledger-backup` copies the database plus its WAL and re-verifies the copy, so a bad copy is
caught:

```sh
acp ledger-backup evidence.db /backups/evidence-$(date +%s).db
```

The helm chart can run this on a schedule as a sidecar to a second volume. For a real recovery point
objective, ship the backup or the signed export to object storage; see [chapter 14](14-operations.md).

## The meta-audit

The control plane keeps a second ledger of its own governance events (policy changes, key rotation,
RBAC changes, break-glass engage and clear), appended to the same verifiable structure, so the
governance of the governor is itself recorded.

## SIEM export

Every decision projects faithfully into your SIEM in CEF, OCSF (class 6003) and RFC 5424 syslog. (OTLP
is a separate live path: the proxy can stream spans to an OpenTelemetry collector with `--otel`, rather
than an `acp siem` output format.)

```sh
acp siem evidence.db --format ocsf
acp siem evidence.db --format cef
acp siem evidence.db --format syslog
```

These read the real ledger records, so what your SIEM sees is exactly what was recorded, not a
separate log that could drift.

## Key custody and rotation

Varman uses several keys, and they do not all rotate the same way. This section lists each one, what it
protects, and, honestly, whether rotation is wired today or is a manual, caveated procedure. Where a
rotation path is not yet built, that is stated plainly so you do not assume a safety net that is not
there.

### The key-encryption key (KEK)

`ACP_LEDGER_KEK_FILE` (a 64-hex secret file, preferred over the inline `ACP_LEDGER_KEK`) wraps the
per-blob keys that encrypt argument payloads at rest.

**Rotation is not yet wired.** There is no re-wrap path: rotating the KEK renders every existing
argument blob permanently unreadable, because the old blobs were wrapped under the old KEK and nothing
re-encrypts them under the new one. Until a re-wrap tool exists, treat the KEK as long-lived. If you
must roll it, the workable procedure is to export what you need, purge old payloads
(`acp purge`, which keeps the signed decisions verifiable), and start encrypting new payloads under the
new KEK, accepting that the old payloads are gone. Verification is unaffected either way, because the
Merkle leaves commit to the record and the argument hash, not to the encrypted blob.

### The ledger signing key (or HSM)

The ledger signs its tree head with an Ed25519 key from a 0600 seed file (`--key`), or on a PKCS#11 HSM
when the `ACP_PKCS11_*` environment is set. The public key is stored inside the ledger so `acp verify`
is self-contained.

The durable answer to custody here is the **HSM**: the private key never leaves the token, so there is
no seed file to rotate or leak. Prefer the HSM over rotating a file seed. Rotating the signing key of an
existing ledger is not a routine operation: past heads were signed with the old key, so a new ledger (or
a new signing epoch) is the clean boundary. Plan signer changes at ledger-rollover time, not mid-stream.

### The control-plane key (`--cp-key`)

`--cp-key` is the key the control plane signs endpoint dispositions and GRC records with. Rolling it
means new records are signed under the new key; records signed under the old key still need the old
public key to verify, so retain the old public key for as long as you keep those records. There is no
automatic re-sign of historical records on rotation. Note also that when an HSM is configured it
currently covers only ledger-head signing, so GRC, endpoint and break-glass signing still use the
`--cp-key` file key.

### Agent tokens

Agent tokens are the one credential with a clean, wired rotation path. Each agent's token is issued once
(shown once) at registration. To rotate, **deactivate the agent and register it again** from the console
Agents page (or `POST /agents/:id/deactivate` then `POST /agents`), which mints a fresh one-time token;
update the proxy's `--agent-token`. There is no long-lived shared secret to leak.

### The break-glass key (`--break-glass-key`)

The kill-switch grant is Ed25519-signed. Pin the public key at each PEP so a tampered or unsigned grant
is rejected. Honest caveat: signature enforcement is active only where a public key is pinned; if no key
is pinned, a grant is accepted without a signature check. Always pin the break-glass public key in
production. Rotating it means re-pinning the new public key at every PEP that honours the grant.

### The enforcement (attestation) key

The proxy signs an `x-acp-enforcement` attestation with its Ed25519 key; a tool-server guard pins the
proxy's public key and rejects un-proxied calls (see [chapter 6](06-guard.md)). Rotating the proxy key
means updating the pinned public key at each guard, so schedule proxy-key changes with a guard re-pin.

### Enrolment and artifact signing keys

Signed interception registries (`acp intercept sign --key`) and signed release artifacts
(`acp sign-artifact`) use file-based Ed25519 keys. Rotation is manual: sign with the new key, distribute
the new public key, and re-sign anything that must keep verifying under the new key.

### JWKS / OIDC rollover

Human identity is verified against your IdP's JWKS (Entra or a generic OIDC issuer). Key rollover is the
**IdP's** job: it publishes new keys at the JWKS endpoint and Varman fetches them, so an IdP-side signing
key rotation needs no change on the Varman side beyond the service being able to reach the JWKS URL. If
the JWKS cannot be loaded when identity is requested, the server and proxy fail closed and refuse to
start rather than run without verifying tokens.

### Summary

| Key | What it protects | Rotation today |
| --- | --- | --- |
| KEK (`ACP_LEDGER_KEK_FILE`) | argument payloads at rest | **not wired** (no re-wrap); treat as long-lived |
| Ledger signing key / HSM | the signed evidence head | prefer HSM; rotate at ledger rollover, not mid-stream |
| `--cp-key` | endpoint and GRC record signatures | manual; retain old public key for old records |
| Agent token | agent identity | **wired**: deactivate and re-register for a fresh token |
| Break-glass key | the kill-switch grant | re-pin the new public key at every PEP |
| Enforcement key | proxy-to-guard attestation | re-pin the new public key at every guard |
| Enrolment / artifact keys | signed registries and artifacts | manual: re-sign and redistribute |
| IdP JWKS (OIDC / Entra) | human token verification | handled by the IdP; Varman refetches |
