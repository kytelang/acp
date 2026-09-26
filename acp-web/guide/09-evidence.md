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
are stored as AES-256-GCM envelopes (a fresh per-blob key wrapped by your KEK, bound to the record):

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
