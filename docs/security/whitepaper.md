# Varman (ACP) security whitepaper and threat model

Date: 2026-09-21
Status: audit-ready reference for the security and cryptographic design of ACP. Written so an independent reviewer (cryptography or security firm) can scope and verify the claims quickly. It is precise about what is guaranteed, and honest about what is not.

## 1. Purpose and trust model

ACP is a runtime authorization and evidence layer for AI actions. Its security value rests on four properties, in order of how much of ACP's differentiation depends on them:

1. Verifiable evidence. Every decision is recorded in a tamper-evident log that a third party can verify with a public key alone, without trusting ACP's store.
2. Fail-closed authorization. If ACP is down, is not in the path, or cannot record a decision, the governed action does not happen.
3. Verified identity. Actions are bound to a registry-verified agent and, when configured, an OIDC-verified human principal.
4. Unavoidability. Deployed correctly, an agent cannot reach a governed resource except through ACP.

The trust core is deliberately small and pure. The crypto-critical logic lives in `acp-core` (no sockets, no filesystem in the hot logic) so it is unit-testable and auditable in isolation: `merkle.rs` (the verifiable log), `sign.rs` (signing and tree heads), `canonical.rs` (canonical hashing), `attest.rs` (enforcement attestation), `breakglass.rs` (signed emergency grants), `toolintegrity.rs` (tool pinning). The ledger persistence is in `acp-ledger`, identity in `acp-registry` and `acp-auth`, transport security in `acp-mtls`, and a PKCS#11 key-custody signer in `acp-hsm` (implemented, not yet wired). Envelope encryption of data at rest lives in `acp-encrypt` and is wired into the ledger: when `ACP_LEDGER_KEK` is set, argument blobs are stored as AES-256-GCM envelopes (fresh per-blob DEK wrapped by the KEK, bound to `args_hash` as AAD), never plaintext. Verification is unaffected because the Merkle leaves commit to the canonical record, not the blob. KMS-sourced KEK delivery is the remaining hardening.

## 2. Architecture (one paragraph)

One control plane (registry, signed policy store, evidence ledger, approvals, keys) and many enforcement points (a transparent MCP proxy, an LLM gateway, a configuration-driven forward proxy, and native managed-settings compiled into coding agents). Each enforcement point consults the same shared policy decision function and writes to the same tamper-evident ledger. The planes are documented in `docs/design/platform-architecture.md`.

## 3. Cryptographic design (the auditable claims)

### 3.1 Evidence ledger

- Structure: an append-only log with an RFC 6962-style Merkle tree (`acp_core::merkle`). Each record's canonical bytes are hashed to a leaf (`leaf_hash`), and the tree root is signed as a Signed Tree Head.
- Signing: the Signed Tree Head carries `{tree_size, root_hash, timestamp_ms}` signed with Ed25519 (`acp_core::sign::Ed25519Signer`, `sign_sth` / `verify_sth`). The signing input is a fixed serialisation (`sth_bytes`).
- Append-only enforcement: the SQLite store (`acp-ledger`) has triggers (`records_no_update`, `records_no_delete`, `heads_no_update`) that reject UPDATE and DELETE on the evidence tables, so casual tampering fails at the database layer.
- Independent verification: `verify_file` and `verify_pack` re-derive every leaf from the stored canonical bytes, rebuild the Merkle tree, and check each stored Signed Tree Head's root and signature under the embedded public key. A single edited record (leaf mismatch) or a history rewrite (unsigned or mismatched root) is caught. Verification needs only the public key, not the private key or ACP itself.
- Argument privacy without losing verifiability: sensitive call arguments are stored separately (`args_blob`, keyed by `args_hash`) and can be purged for retention without changing the record's leaf, because the leaf is over the canonical record whose `args_hash` is unchanged. Redaction masks values for display and forwarding; the evidence hash is over the original, so a purged or redacted ledger still verifies.

Auditor procedure (independent evidence check):
1. Export a pack: `acp export <ledger.db> > pack.json`.
2. Verify with the public key inside the pack only: `acp verify-pack pack.json`.
3. Tamper test: edit any record's canonical bytes (removing the append-only triggers first, to simulate raw database access) and re-run; verification must fail with a leaf mismatch. This is exercised by `demo/vertical/run.sh`.

### 3.2 Keys and signing

- Algorithm: Ed25519 throughout (evidence tree heads, enforcement attestation, break-glass grants, policy and artifact signing). Content hashing is SHA-256 over canonical JSON (`canonical.rs`, sorted-key JCS-style serialisation) for stable, reproducible hashes.
- Key generation and custody: `Ed25519Signer::generate` and `from_seed`; seeds written with 0600 permissions on unix (`secret::write_key_secure`). For production, keys belong in an HSM or KMS. `acp-hsm` implements a real PKCS#11 (`cryptoki`) Ed25519 signer whose private key never leaves the token. Status: this signer is wired into the evidence-signing services (proxy, gateway, server) and selected with `ACP_PKCS11_MODULE`; the ledger then signs tree heads on the token, with a 0600-seed file key as the fallback. Verified end to end against SoftHSM 2.7 (HSM-signed evidence verifies pubkey-only). Validate against your specific production HSM module before relying on it.
- Rotation and agility: the record provenance stamps the algorithm identifiers (`algo_hash`, `algo_sig`) so the scheme is explicit in every record and can evolve without ambiguity.

### 3.3 Enforcement attestation

- Purpose: prove to a tool server that a request passed through the governing proxy, so an agent cannot reach a guarded server directly.
- Mechanism (`acp_core::attest`): the proxy stamps a short-lived token `<issued_ms>.<session>.<sig>` signed over `<issued_ms>.<session>` with the proxy key. A guard (`acp-guard`) verifies the signature under the pinned public key and rejects any request older than a bound (`max_age_ms`), so a captured token cannot be replayed indefinitely. The agent never holds the signing key.

### 3.4 Break-glass (emergency controls)

- Scoped, signed grants (`acp_core::breakglass`): a grant file is signed (Ed25519) and verified before application; scopes are global, agent, resource, tool or model; lockdown persists until cleared; grants are TTL-aware. A grant not validly signed by the pinned key is ignored. Separation of duty prevents a policy admin from tripping the kill-switch and the reverse.

### 3.5 Tool integrity

- TOFU pinning (`acp_core::toolintegrity`): a tool's `{name, description, inputSchema}` is fingerprinted (SHA-256 over canonical form) on first sight; a later change is reported as Changed and the tool is quarantined (rug-pull and tool-poisoning defence). Pins can be shared across replicas via Postgres so a rug-pull seen on one replica is caught on all.

## 4. Identity, authentication and authorization

- Agent identity: registry-issued bearer tokens; only the SHA-256 of the token is stored (`token_sha256`), so the store does not hold the secret. Verification is constant-work and fail-closed (an invalid token is not accepted as the agent).
- Human principal: OIDC and Microsoft Entra, RS256 verified via `ring` with JWKS fetch and rotation and a clock-skew leeway (`acp-auth`); degrades to `unattributed` when no valid token is presented, never to a spoofed identity.
- Delegation: an agent acting for a human principal is bound per request.
- Access control: RBAC on the control plane with separation of duty (PolicyAdmin, Approver, BreakGlassOperator, Auditor, Registrar).
- Transport: mutual TLS between the proxy and control plane (`acp-mtls`, rustls, client-cert required).

## 5. Threat model

Assets: the evidence ledger and its signing key; the policy and its signing key; agent and human identities; the break-glass key; the model and tool credentials the gateway brokers.

Trust boundary: only the `arg` namespace of a request is agent-controlled and therefore untrusted. The agent, principal, resource, operation, impact and derived flags are proxy-derived or registry-verified and are placed in a namespace the agent cannot populate.

| Threat (STRIDE) | Vector | Mitigation |
|---|---|---|
| Spoofing identity | Forge an agent or human identity | Registry token (hash-stored), OIDC RS256 with JWKS, fail-closed on invalid token |
| Tampering evidence | Edit or delete a decision record | Merkle leaves + signed tree heads + append-only triggers; independent verification catches edits and rewrites |
| Repudiation | Deny an action occurred | Every decision signed into the tamper-evident log, re-derivable by a third party |
| Information disclosure | Sensitive args in logs | Separated args store, redaction, hash-only evidence; ledger stores no plaintext secret |
| Denial of service or fail-open | Crash ACP to bypass it | Fail-closed: stdio child dies with the proxy; a bad evidence write denies rather than forwards; `--fail-open` is testing-only and warns loudly |
| Elevation of privilege | Do more than authorized | Default-deny with deny-overrides at the resource boundary; trajectory and data-boundary rules catch multi-step escalation and exfiltration |
| Replay | Reuse an attestation token | Freshness bound (`max_age_ms`) on the signed attestation |
| Confused deputy (MCP) | Token passthrough, consent abuse | ACP terminates and does not pass client tokens through; MCP OAuth audience binding is honoured |
| Supply chain | Rug-pull or poisoned tool or model | Tool-integrity pinning, admission gate with provenance and an external scanner verdict, signed AI-BOM |
| Key compromise | Steal the signing key | 0600 seeds today (HSM/KMS custody via `acp-hsm` is implemented but not yet wired); the append-only store and separation of duty limit blast radius |

## 6. What ACP does not claim (honest scope)

- Content detection is best-effort. Prompt-injection and jailbreak detection (signatures plus a trained classifier, hardened against obfuscation and indirect injection) reduces risk but does not survive a determined attacker. The layer that survives is authorization: even a fully-fooled agent cannot exceed its resource entitlements. See `docs/design/ml-based-content-engine.md`.
- Unavoidability is partly a deployment property. ACP provides the mechanisms (credential brokering, enforcement attestation, egress lockdown, a coverage report and a canary that measure it); making them unroutable-around is a rollout responsibility. See `docs/design/enforcement.md`.
- HTTP/2 on the TLS-interception path is fail-closed, not supported: an HTTP/2-only client fails the handshake and is recorded rather than passed. Workaround is base-URL pinning.
- Operational maturity: single-node verified; HA, DR and multi-replica are designed and the shared state is verified against Postgres, but a production deployment has not been run in anger. See `docs/commercial/pre-launch-requirements.md`.

## 7. Recommended audit scope

For an efficient external review, focus on the pure trust core, which has no I/O and is unit-testable in isolation:

- `crates/acp-core/src/merkle.rs`, `sign.rs`, `canonical.rs` (the verifiable-log and signing primitives).
- `crates/acp-ledger/src/lib.rs` (append, verify, verify_pack, verify_file, the append-only triggers).
- `crates/acp-core/src/attest.rs`, `breakglass.rs`, `toolintegrity.rs`.
- `crates/acp-auth/src/lib.rs` (RS256 and JWKS handling), `crates/acp-registry/src/lib.rs` (token hashing), `crates/acp-mtls`, `crates/acp-hsm`.

Suggested questions for the reviewer to answer independently: is the Merkle construction second-preimage resistant as used; are the Signed Tree Head serialisation and signature free of malleability; is the append-only property enforced beyond the database triggers by the verification itself (it is: verification re-derives leaves, so trigger removal does not defeat detection); is the OIDC verification free of algorithm-confusion and key-confusion; is key custody sound for the intended deployments.

## 8. Verification artifacts

- The end-to-end acceptance (`demo/vertical/run.sh`) demonstrates identity, decision, human approval, execution, evidence and independent verification, plus two fail-closed checks (tampered ledger fails verification; invalid token rejected).
- The adversarial-testing gate (`acp redteam`) reports the content engine's catch-rate and false-positive rate on an obfuscation corpus.
- The coverage attestation (`acp coverage`) and egress canary (`acp canary-egress`) measure unavoidability.
