# 15. Security and verification

Varman is a governance product, so its own security and the way you can check its claims matter as
much as its features. This chapter is the trust model, the threat model in brief, and how to verify
the guarantees yourself.

## The trust core

The crypto-critical logic is deliberately small and pure, with no sockets or filesystem in the hot
path, so it can be audited in isolation.

- **Hashing:** SHA-256 over canonical (sorted-key) JSON, for stable, reproducible record hashes.
- **The log:** an RFC 6962 Merkle tree with correct leaf and node domain separation, inclusion and
  consistency proofs.
- **Signing:** Ed25519 signed tree heads (never per record). Verification is public-key only.
- **Append-only:** enforced by SQL triggers, and, more importantly, by verification itself, which
  re-derives the leaves, so dropping the triggers does not defeat detection.
- **Keys:** a 0600 seed file by default, or a PKCS#11 HSM ([chapter 9](09-evidence.md)); evidence
  argument payloads encrypted at rest with AES-256-GCM under a KEK that never touches the database.

## What the threat model assumes and resists

- **A tampered store.** An attacker with write access to the ledger database cannot forge history:
  editing a leaf or rewriting the tree is caught at verification because they cannot re-sign the head
  without the private key.
- **A bypass attempt.** An agent that tries to reach a tool server or model directly is stopped by
  the [guard](06-guard.md) (attestation) and [credential brokering](04-gateway.md), and the attempt
  is recorded. The [coverage report and egress canary](12-grc.md) measure residual reachability.
- **A malicious tool server (rug-pull).** Tool-integrity pinning detects a changed tool definition
  and quarantines it until re-pinned.
- **Prompt and indirect injection.** The [content firewall](10-content-firewall.md) screens prompts,
  arguments and tool results, hardened against obfuscation. Detection is defence in depth; the
  authorization layer contains what gets through.
- **A bad policy deploy.** A policy is signed and versioned; a PEP loads it only after verifying the
  signature, and a non-compiling policy is rejected, leaving the last good policy serving.
- **A compromised key.** Custody can move to an HSM; the append-only store and separation of duty
  limit the blast radius; key rotation with historical verification is designed for but not yet wired
  into the ledger.

Some properties depend on deployment: credential brokering and the guard only help if callers cannot
reach the upstreams directly (enforce that with a network allowlist), and RLS tenant isolation
depends on connecting as a non-superuser role ([chapter 14](14-operations.md)).

## Verify it yourself

Do not take the claims on trust. The whole point of the design is that you do not have to.

```sh
# 1. Run the end-to-end acceptance: identity, decision, approval, execution, evidence, verification,
#    plus fail-closed checks (a tampered ledger fails, an invalid token is rejected).
bash demo/vertical/run.sh

# 2. Prove the firewall's resilience on an obfuscation corpus.
acp redteam model.json --min-catch 0.9

# 3. Measure unavoidability.
acp coverage observed.txt governed.txt
acp canary-egress probes.json

# 4. Verify a live ledger, then verify a standalone export on a clean machine with only the pubkey.
acp verify evidence.db
acp export evidence.db > pack.json && acp verify-pack pack.json
```

## Independent review questions

For a cryptographic reviewer, the questions worth answering independently: is the Merkle construction
second-preimage resistant as used; are the signed-tree-head serialisation and signature free of
malleability; is the append-only property enforced beyond the database triggers by verification
itself (it is, verification re-derives leaves); is the OIDC verification free of algorithm-confusion
and key-confusion; and is key custody sound for your intended deployment.

## Honest status

Varman has no third-party security certifications (SOC 2, penetration test, independent cryptographic
audit) yet, and no production deployments. The HSM signing path is verified against SoftHSM and
should be validated against your specific production module. Treat the reference implementation as
ready to evaluate and pilot; chapter 14 sets out what is in place and what remains before an
unattended production rollout.
