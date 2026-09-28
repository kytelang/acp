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
  arguments and tool results (text and, through the external scan hook, image and audio parts),
  hardened against obfuscation. Detection is defence in depth; the authorization layer contains what
  gets through.
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
acp canary-egress targets.txt

# 4. Verify a live ledger, then verify a standalone export on a clean machine with only the pubkey.
acp verify evidence.db
acp export evidence.db > pack.json && acp verify-pack pack.json
```

## Detection efficacy (measured, gated in CI)

The content firewall's efficacy is measured against a checked-in labelled corpus
(`crates/acp-core/corpus/detection-corpus.jsonl`, 263 examples: 111 injection, 42 PII, 110 benign,
authored by the ACP team). The `corpus_gate` test runs the built-in engine over it on every
`cargo test`, so a regression fails CI.

Current numbers for the built-in signature engine (no ML model loaded):

| Detector | Precision | Recall | Benign false-positive rate |
| --- | --- | --- | --- |
| Prompt injection | 1.00 | 1.00 | 0.00 |
| PII | 1.00 | 0.92 | n/a |

Published thresholds the CI gate enforces (a build fails if any is breached): injection precision and
recall at least 0.90 with a benign FPR at most 0.10; PII precision at least 0.90 with recall at least
0.80. These are for the signature engine alone; loading an ML model (the content firewall's `model`
field) raises recall further. A `content_scan_latency_is_reported` test measures the content-scan path:
on the development machine it runs at roughly 70 microseconds per scan (signature engine, over the
263-example corpus), and CI guards it under 2 ms/scan. A separate `content_scan_throughput_and_percentiles`
load benchmark (ignored by default; run with `cargo test -p acp-core --release -- --ignored --nocapture`)
drives the scan path across 8 concurrent workers: on the development machine it sustains roughly 690,000
scans/sec with p50 6.5 us, p95 14 us and p99 25 us. Grow the corpus as new attack families appear and keep these numbers in
step with the test.

## Injection model: a held-out benchmark

Beyond the corpus gate (which scores the shipped model on the whole corpus), a separate benchmark
(`crates/acp-core/tests/injection_benchmark.rs`) trains the hashed n-gram logistic-regression model on a
deterministic train split and evaluates it on the UNSEEN test split, so it measures generalisation, not
memorisation. On the current corpus it reports roughly precision 0.94, recall 0.97 and a benign
false-positive rate 0.05 on the held-out set, and a metric gate fails CI on a regression. This is the
fast, on-prem first-stage detector; a transformer via ONNX is the documented next tier behind the same
`Scorer` seam (it needs a training-data programme, so it is not bundled).

## Independent review questions

For a cryptographic reviewer, the questions worth answering independently: is the Merkle construction
second-preimage resistant as used; are the signed-tree-head serialisation and signature free of
malleability; is the append-only property enforced beyond the database triggers by verification
itself (it is, verification re-derives leaves); is the OIDC verification free of algorithm-confusion
and key-confusion; and is key custody sound for your intended deployment.

## Honest status

Varman has no third-party security certifications (SOC 2, penetration test, independent cryptographic
audit) yet, and no production deployments. A readiness assessment that maps the existing technical
controls to the SOC 2 Trust Services Criteria, ISO/IEC 27001 Annex A and ISO/IEC 42001 is in
`docs/soc2-iso-control-mapping.md`; the remaining work for certification is documented policy plus an
operating window and an auditor, not new features. The HSM signing path is verified against SoftHSM and
should be validated against your specific production module. Treat the reference implementation as
ready to evaluate and pilot; chapter 14 sets out what is in place and what remains before an
unattended production rollout.
