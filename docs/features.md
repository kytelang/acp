# Varman (ACP) platform features

An honest capability map, written from the code, not from memory. Every item names the module or
crate that implements it so you can check the claim.

Read the tags carefully, because they are the point of this document:

- (enforced) means the capability runs inside a running binary (the proxy, the gateway, the guard,
  the intercept proxy, the control-plane server, or the CLI) and is exercised end to end.
- (primitive) means the logic is implemented and unit-tested in `acp-core` but is NOT yet called by
  any running binary. It is real, tested code you could wire up, not a shipping feature. We list these
  because they were genuinely built, but we will not pretend they are in the request path.
- (local-only) means only a local or in-memory backend exists; the external backend (cloud KMS, a
  transparency log, and so on) is a seam, not an implementation.
- (integrate) means it connects an external system you supply.
- (deployment) means it needs a rollout step to become fully unavoidable.

On-prem, vendor-neutral. See `docs/positioning.md`, `docs/evaluation-guide.md` and `docs/design/*`.

## Coverage: the surfaces it governs (enforced)
- Agent tool calls (MCP): a transparent proxy over stdio and streamable-HTTP (`acp-proxy`)
- Direct model API calls: a reverse-proxy gateway holding the upstream key (`acp-gateway`)
- Arbitrary HTTP/API traffic from agents, IDEs and browsers: a configuration-driven forward proxy
  (`acp-intercept`) with a signed endpoint registry and a real rustls TLS-interception CA (`mitm.rs`,
  built on `rcgen`/`rustls`) that decrypts and inspects body-inspecting endpoints on managed devices,
  detects cert-pinning and HTTP/2 handshake failures honestly rather than silently passing
- Coding agents' own powers (shell, file, network): one ACP policy compiled into Claude, Copilot and
  Gemini managed-settings JSON (`acp-nativecompile`). Note: this emits vendor settings, not machine
  code; the agent stays the enforcer of its own sandbox
- SaaS and embedded AI via connectors (integrate)

## Policy and authorization (enforced)
- One policy language across every surface: the model-v2 YAML DSL, compiled to Cedar (`acp-policy`)
- Subject = agent plus human principal; object = resource (database, filesystem, secrets, model-class,
  network, ...); operation (read, write, delete, egress, ...)
- Trusted tool-to-resource taxonomy (`resource.rs`) and model-to-class taxonomy (`modelclass.rs`),
  derived from names only, never agent-asserted, fail-safe to most-privileged on ambiguity
- Verdicts: allow, deny, step-up, allow-with-obligations
- Obligations: confirm, redact, rate-limit and token/cost budgets
- Default-deny with deny-overrides; multi-policy precedence deny > step-up > shadow > allow
- Signed, versioned policy with tamper detection on load; fail-closed on any evaluation or context
  error (`acp-policy::eval`, `store.rs`)

## Identity (enforced)
- Verified agent identity: registry tokens stored only as SHA-256, verify is fail-closed, immediate
  revocation (`acp-registry`)
- Verified human principal via OIDC/Entra: real RS256 and EdDSA with JWKS fetch and hourly refresh,
  algorithm and key-confusion checked, degrades to unattributed (`acp-auth`)
- Delegation: an agent acting for a human, with a TTL binding (`acp-registry`)
- Per-request identity on both the control plane (`acp-server`) and the enforcement path (`acp-proxy`,
  `acp-gateway`)

## Access control and human oversight (enforced)
- RBAC on the control plane: PolicyAdmin, Approver, BreakGlassOperator, Auditor, Registrar capabilities
  (`acp-auth`, gated in `acp-server`). With no auth flags, RBAC is off for local demo use; if auth is
  requested and JWKS fails to load, the server refuses to start
- Separation of duty: a policy admin cannot trip the kill-switch, and the reverse
- Step-up approvals with an approvals inbox: single-use, bound to session, principal, argument-hash and
  TTL, enforced by one atomic update (`acp-approvals`)
- mutual TLS between components, requiring a CA-signed client certificate (`acp-mtls`, wired in
  `acp-server`)

## Emergency controls (enforced)
- Kill-switch (break-glass): scoped (global, agent, resource, tool), signed grant files with optional
  pinned-key verification, mandatory reason and TTL; lockdown persists past its TTL until cleared
  (fail-safe); emits a meta-audit event (`breakglass.rs`, wired in proxy and gateway)

## Evidence and audit (enforced)
- Tamper-evident Merkle ledger: RFC 6962 tree over SHA-256 with correct leaf/node domain separation,
  inclusion and consistency proofs, signed tree heads (Ed25519), durable append-only SQLite with
  trigger-enforced immutability, idempotent append by decision id, a crash-safe evidence spool with
  replay (`acp-ledger`, `merkle.rs`, `sign.rs`)
- Independently verifiable with a public key alone: `acp verify` opens the store read-only and
  re-derives leaves, so removing the database triggers does not defeat detection
- Right-to-erasure without breaking verification: argument blobs are separately purgeable
- SIEM export that is a faithful projection of real ledger decision records: CEF, OCSF (class 6003) and
  RFC 5424 syslog (`acp siem`), plus OTLP, CEF and syslog event sinks in the proxy
- Encryption at rest (P0-1, wired): argument blobs, the sensitive part of the evidence store, are
  encrypted with AES-256-GCM envelope encryption (`acp-encrypt`) when a key-encryption key is set via
  `ACP_LEDGER_KEK`; each blob has a fresh DEK wrapped by the KEK, bound to its `args_hash` as AAD. The
  KEK never touches the database, verification is unaffected (the Merkle leaves commit to the record,
  not the blob), and erasure and backward-compatible plaintext reads still work. Remaining hardening:
  source the KEK from a KMS or secret manager rather than an environment variable (ties to key custody).

## Integrity and anti-tamper (enforced)
- Tool-integrity pinning: a SHA-256 fingerprint over name, description and input schema, trust-on-first
  -use, and a changed tool stays quarantined until an explicit re-pin (`toolintegrity.rs`, wired in the
  proxy and shared across replicas via Postgres)

## Unavoidability and containment (enforced, some deployment-gated)
- Credential brokering: the gateway holds the model key, so callers cannot reach the model directly
- Enforcement attestation: a signed, freshness-bound token proves a call came through ACP
  (`attest.rs`); the guard sidecar (`acp-guard`) verifies it in front of a tool server and records
  refused un-proxied attempts to the ledger
- Coverage attestation (`acp coverage`): a signed report joining observed against governed endpoints,
  listing ungoverned and leaky paths; `--require-full` gates a rollout. Honest boundary: the observed
  and governed sets come from operator-supplied files, so the number is only as complete as those inputs
- Egress canary (`acp canary-egress`): probes direct model or tool access and fails on any host
  reachable off-ACP
- Gateway base-URL pinning (`native-compile --gateway`): forces a coding agent's own model traffic
  through the gateway (deployment)
- SSRF hardening: an egress allowlist that hard-blocks loopback, private, link-local and cloud-metadata
  targets is implemented and tested (`egress.rs`), but is NOT yet wired into an outbound-dial path; only
  the canary half is in use today

## Content firewall (first-party, in-path) (enforced)
- Native content engine (`content.rs`): a genuinely trained linear classifier over hashed word and
  char n-grams (`LinearScorer`, from a shipped `models/injection-lr.json`) plus signature detection,
  PII and secret detection, span-level redaction and denied-topic rules; block or redact
- Hardened against obfuscation: input normalisation decodes base64, strips zero-width characters, folds
  homoglyphs and rejoins de-spaced letter runs; tool-result screening catches indirect injection in
  poisoned fetched documents, not just prompts and arguments
- Gated so a weakened model cannot ship: an adversarial red-team gate (`acp redteam`) and an eval gate
  (`acp content-eval`) with recall and precision thresholds on held-out data
- Enforced on both surfaces: the gateway prompt path and the proxy tool-call arguments
- Groundedness and hallucination: a zero-dependency lexical baseline flags an answer unsupported by its
  source context (`groundedness.rs`, `acp groundedness`); it does context-grounded faithfulness, not
  reference-free factuality. Production-grade groundedness is delegated to an external service (Azure or
  Bedrock) through the content-scan hook (integrate)
- Honest boundary: detection is defence in depth; the authorization layer is what actually contains a
  successful attack. Also note the PII/secret classifier (`classify.rs`) uses broad regexes: its secret
  pattern matches any 32-plus character alphanumeric run and will over-match

## Discovery and enrollment (enforced)
- Shadow-AI detection: classifies un-governed model-API and MCP endpoints by provider against a static
  host table of about twenty providers (`discover`)
- Enrollment loop (`acp enroll`): append-only signed dispositions (enroll, quarantine, accept-risk with
  expiry) over discovered endpoints; feeds the coverage report
- MDM/CASB export (`acp enroll export-mdm`): an allow and block list ACP hands to the org's endpoint
  tools

## Compliance and GRC
Two honestly different things live here. Read the tags.

Ledger-backed (derived from real signed ledger records):
- Framework reports (`acp grc-report`, enforced): grades EU AI Act, NIST AI RMF and ISO 42001 controls
  from counts decoded out of real ledger decision records. Note: the control-to-evidence id mapping in
  `export_evidence` is currently a small hardcoded demo, not a configured production mapping
- SIEM projection (`acp siem`, enforced): see Evidence above
- Warehouse re-verification (`warehouse.rs`, enforced): re-verifies an exported evidence row against a
  Merkle inclusion proof and a signed tree head, so a warehoused copy can be checked independently

Signed operator documents (authored by a human, Ed25519-signed, but NOT reconciled against the ledger).
The signature proves the document was not altered after signing. It does not prove that the "evidence"
strings or "linked decisions" inside it correspond to anything in the tamper-evident ledger; those are
free-text references today:
- EU AI Act risk assessment and tiering from a questionnaire (`acp assess`)
- Conformity checklist (`acp conformity`)
- AI risk register with likelihood x impact scoring (`acp risk`); linked decisions are free-text
- Model-card registry (`acp modelcard`)
- Use-case lifecycle registry with gated transitions (`acp usecase`)
- Signed attestations and sign-offs (`acp attest`)
- Signed AI bill of materials in CycloneDX (`acp aibom`) over an operator-supplied inventory
- Static control library across the three frameworks (`acp controls`)
- Policy-hash signing and a push allowlist (`policyprov.rs`): genuine cryptographic policy integrity

## Operations and posture (enforced)
- Control-plane console (`acp-server`): an approval inbox, policy view and signed deploy, verify and
  report endpoints, break-glass engage and clear, evidence timeline (via `acp-ledger`), agents and apps
  listing, Prometheus metrics. Single-tenant; liveness and spike state is in-memory and resets on
  restart
- Liveness and bypass detection: a dead-man's-switch over proxy heartbeats (`liveness.rs`) and a spike
  detector (`anomaly.rs`), both wired into the server
- Shared state across replicas: Postgres-backed token budgets and tool-integrity pins with row-locked
  atomic refills (`acp-pgstate`), and tenant isolation enforced by Postgres row-level security
  (`acp-pgstore`). Both are real tokio-postgres code; their tests are gated on a reachable database and
  skip cleanly without one
- Configurable impact taxonomy for blast-radius scoring (`impact.rs`), wired into the proxy and policy
- Self-governance meta-audit of policy, key, RBAC and break-glass changes, appended to the real ledger
  (`metaaudit.rs`)
- Fully on-prem, no cloud dependency; vendor-neutral

## Intent, sequence and data-boundary governance (enforced via proxy flags)
These are enforced when the proxy is launched with the matching flag, not as standalone CLI commands:
- Intent/trajectory governance (`trajectory.rs`, `--trajectory`): denies the action that completes a
  toxic combination (read a secret then egress) or exceeds a high-impact velocity budget, per session
- Data-boundary enforcement (`databoundary.rs`, `--data-boundary`): classified data may not cross to a
  lower-trust destination, most-restrictive-wins, destination-aware unlike the content firewall
- Continuous adversarial testing (`redteam.rs`, `acp redteam`): an obfuscation corpus with a catch-rate
  and false-positive gate for CI

## Implemented but NOT yet integrated (primitive)
These modules were genuinely built and are unit-tested, but no running binary calls them yet. We list
them so the inventory is honest, not to imply they are in the request path. Wiring each is a known,
bounded task:
- HA leader lease with fencing tokens (`ha.rs`)
- Staged policy rollout state machine (`rollout.rs`) and default-deny maturity path (`posture.rs`)
- Fleet registry (`fleet.rs`), classifier feedback and tuning (`tuning.rs`), classifier drift monitor
  (`drift.rs`), usage metering (`metering.rs`)
- Crypto-agility verifier registry (`agility.rs`)
- Four-eyes dual control (`dualcontrol.rs`), ITSM hold tickets (`ticket.rs`), SCIM approver directory
  (`scim.rs`; there is no SCIM REST endpoint in this tree), tenant offboarding and certificate of
  destruction (`offboarding.rs`)
- MCP method-drift tracker (`mcpdrift.rs`), non-MCP adapter normaliser (`adapter.rs`), host step-up
  retry shim (`hostshim.rs`), cross-proxy forensic timeline helper (`timeline.rs`)
- Real HMAC-SHA256 webhook signing and Slack verification (`webhook.rs`), correct but not plumbed to
  any endpoint
- `blast_radius.rs` is the v0 heuristic, superseded by the wired `impact.rs`

## Cryptographic primitives built but not wired (primitive, local-only)
- HSM/PKCS#11 signer (`acp-hsm`): a real `cryptoki` Ed25519 signer whose key never leaves the token,
  including a `Send` threaded wrapper. But no crate depends on it and the ledger does not use it yet; its
  tests are gated on a hardware or SoftHSM module. So HSM key custody exists in code, not in the signing
  path
- Encryption-at-rest (`acp-encrypt`): NOW WIRED into the ledger (see the Evidence section). Enable with
  `ACP_LEDGER_KEK`. The remaining gap is KMS-sourced key delivery, not the encryption itself
- Key rotation with historical verification (`keymgr.rs`): a local KMS that keeps every key so old
  records still verify after rotation; not wired to the ledger, which uses a single signer
- External transparency anchoring (`anchor.rs`): only a local in-memory anchor exists; Rekor or an
  RFC 3161 TSA would be a new backend behind the same seam

## Not built (explicit non-goals or gaps)
- OS-level process sandboxing of shell commands: `sandbox.rs` is a portable default-deny profile (a
  data structure) only. There is no seccomp, landlock or cgroups enforcement. The coding agents enforce
  their own sandboxes; ACP does not re-implement them
- A fully-managed cloud SaaS: ACP is on-prem by design
- Statistical model monitoring (bias, fairness, explainability dashboards)

## End-to-end vertical (enforced)
One acceptance test (`demo/vertical/run.sh`) proves the spine end to end: Agent, Action, Policy,
Decision, Human approval, Execution, Evidence, Independent verification, with fail-closed checks (a
tampered ledger fails verification; an invalid token is rejected).

## The through-line
One policy language, one identity model, one tamper-evident ledger, one kill-switch, a first-party
content firewall with a trained classifier, and a GRC surface, applied to every place AI acts. The
runtime authorization and cryptographic evidence are the core and are genuinely wired. The GRC document
surface is real and signed but operator-authored. A meaningful set of governance primitives are built
and tested but not yet in the request path, and this document says which is which.
