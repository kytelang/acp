# ACP (Agent Control Plane): Design

The single design document: what we are building, how, and why. Delivery is tracked in
`PLAN.md`, which is organised around this design. (Superseded docs, the old build-spec,
decisions, roadmap, threat-model, workspace, production-readiness, and opportunity files,
are consolidated here and in `PLAN.md`; their long-form history remains in git.)

Doc style: Indian English, plain punctuation, no em dashes.

Status note (2026-09-21): this is the v0 design record and parts are superseded. The current authoritative sources are `docs/design/model-v2.md` (policy model), `docs/design/platform-architecture.md` (platform architecture), and `docs/positioning.md` (scope). Since v0, the content firewall and the GRC lifecycle were built into the product (2026-09-20), the human principal is now verified (not "unverified"), and the workspace has ~19 crates. Where this document disagrees with those, they are current and this is history.

---

## 0. Why this exists (the wedge)

The AI "firewall" (an inline prompt/jailbreak/PII filter in front of an LLM) is already
crowded and being commoditised by hyperscalers, security platforms, and open source. The open,
valuable seam is different: **govern what AI agents actually DO (their tool calls and actions),
and turn every decision into audit evidence a regulator or auditor will accept.** Runtime-
enforcement vendors and GRC/evidence vendors are two separate camps; owning the join between
them, at the agent action boundary, is the wedge.

v0 is one job done well: **stop an agent taking an irreversible or expensive action without a
recorded, provable decision.** The moat is evidence gravity (a verifiable history that
compounds), being the neutral cross-model/cross-cloud standard early, and regulatory depth.

Non-goals in v0 (later reversed on 2026-09-20, when the content firewall was built in): text-level content safety, jailbreak detection, model-output filtering,
governance of agents that never pass through the proxy. We gate what an agent *does*, not what
a model *says*.

---

## 1. System overview

```
        MCP client (agent host: Claude Desktop, IDE, custom)
                          |  MCP (stdio or streamable HTTP)
                          v
        +-----------------------------------------+
        |            acp-proxy (interceptor)      |
        |  transport shim | tools/call intercept  |
        |  policy decide  | approval broker        |
        |  durable spool  | evidence + event emit  |
        +-----------------------------------------+
          | allow        | step-up       | record + emit
          v              v               v
       tool server   approval inbox   acp-server (ledger, policy,
       (bound to     (Slack/Teams/     approvals, verify/export,
        the proxy)    web/PagerDuty)    reporting) + sinks (SIEM/OTel)
```

Two binaries in v0: **`acp-proxy`** (one per agent host; stdio or HTTP) and **`acp-server`**
(control service: policy store, approval broker, evidence ledger, query/export/verify, minimal
web UI). If `acp-server` is unreachable, the proxy applies an explicit **fail-policy**
(fail-closed for gated verdicts; low-impact allow may fail-open by config), always spooling
evidence durably for replay.

Trust-surface principle: everything a customer or auditor must trust (the proxy in their infra,
the crypto, the verifier, the store) is boring, memory-safe, statically linked, and
independently reviewable. That is why the stack is Rust throughout and the young proprietary
stack (kyte/kaidb) is kept out of the v0 trust and enforcement path.

---

## 2. Interception mechanics

MCP is JSON-RPC 2.0 over stdio (proxy launches the tool server as a child, relays
stdin/stdout) or streamable HTTP+SSE (proxy is a reverse proxy). The proxy is transparent for
everything except the decision point.

- **Passthrough verbatim:** `initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`,
  notifications. Byte-identical in/out.
- **Decide on `tools/call`:** extract tool, arguments, session, caller identity.
  - allow -> forward, relay response unchanged.
  - deny -> do not forward; return a structured `isError` naming the rule + a redaction-safe
    rationale (what fired, what would pass).
  - step-up -> park, open approval, return `-32001 approval required` + `approvalId` +
    `retryAfter`; resolved on re-issue (section 4).
  - shadow -> forward, record a would-block without enforcing.

Correctness requirements: never mutate arguments (v0); exact id correlation under concurrency;
streamed responses relayed verbatim, decision made before the first upstream byte; allow-path
adds < 10 ms p95 and never blocks on the network.

**Anti-bypass (decision D10), without these the gate is only advisory:**
- The tool server accepts connections **only from the proxy** (mTLS / proxy-held token /
  private namespace). Else the agent goes out-of-band and skips the gate.
- Upstream TLS is verified (validation/pinning, no cleartext downgrade, documented anchors);
  the proxy's own MITM cert/key handling is specified.
- **Unknown action-bearing methods are denied by default**; the interception layer tracks the
  MCP version it was verified against, so protocol drift is not a silent bypass.
- Resource limits: max message/arg size, per-connection timeout, concurrency caps; fail-closed
  on breach (a hostile agent or tool server cannot OOM/stall the proxy).

---

## 3. Policy

**Two layers (decision D2): YAML authoring surface, Cedar engine.** Humans write a clean YAML
DSL (versioned in the customer's git); `acp policy-compile` lowers it to **Cedar**
(`cedar-policy`, native Rust, formally-verified core), which does the deciding. We never
hand-roll the evaluator; the compiler is our unit-tested code and emits the generated Cedar for
review. A YAML front-end over a verified engine gives both ergonomics and a defensible trust
story. YAML example:

```yaml
version: 1
default: allow            # allow | deny | step_up | shadow
rules:
  - id: cap-spend
    when: { tool: "payments.charge", arg: { amount_cents: { gt: 50000 } } }
    verdict: step_up
    approvers: ["finance-approvers"]
```

Matchers: `eq/ne/in/gt/gte/lt/lte/contains/regex/exists`, glob on tool, `contains_class` (data
class), and the impact score (section 5). Each maps to a Cedar operator; the YAML rule's
`verdict` becomes a `@verdict(...)` annotation on the generated policy.

**Soundness (decision D9), these close real bypasses:**
- **Namespaced context:** untrusted `args` live under an un-spoofable sub-key; proxy-injected
  fields (impact, `env`, `principal_scopes`, class flags) are in a separate namespace the agent
  cannot populate. Reserved-name check at compile time.
- **Typed guards, fail-closed:** a type mismatch (`amount_cents` sent as `"50000"`/`5e4`) never
  silently no-matches into `default: allow`.
- **Verdict precedence:** Cedar returns a set of determining policies; resolution is
  **deny > step_up > shadow > allow** (superseded by model-v2: deny > step_up > allow_with_obligations > allow); ambiguous sets rejected at compile time.
- **Safe entity ids** from the untrusted tool name; **regex** uses a linear-time engine with a
  per-eval bound; **Cedar eval errors are fail-closed + alert** (decision D13), never a
  fall-through.

**Lifecycle:** policy compiled + schema-validated + content-hashed on load; the hash is stamped
into every record. `acp policy-test` diffs verdicts against recorded-call fixtures (CI gate).
Shadow mode is a config switch (ship every policy in shadow first). Proxies pull policy with a
**max-staleness cap** so a partitioned proxy fails safe, not stale.

---

## 4. Human approval (step-up)

Flow: proxy hits step-up -> `POST /approvals` -> fan out to the configured channel
(Slack/Teams/web/PagerDuty/email) -> approver acts -> the agent re-issues the call and the
proxy resolves from the recorded approval. Re-issue (not long-hold) avoids transport/stdio
timeouts; a small host shim auto-retries on `-32001`.

**Integrity (decision D8), closes core-promise breaks:**
- **Single-use:** an approval authorises exactly one forward, atomically consumed (CAS);
  approve/deny/expire is one terminal transition; concurrent re-issues cannot both forward.
- **Caller-bound:** bound to `approvalId + session + principal`, not just the arg hash.
- **One canonical form:** the bytes forwarded, the bytes the human approved, and the bytes
  hashed into evidence are identical; a re-issue that does not canonicalise identically is
  **rejected, not relayed** (closes approve-X-execute-Y TOCTOU).
- **Legal record:** stores the presented-context snapshot the approver saw plus an explicit
  acknowledgement, not just identity + timestamp. TTL is skew-safe (single authority / signed
  absolute expiry).

**The approval UX is an injection surface (R1):** demarcate untrusted content, show the real
tool + impact prominently, never render agent text as chrome; per-sink output encoding (Slack
Block Kit/`mrkdwn`, CSV formula injection).

**Approver operations (R1):** routing, escalation, delegation, out-of-office, reminders, an
approval on-call, defined no-response behaviour, notifying the human driving the agent, queue
caps + `retryAfter` jitter under a step_up burst, and a fallback when the channel is down.

---

## 5. Evidence ledger (the asset)

Every decision writes one **record** that becomes a leaf in the log. The record is not
individually signed and has no `prev_hash` chain: integrity comes from the Merkle root and the
signed tree head (decision D3). The format carries longevity, reproducibility, and outcome
fields (decisions D7/D11/D12):

```json
{
  "schema": 1,
  "seq": 10432, "ts_ms": 1789200012114,
  "hlc": "7ffe:0003:host-7",                 // cross-proxy causal ordering (D12/F11)
  "tool_server_fingerprint": "sha256:...",   // verified executor identity (D12/B5)
  "agent_id": "...", "session_id": "...",
  "principal": { "id": "kamlesh@example.com", "verified": true }, // now verified via OIDC/Entra (supersedes D10 v0)
  "action": { "tool": "payments.charge", "args_hash": "sha256:...",
              "impact": { "level": "high", "taxonomy": "impact@1.3" } }, // D12/D13
  "decision": { "verdict": "step_up", "rule_id": "cap-spend",
                "matched": "context.args.amount_cents > 50000",  // explainable/replayable (D12/E3)
                "policy_hash": "sha256:...", "reason": "amount > 500.00" },
  "provenance": { "algo": {"hash":"sha256","sig":"ed25519"},     // crypto-agility (D7)
                  "evaluator": "cedar-policy@x.y", "compiler": "acp-policy@x.y",
                  "context_derivation": "classifier@a.b, impact@1.3" }, // deterministic (D13/A6)
  "leaf_hash": "sha256:..."
}
```

- **Outcome record (D11/D12):** a decision asserts a verdict, not execution. Each forward emits
  a linked outcome (`forwarded` + upstream status / `not_executed` / `eval_error`), so the
  ledger never implies an action happened; ghost approvals are reconciled.
- **Tamper-evidence (D3):** leaves in an **RFC 6962** Merkle tree (`ct-merkle`, or the hand-
  checked `acp-core::merkle` fallback). A **single writer/leader** extends the head (D6, lease-
  fenced, per-tenant partitioned). The **signed tree head** (`ed25519-dalek`) is signed over the
  STH, not per record, on a defined cadence with a bounded unsigned window. Equivocation is
  blunted by witness/gossip + external anchoring.
- **`acp verify`:** recomputes leaves + root, verifies the STH, and checks a consistency proof
  between two heads (append-only). Catches an edit at the exact leaf and a history rewrite.
- **Durability (D5):** decisions hit a **durable disk-backed spool** before/at forward; gated
  verdicts fail-closed on outage; idempotent ingest (client decision id) means retried batches
  create no duplicate leaves; a dead-letter path stops a poison record blocking replay.
- **Signing/KMS-outage policy (D13):** if heads cannot be signed, decisions still spool, the
  unsigned window is bounded and alarmed, and on recovery everything signs with no divergence.
- **Storage:** `sqlx` + SQLite (v0) / Postgres (multi-tenant), append-only enforced; a separate
  `args_blob` (encrypted, field-level BYOK) so payloads purge while signed decisions survive.
- **Export:** `acp export` produces a signed pack (records + policy versions + public key + STH
  manifest) that verifies standalone with only the public key. Long-term validity: re-anchoring
  and algorithm-agility keep old evidence verifiable as crypto ages.

**Governance-event seam (D14):** in parallel with the record, every decision/approval/break-
glass emits one canonical internal event; SIEM (OCSF/CEF), OpenTelemetry spans, and notifiers
are sinks on that seam (all scrubbed of raw args), designed in now so integrations are sinks,
not rebuilds.

---

## 6. Impact taxonomy and classifiers (MLOps stance, decisions D13/D15)

**Impact is a configurable, per-tenant, versioned taxonomy, not a hardcoded heuristic (D13).**
Named factors (destructive verbs, amount/quantity tiers, wildcard targets, external recipients,
regulated data classes) with per-tenant weights/thresholds, evaluated into the un-spoofable
context; the taxonomy version is stamped into every record. The fail-policy's "high-impact"
notion never keys on agent-influenceable input.

**Classifiers (`pii`, `secret`) are deterministic, versioned rule-sets, not opaque ML models
(D15).** For a trust product this is required so decisions stay reproducible (`acp replay`),
verifiable (derivation feeds the canonical leaf, so it must be deterministic across OS/arch),
explainable (a deny states what fired), and auditable (every version resolves to a model card).
They are advisory on `deny` paths (evasion is expected), never the sole barrier.

**MLOps lifecycle around the rule-sets:** a registry + model cards; a labelled multilingual eval
harness with published precision/recall targets; a CI regression gate; bias/fairness slices;
a standing adversarial-evasion corpus; production drift monitoring; staged/shadow rollout of a
new version before promotion; and the feedback/tuning corpus governed like `args_blob` (no
shadow PII store). Future ML may only sit on a gated path if its inference is pinned and
reproducible, and even then stays advisory on deny.

---

## 7. Identity (v0 minimal, decision D10)

Records carry `agent_id`, `principal`, `session_id`. `principal` comes from the agent-set
`X-ACP-Principal` header, so it is recorded **unverified** and never signed as verified
attribution. A static `principal_scopes` check demonstrates "an agent cannot exceed the human's
authority" without building an IAM. Verified, IdP-backed identity (Okta / Entra Agent ID /
Aembit-class) with delegation chains is v2.4; until then the confused-deputy guard is a
demonstration, described as such.

---

## 8. APIs and interface seams

Internal (proxy -> server): `GET /policy/current` (with `max_staleness`); `POST /decisions`
(idempotent); `POST /outcomes`; `POST /approvals`; `POST /approvals/{id}/consume` (atomic
single-use); `GET /approvals/{id}`; proxy heartbeat (dead-man's-switch, D14/B1).
Operator/UI: `GET /ledger`, `POST /export`, `GET /verify`, signature-verified notifier webhooks.
External: a versioned public REST API + signed, replay-protected webhooks (decision.made,
approval.requested/resolved, policy.changed), under the deprecation policy.
Auth: per-proxy service token + mTLS proxy<->server; SSO/OIDC + RBAC for the console; SCIM for
approver-group lifecycle. Distinct from D10's tool<->proxy binding.

---

## 9. Tech stack and workspace

**Rust everywhere.** `tokio`; `hyper` + `tokio::process` (stdio relay); `rmcp` or a thin
`serde_json` framing layer; `axum` (+SSE); `cedar-policy`; `ed25519-dalek` + `sha2`;
`ct-merkle` (hand-checked `acp-core::merkle` fallback); `sqlx`; `reqwest`; `maud`/`askama` +
htmx; `clap`; `serde`/`serde_json`/`serde_yaml`.

Cargo workspace (repo `acp`, standalone, no proprietary-stack dependency):
```
acp-core     trust core: types, canonical, merkle (RFC 6962), sign seam, blast_radius. Pure, no I/O.
acp-policy   YAML DSL + compiler to Cedar (+ M2: cedar-policy evaluation).
acp-jsonrpc  thin JSON-RPC framing for transparent interception.
acp-proxy    interception proxy: stdio/http, binding (D10), limits, durable spool, evidence client.
acp-server   policy store, approvals (single-use), ledger (single-writer head), notifiers, web UI.
acp-cli      acp: init, verify, export, policy-compile, policy-test, replay.
```
Open source: acp-core, acp-policy, acp-jsonrpc, acp-proxy, acp-cli (Apache-2.0). Commercial:
acp-server. kyte's only honest future home is the read-only reporting dashboard in v1, and only
because evidence is verifiable outside the UI; the approval inbox stays in Rust (enforcement
path).

Build status: skeleton compiles; acp-core Merkle + blast-radius, acp-jsonrpc framing, and the
acp-policy YAML->Cedar compiler are implemented and tested. Everything else is spec + decisions
pending M1-M5 (see `PLAN.md`).

---

## 10. Decisions register (D1-D15)

- **D1** MCP interception: thin JSON-RPC framing, forward verbatim, parse only what is needed.
- **D2** Policy: YAML authoring surface compiling to Cedar; never hand-roll the evaluator.
- **D3** Integrity: `ed25519-dalek` + RFC 6962 Merkle (`ct-merkle`/hand-checked); sign the STH,
  not per record; JCS canonical bytes; leaf/node domain separation.
- **D4** Templating: `maud` for the approval inbox.
- **D5** Record-before-forward durability: disk-backed spool; per-verdict fail-closed/open;
  backpressure; data-loss boundary.
- **D6** Single-writer log: leader extends the head; lease-fenced split-brain; per-tenant shard.
- **D7** Longevity + reproducibility record format: algorithm ids; evaluator/compiler/context-
  derivation versions; re-anchoring fields.
- **D8** Approval integrity: single-use, caller-bound, one canonical form, presented-context+ack.
- **D9** Policy-evaluation soundness: namespaced context, typed fail-closed guards, verdict
  precedence, safe entity ids, regex bounds, classifiers advisory-only.
- **D10** Enforcement binding / anti-bypass: tool bound to proxy; upstream TLS; deny unknown
  action methods; principal recorded unverified.
- **D11** Evidence = intent + linked outcome; idempotent ingest; dead-letter spool.
- **D12** Record-format additions: hlc, tool-server fingerprint, eval-error outcome, impact-
  taxonomy version, matched condition. Must exist from day one.
- **D13** Enforcement-contract additions: Cedar eval-error fail-closed; KMS-outage policy;
  deterministic context derivation; configurable impact taxonomy.
- **D14** Interface seams: canonical governance-event seam; proxy<->server heartbeat; feedback
  corpus inside the args_blob governance boundary.
- **D15** MLOps: classifiers + impact are deterministic, versioned rule-sets, not opaque ML;
  full eval/regression/registry/drift lifecycle; future ML only if pinned + reproducible.

---

## 11. Threat model (summary)

Trust boundaries: agent<->proxy (agent is untrusted input, including prompt-injection);
proxy<->tool (tool may be hostile); proxy<->server; server<->approver; server<->store+key;
operator/insider. Design intent: an exported pack is verifiable independent of the UI, the
store, and even the running server.

Guarantees (given the signing key is safe): no record can be silently edited or deleted
(`acp verify` catches it at the exact leaf); no history silently rewritten (consistency proof);
exports verify with only the public key; the exact policy version and approver of every gated
action are provable.

Key residual/known risks and their mitigations:
- **Signing-key theft** (T6) collapses tamper-evidence until external anchoring (Rekor) lands;
  KMS/HSM + anchoring are H0.
- **A compromised/silent proxy** (T7): mitigated by open-source review, dead-man's-switch
  (D14/B1), synthetic canaries, and supply-chain-verified proxy releases.
- **Approval attacks** (T13-T16) closed by D8 (single-use, caller-bound, canonical binding) and
  injection-safe rendering.
- **Policy-eval attacks** (T17-T21) closed by D9 (namespacing, typed guards, precedence, entity
  safety, non-agent-influenceable fail-policy).
- **Bypass/MITM/drift** (T22-T25) closed by D10.
- **Evidence-vs-reality** (T26-T27) closed by D11/D6 (outcome records, idempotent ingest,
  single-writer head, equivocation defence).
- **Argument confidentiality** (T8): encryption-at-rest + BYOK + redaction (H0); no redaction in
  the earliest v0.
- **Identity honesty** (T11): the confused-deputy guard is a demonstration until IdP-backed
  (v2.4); never described as strong enforcement.

Mitigations are design intent until implemented and tested; `PLAN.md` acceptance criteria track
that.

---

## 12. What v0 does and does not promise

Does: gate every `tools/call`, hold high-impact actions for human approval, and produce a
signed, independently-verifiable evidence log with a reproducible, explainable decision record.

Does not (v0): argument redaction (H0 for regulated data), non-MCP interception (v2), regulatory
control mappings in the export (v1), multi-tenant SaaS (v1), strong (IdP-backed) identity (v2),
protection against signing-key theft before anchoring (H0), or governance of un-proxied agents
(v2 discovery). Production readiness is a separate, higher bar than feature-completeness; see the
hardening gates H0/H1/H2 in `PLAN.md`.
