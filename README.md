# acp - Agent Control Plane

Govern what AI agents are allowed to *do*, and turn every decision into audit evidence a
regulator will accept. v0 is a transparent MCP proxy that gates every `tools/call`, holds
high-impact actions for human approval, and writes a signed, RFC 6962-verifiable evidence
log.

Rust everywhere. The trust surface (proxy, crypto, verifier, store) is boring, memory-safe,
and independently reviewable. See `docs/DESIGN.md` (design, decisions D1-D15, threat model) and `docs/PLAN.md` (delivery plan v0-v3).

## Crates
- `acp-core`    - trust core: types, verifiable log (RFC 6962), signing seam, blast-radius. Pure, no I/O.
- `acp-policy`  - policy authoring: the YAML DSL and its compiler to Cedar (the engine).
- `acp-jsonrpc` - thin JSON-RPC framing for transparent interception.
- `acp-proxy`   - the interception proxy (stdio + HTTP).
- `acp-server`  - policy store, approval broker, evidence ledger, reporting.
- `acp-cli`     - `acp` CLI: init, verify, export, policy-compile, policy-test.

## Policy: YAML surface, Cedar engine
Humans author policy in YAML (`fixtures/policies/sample.yaml`); `acp policy-compile` lowers
it to Cedar (`fixtures/policies/sample.generated.cedar`), which the formally-verified
`cedar-policy` engine evaluates. We never hand-roll the evaluator.

```
cargo run -p acp-cli -- policy-compile fixtures/policies/sample.yaml
```


## Quickstart (worked example)

```
# 1. Install (build from source)
sh install.sh                       # puts acp + acp-proxy in ~/.acp/bin

# 2. Scaffold a workspace with a sample policy
acp init demo                       # writes demo/policy.yaml (a step-up + a prod-delete deny)

# 3. Run the proxy in front of your MCP server, recording evidence
acp-proxy stdio --policy demo/policy.yaml --ledger demo/ledger.db -- <your-mcp-server>

# The sample policy holds `payments.charge > 500.00` for human approval. When the agent hits it,
# it gets `-32001 approval required`. A human approves out of band:
acp approvals demo/ledger.db.approvals            # list pending, copy the id
acp approve   demo/ledger.db.approvals <id>       # approve (Slack/web inbox is v1)

# The agent re-issues the identical call and it is now forwarded, exactly once.

# 4. Prove it to an auditor, from the public key alone
acp verify demo/ledger.db                         # OK: verifies
acp export demo/ledger.db > pack.json             # signed, self-verifying evidence pack
acp verify-pack pack.json                          # OK: verifies standalone
```

HTTP transport: `acp-proxy http --policy demo/policy.yaml --addr 127.0.0.1:8080 --upstream https://your-mcp-endpoint`.

Safe rollout: add `--shadow` to record what *would* be blocked while enforcing nothing, until you trust the policy.

## Build and test
```
cargo build --workspace
cargo test  --workspace      # trust suite (tamper + rewrite), transparency, compiler, blast-radius
```

## Status
Skeleton. Design decisions D1-D15 are in `docs/DESIGN.md` (D5-D7 architectural; D8-D11 the v0-fix correctness cluster; D12-D15 record-format/enforcement/interface/MLOps from deep review). Implemented and tested: `acp-core` merkle + blast-radius, `acp-jsonrpc` framing,
and the `acp-policy` YAML->Cedar compiler. Stubbed for M1-M5: transports, the `cedar-policy`
evaluation wiring, sqlx ledger, Ed25519 signing backend, approvals, and web UI
(see `docs/PLAN.md`).

## Licence
`acp-core`, `acp-policy`, `acp-jsonrpc`, `acp-proxy`, `acp-cli`: Apache-2.0. `acp-server`: commercial.
