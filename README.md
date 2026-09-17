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
