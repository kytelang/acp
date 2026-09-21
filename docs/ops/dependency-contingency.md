# Young-dependency EOL contingency (A7)

One trust-critical dependency is young enough that its long-term maintenance is a real risk:
`ct-merkle` (the RFC 6962 transparency-log primitives). If it is abandoned, ACP must not be stranded.
This note is the documented fallback and the trigger that keeps us able to move.

## The exposure

- `ct-merkle`: supplies Merkle inclusion and consistency proof logic. It sits directly under the
  evidence-integrity guarantee, so a bug or an EOL here is a trust problem, not just a build problem.

MCP is not on this list, deliberately. ACP does not depend on an external MCP-types crate: the MCP
JSON-RPC framing is a first-party crate, `acp-jsonrpc` ("thin JSON-RPC framing for transparent MCP
interception"). There is no third-party MCP library to fork or vendor, so the interception path
carries no young-dependency risk from the protocol side. New action-bearing MCP methods are handled by
extending `acp-jsonrpc`, which we own.

## Standing fallback: acp-core::merkle

ACP already carries its own RFC 6962 Merkle implementation in `acp-core::merkle`, independent of
`ct-merkle`. It is not dead code kept for insurance: it is build-tested and its output is checked
against the same known-answer vectors as the primary path (the A2 determinism requirement). This
means the fork plan for `ct-merkle` is not a future project. The replacement already exists, is
exercised in CI, and produces identical roots and proofs. If `ct-merkle` is abandoned, we cut over
to `acp-core::merkle` behind the same interface, and the A2 cross-implementation test is what proves
the cut-over changed no hashes.

## What CI guarantees today

- `acp-core::merkle` builds and passes the A2 known-answer and cross-implementation tests on every
  merge, so the `ct-merkle` fallback is always ready, not theoretical.
- Dependency scanning (cargo-audit in CI) flags an unmaintained or vulnerable advisory on the crate,
  which is the trigger to execute the fallback above.

## Trigger and owner

The trigger is a maintenance-status signal: an RUSTSEC unmaintained advisory, a year without releases
against open security issues, or an incompatible ecosystem move. When the trigger fires, the owner
executes the standing fallback (cut over to `acp-core::merkle`) and records the change in the
meta-audit log, since it touches the trust core.
