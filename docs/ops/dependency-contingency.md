# Young-dependency EOL contingency (A7)

Two trust-critical dependencies are young enough that their long-term maintenance is a real risk:
`ct-merkle` (the RFC 6962 transparency-log primitives) and `rmcp` (the MCP protocol types). If
either is abandoned, ACP must not be stranded. This note is the documented fork-or-vendor plan and
the standing fallback that keeps us able to move.

## The exposure

- `ct-merkle`: supplies Merkle inclusion and consistency proof logic. It sits directly under the
  evidence-integrity guarantee, so a bug or an EOL here is a trust problem, not just a build
  problem.
- `rmcp`: supplies MCP JSON-RPC types and transport glue. It sits on the interception path. An EOL
  here is a compatibility problem: new MCP methods would stop being modelled.

## Standing fallback: acp-core::merkle

ACP already carries its own RFC 6962 Merkle implementation in `acp-core::merkle`, independent of
`ct-merkle`. It is not dead code kept for insurance: it is build-tested and its output is checked
against the same known-answer vectors as the primary path (the A2 determinism requirement). This
means the fork plan for `ct-merkle` is not a future project. The replacement already exists, is
exercised in CI, and produces identical roots and proofs. If `ct-merkle` is abandoned, we cut over
to `acp-core::merkle` behind the same interface, and the A2 cross-implementation test is what proves
the cut-over changed no hashes.

## Fork-or-vendor plan for rmcp

`rmcp` has no in-repo twin, so its contingency is a vendor-in plan rather than a standing fallback:

1. The interception surface depends on a thin internal adapter, not on `rmcp` types spread through
   the codebase, so the blast radius of replacing it is one module.
2. If `rmcp` is abandoned, vendor the last good version into the tree under a pinned, audited copy,
   and take over maintenance of only the subset ACP uses (the JSON-RPC framing and the method set
   we intercept), not the whole crate.
3. The MCP-version-drift process (a tracked obligation) is what tells us when a new action-bearing
   method appears, so a vendored copy does not silently fall behind the protocol.

## What CI guarantees today

- `acp-core::merkle` builds and passes the A2 known-answer and cross-implementation tests on every
  merge, so the `ct-merkle` fallback is always ready, not theoretical.
- Dependency scanning (cargo-audit in CI) flags an unmaintained or vulnerable advisory on either
  crate, which is the trigger to execute the matching plan above.

## Trigger and owner

The trigger for either plan is a maintenance-status signal: an RUSTSEC unmaintained advisory, a
year without releases against open security issues, or an incompatible ecosystem move. When the
trigger fires, the owner executes the standing fallback (ct-merkle) or the vendor-in (rmcp) and
records the change in the meta-audit log, since it touches the trust core.
