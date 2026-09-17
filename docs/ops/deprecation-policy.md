# Versioning and deprecation policy (X.6)

ACP produces evidence that must stay interpretable for years, often longer than any single version
of the product lives. That makes deprecation a correctness concern, not just a courtesy. This policy
fixes what we version, how long each surface is supported, and the one guarantee that overrides
everything else: old evidence must remain verifiable and interpretable after any change.

## What is versioned

Four surfaces carry explicit versions, and a change to any of them follows this policy:

- The policy DSL (the YAML authoring surface and its compile to Cedar).
- The evidence record format (the `schema` field on every record).
- The wire and HTTP APIs (JSON-RPC interception contract, server endpoints, webhooks).
- The classifier and impact-taxonomy versions stamped into evidence provenance.

## Support windows

- Record format: supported indefinitely for reading. A reader for schema N must keep working for
  the life of the product. New writers may emit schema N+1, but `verify`, `export`, and `replay`
  continue to parse every earlier schema. We never drop read support for a record format that
  exists in any customer ledger.
- Policy DSL: a deprecated construct is supported for at least 18 months and two minor releases
  after deprecation is announced, with a compiler warning naming the replacement throughout.
- APIs: a deprecated endpoint or field is supported for at least 12 months after its replacement
  ships, served in parallel, with the sunset date in the response deprecation header.
- Classifiers and taxonomies: superseded versions are never deleted, because evidence references
  them by version. A record that says it was classified by `pii@1.2` must always be explainable by
  fetching `pii@1.2`, even after `pii@2.0` is the default.

## The overriding guarantee

No change to any surface may make previously written evidence unverifiable or uninterpretable. In
practice this means: the leaf-hash and signature algorithms are named in each record (crypto-agility
by design, so a second scheme can be introduced without invalidating old records), the record
carries the evaluator, compiler, and context-derivation versions that produced it, and every
historical policy hash and classifier version stays resolvable. If a proposed change cannot honour
this, it is not shipped as a change; it is shipped as a new versioned surface alongside the old one.

## How a deprecation runs

1. Announce in the release notes and, for APIs, in a response deprecation header with a sunset date.
2. Keep the old surface working for its full window, with a warning that names the replacement.
3. Publish a migration note in the versioned docs with a before-and-after example.
4. Remove only after the window closes, and only for writers. Readers for evidence formats are
   never removed.

## Sandbox and sample policies

A trial or sandbox always runs the current supported version and ships with the sample-policy
library so a new user can see a working, current policy without reading the whole reference. The
sample library is versioned with the DSL and updated in lockstep with any deprecation.
