# Evidence capacity, cost, and tiering model (C3)

ACP produces evidence for years and must keep it verifiable the whole time without the storage
bill growing without bound. This note sets the capacity model, a three-year cost projection
method, and the hot/cold/archive tiering rules, with one hard constraint: tiering must never move
data in a way that violates a mandated retention floor, and `verify`/`export` must still succeed
against archived segments.

## What we store per decision

Each decision writes two things: a small canonical record (a leaf in the Merkle log: ids, tool
name, verdict, rule id, impact, hashes, timestamps, HLC) and, separately, the argument blob keyed
by its hash. The record is bounded and predictable, on the order of a few hundred bytes. The
argument blob is customer-shaped and can be large; it is the part that dominates cost and the part
that redaction, BYOK, and right-to-erasure act on. Records and blobs are stored in separate tables
precisely so they can be retained and tiered on different schedules.

## Three-year projection method

Project cost from three inputs a tenant can estimate: decisions per day, mean argument-blob size,
and the retention floor for their sector. Records volume is decisions times record size times
retention days. Blob volume is decisions times mean blob size times the blob-retention window
(which may be shorter than the record retention, since redaction can drop blobs while keeping the
verifiable record). Add the Merkle overhead (one hash per node, so under 2x the leaf count) and a
signed tree head per checkpoint interval. Multiply each volume by the per-tier unit price. The
worked template lives with the go-to-market pricing material, not here; this note fixes the method
so two people compute the same number.

## Tiers

- Hot: recent records and blobs on fast storage, serving live approvals, reporting, and replay.
- Cold: older records and blobs on cheaper storage, still directly readable for audit and export
  with higher latency.
- Archive: sealed, immutable segments (object-lock class storage) holding records and, where still
  required, blobs. Cheapest, slowest, and the tier retention floors are enforced against.

A segment moves to a colder tier by age, never by deleting anything a retention floor still covers.
The floor is per sector (for example SEC 17a-4, FINRA, MiFID minimum-retention) and is checked
before any tier move or purge; a move that would drop below the floor is refused, the same way the
purge path already refuses to violate a mandated minimum.

## Verifiability across tiers

Tiering must not weaken the audit story. Two properties hold on every tier, including archive:

- `verify` succeeds against an archive-tier-only segment. The Merkle structure is self-contained
  per segment plus the chain of signed tree heads, so a verifier needs the segment and the head,
  not the hot store.
- `export` produces a pack whose figures re-derive from the exported records and STH alone, with
  no dependency on the live database.

This is validated by a test that seals a segment, drops it to archive-only, and runs `verify` and
`export` against it with the hot store removed. That test is a prerequisite of the H2.1 scale gate.

## The one rule

Cheaper storage is always allowed; losing verifiability or dropping below a retention floor never
is. Every tiering change is evaluated against the floor first and the bill second.
