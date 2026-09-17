# Performance model and targets (C1)

This note fixes the numeric performance targets ACP commits to, the model behind them, and how
each is checked. The point is to make performance a gate, not a hope: every number here has either
an automated check today or a named load test that must run before the matching hardening gate.

## The cost model

An intercepted tool call passes through a fixed pipeline: parse the JSON-RPC frame, derive the
action context (classifiers plus impact taxonomy), evaluate the policy (Cedar authorisation),
write the decision to the durable spool (fsync), append it to the Merkle ledger, and forward or
reply. The two costs that grow with load are the policy evaluation (bounded by policy size, not by
traffic) and the ledger append (bounded by tree height, which is logarithmic in record count).
Everything else is constant per call.

Because the ledger is an append-only Merkle log, an inclusion proof is O(log n) hashes and a
consistency proof between two heads is also O(log n). Neither `verify` nor `export` needs to hold
the whole ledger in memory: they stream leaves in sequence order.

## Targets

| Metric | Target | Basis | Checked by |
| --- | --- | --- | --- |
| Allow-path decision latency | under 4 ms/call on a dev box, under 1 ms in release | Cedar authorise plus context build; no per-call recompile | `acp-policy` perf gate test (C2), release load run |
| Policy build (compile to Cedar) | under 50 ms | one-off per policy load, not per call | `acp-policy` perf gate test (C2) |
| Records ingest | 5,000 records/sec/core sustained | spool fsync batched, single-writer ledger | load run before H0.11 |
| `verify` over 10M records | under 60 s | streamed O(n) hash walk | load run before H0.11 |
| `verify` over 100M records | under 15 min | same walk, larger n | load run before H2.1 |
| `export` a day of records | under 30 s | streamed leaves plus one STH | load run before H0.11 |
| Approval-queue resolution | p95 under the policy TTL | human-bound, capped and jittered | tracked as an SLO (C-series) |

## What trips a regression

The C2 gate runs on every merge and fails CI if the allow-path decision or the policy build
crosses its committed budget. The budgets carry roughly 5x headroom over observed timings, so
normal machine variance never flakes them, but an order-of-magnitude regression (an O(n) blow-up,
an accidental per-call policy recompile, a synchronous fsync moved onto the hot path) is caught
before it ships. The large-ledger `verify`/`export`/ingest numbers are validated by the named load
runs listed above, which are prerequisites of their hardening gates, not of every merge.

## Re-baselining

When a target is changed deliberately (new hardware baseline, a new algorithm), update the budget
in the C2 test and the row here in the same change, with a one-line reason in the commit. A silent
budget bump is treated as a regression that was waved through.
