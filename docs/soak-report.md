# ACP scale and soak report (R8)

This is the method and the measured result of the ACP scale + soak drill. It is reproducible with one
command; the numbers below are from a local developer machine (macOS, Apple silicon, release build) and
are a floor, not a datacentre benchmark. Re-run in the target environment to get environment-specific
figures.

## How to reproduce

```
DUR=6 CONC=32 TTL=3000 bash scripts/soak.sh
```

The drill is self-contained: it builds the release binaries, starts mock upstreams, and runs three
parts. It exits non-zero if any check fails. The load driver is `scripts/loadtest.py` (a duration-based
concurrent HTTP driver with `--body mcp` for the proxy and `--body chat` for the gateway), reporting rps
and p50/p95/p99 latency and the status-code distribution.

## Part 1: MCP proxy under sustained load

Concurrent `tools/call` frames through `acp-proxy` (http transport) to a mock MCP upstream, for the full
policy-enforcement path (decision, screening, forwarding).

- 32 concurrent clients, 6 seconds.
- ~29,500 requests, all 200. Throughput about 4,900 rps.
- Latency: p50 5.2 ms, p95 10.6 ms, p99 37.4 ms.
- Error rate: 0 (no connection errors, no 5xx).

## Part 2: LLM gateway under sustained load

Concurrent chat/completions through `acp-gateway` (the reverse-proxy PEP) to a mock LLM upstream.

- 32 concurrent clients, 6 seconds.
- ~21,700 requests, all 200. Throughput about 3,400 rps.
- Latency: p50 4.8 ms, p95 32.1 ms, p99 101.6 ms.
- Error rate: 0.

Both PEPs shed with 503 (not 5xx) above their concurrency cap; the driver treats 503 as governed
back-pressure, and a 0 (connection error) or a non-503 5xx as a failure signal. None were seen here.

## Part 3: two-replica control-plane failover drill

Two `acp-server` replicas (nodeA, nodeB) on one shared store, with the HA leader lease enabled (ttl
3000 ms). The drill:

1. Confirms exactly one leader at steady state (the split-brain guard): nodeA led, nodeB followed. The
   shared-store fencing token prevents two leaders.
2. Registers app records on the leader, confirms they are visible through the survivor (shared store).
3. Kills the leader process (SIGKILL) under that write load.
4. Measures how long the survivor takes to acquire leadership: about 2.7 seconds, bounded by the lease
   ttl (3000 ms), as expected. Production ttls are larger; recovery scales with the ttl.
5. Confirms control state survived the failover (all 5 app records still present) and that writes resume
   on the new leader (a post-failover registration succeeds).

Result: no split-brain, no lost liveness or control state, and bounded recovery (about one lease ttl).

## Interpretation and limits

- These figures are single-node throughput on a laptop with mock upstreams; real upstream latency
  dominates in production, so treat the PEP overhead (the p50s here) as the meaningful ACP cost.
- The failover drill uses a deliberately short lease ttl so it finishes quickly. Recovery time tracks
  the ttl: choose it against your tolerance for a leaderless window versus false failovers under a
  network blip.
- Not covered here and left for an environment-specific run: multi-hour endurance, a real Postgres/MySQL
  shared store under concurrent writers (this drill uses SQLite), and a network-partition (as opposed to
  a process kill) partition test. The shakedown drill (`scripts/shakedown.sh`) covers evidence integrity
  and backup/restore.
