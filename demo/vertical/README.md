# End-to-end governance vertical

`run.sh` is a one-command acceptance test for the whole ACP governance vertical:

Agent -> Action -> Policy -> Decision -> Human approval -> Execution -> Cryptographic evidence -> Independent verification

Run it from the repo root (build the debug binaries first):

```sh
cargo build -p acp-cli -p acp-proxy --bin mock-mcp-server
bash demo/vertical/run.sh
```

It asserts, and prints PASS/FAIL for, each link plus the fail-closed seams:

- Agent identity: a registered agent with a verified, un-spoofable token.
- The identity is verified inside the enforcement path.
- Decision: a destructive action is DENIED; a payment is held for STEP-UP.
- Human approval: a separate operator approves the held action.
- Execution: the re-issued, now-approved action is forwarded and executed.
- Evidence: every decision is written to the tamper-evident ledger.
- Independent verification: the ledger and a standalone export pack both verify with the public key alone.
- Fail-closed: a tampered ledger fails verification (after the append-only triggers are removed to simulate raw DB access).
- Fail-closed: an invalid agent token is not accepted as the agent.

This is the bulletproof spine. The additional capabilities (intent/trajectory governance, data-boundary enforcement, HTTP/API interception, continuous adversarial testing, regulatory evidence mapping) layer on top and have their own tests and demos.
