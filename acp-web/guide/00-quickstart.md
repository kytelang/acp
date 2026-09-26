# 0. Quickstart: one governed call in five minutes

This is the shortest path from nothing to a real, governed tool call with a signed evidence record.
It uses only the workstation tools, no server, so you can see the shape of the system before you set
up the control plane. When you are ready for the full stack (control plane, console, gateway), follow
the [setup runbook](16-setup.md).

You need the `acp` CLI and `acp-proxy` on your PATH (see [chapter 16](16-setup.md) for the installer),
and any MCP tool server you already run.

## 1. Scaffold a workspace

```sh
acp init acp-demo
```

This writes `acp-demo/policy.yaml`, a starter policy in observe-friendly `default: allow` mode with two
example rules: a spend cap that raises a step-up over a threshold, and a deny on destructive database
operations in `prod`. The ledger at `acp-demo/ledger.db` is created on the first run. Read
[chapter 2](02-policy.md) for the policy DSL.

## 2. Put the proxy in front of your MCP server

`acp-proxy stdio` wraps a local MCP server over stdio: the agent talks to the proxy, the proxy governs
each `tools/call` and forwards it to the real server. Point your agent host (the IDE or agent runner)
at this command instead of the tool server directly:

```sh
acp-proxy stdio \
  --policy acp-demo/policy.yaml \
  --ledger acp-demo/ledger.db \
  --key    acp-demo/signing.key \
  -- your-mcp-server --its --args
```

The `--key` file is generated on first use and is the Ed25519 key the ledger signs its tree head with.
From now on every tool call is authorised against the policy and appended to the signed ledger. If you
start the proxy with no `--policy` or `--policy-dir`, it runs in transparent mode and warns loudly that
nothing is being governed, so an accidental ungoverned run is visible.

## 3. Make a call that gets held

Drive your agent to call a tool the policy gates. With the starter policy, a `payments.charge` over the
cap, or a `db.*` delete in `prod`, is the easy one to trigger. A step-up returns a JSON-RPC
`-32001 approval required` to the agent (it is a hold, not a failure) and opens an approval keyed to the
exact call. The agent re-issues the same call after a human resolves the hold. A deny returns a
structured tool error and never reaches the tool server. See [chapter 11](11-containment.md) for the
full step-up flow and how to resolve a hold.

For a self-contained proxy (no server), the hold sits in the proxy's local approval store next to the
ledger (`acp-demo/ledger.db.approvals`). When you run the full stack, holds and their resolution live
in the control plane and appear in the console Approvals inbox.

## 4. Verify the evidence

The whole point is that you can prove what happened without trusting the store:

```sh
acp verify acp-demo/ledger.db            # re-derive the Merkle tree, check the signed heads
acp export acp-demo/ledger.db > pack.json
acp verify-pack pack.json                # verify a standalone pack on a clean machine
```

`acp verify` needs only the public key stored inside the ledger. Any edit to a recorded decision is
caught. See [chapter 9](09-evidence.md).

## 5. Prove the whole vertical end to end

The repository ships a scripted acceptance that exercises the full spine (agent identity, decision,
human approval, execution, evidence, independent verification) plus the fail-closed checks at each
seam:

```sh
bash demo/vertical/run.sh          # from the repo root; expect 10/10 PASS
```

This is the fastest way to confirm a build behaves before you wire in a control plane.

## Where to go next

- [Chapter 1](01-overview.md) for the architecture and the six-step spine.
- [Chapter 2](02-policy.md) to write real policy, and `acp policy-test` to test it in CI.
- [Chapter 16](16-setup.md) to stand up the control plane, console and gateway as services.
- [Chapter 14](14-operations.md) for operations, monitoring and recovery.
