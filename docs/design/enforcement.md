# Making enforcement unavoidable and fail-closed (model v2, phase 4b)

Governance is only real if an agent cannot skip it. This note states exactly what ACP guarantees today, how, and where the boundary of that guarantee lies. It is deliberately honest: some of "unavoidable" is a deployment property, not something a proxy can assert alone.

## Fail-closed when ACP is down

- stdio transport: the proxy SPAWNS the tool server as a child and owns its stdio (kill_on_drop). If the proxy dies, the child dies with it. There is no tool server left running for the agent to reach out of band, so "proxy down" means "no tool service". Unavoidability here is structural.
- HTTP transport: the proxy IS the endpoint the agent is configured to call. If the proxy is down, the agent's requests are refused; there is no service. Fail-closed by default.
- Evidence durability: when the tamper-evident ledger cannot record a decision, the proxy denies rather than forwarding an unrecorded call, unless `--fail-open` is set. `--fail-open` is for controlled testing only and now logs a prominent warning at startup, because it trades the fail-closed guarantee for availability.

## Unavoidable when ACP is up

The remaining threat is an agent that reconfigures itself to talk to the tool server directly, bypassing the proxy.

- stdio: already closed. The agent's only handle to the server is the child the proxy spawned; it has no address or credential to reach it otherwise.
- HTTP: nothing structurally stops an agent pointing at the tool server's URL instead of the proxy. ACP closes this with an enforcement attestation:
  - The proxy holds an Ed25519 signing key (`--enforcement-key <seed>`) and stamps a short-lived, signed token on every forwarded request (`x-acp-enforcement` header). The token is `<issued_ms>.<session>.<sig>`, signed over `<issued_ms>.<session>` (see `acp_core::attest`).
  - The tool server, or a thin guard in front of it, verifies the token against the proxy's pinned public key and rejects any request without a fresh, valid one (`acp_core::attest::verify(pubkey, token, now, max_age)`).
  - The agent never holds the signing key, so it cannot forge the proof and cannot reach a guarded server un-governed. A captured token cannot be replayed past `max_age`.

This is the honest shape of the guarantee: ACP provides the mechanism (stamp + verify), and the deployment makes it unavoidable by putting the guard in front of the tool server. For a customer who controls their tool server (or fronts it with the guard), the proxy becomes the only path. For a third-party server we do not control, unavoidability reduces to the stdio structural guarantee or network isolation.

## Deploying the HTTP guard

1. Generate a 32-byte seed; run the proxy with `--enforcement-key <seed-hex>`. It logs the public key to pin.
2. In front of the tool server, verify every request:
   - read the `x-acp-enforcement` header;
   - `acp_core::attest::verify(pinned_pubkey, header, now_ms, max_age_ms)`;
   - reject (401) if absent or invalid.
3. Ensure the tool server accepts connections only from the guard (loopback bind, network policy, or mTLS), so the header cannot simply be added by a direct caller.

## What this is not

- It does not stop an operator with local admin rights who can read the proxy's key or rewrite the guard. Key protection is the deployment's responsibility (file permissions, HSM via `acp-hsm`).
- It does not make third-party hosted tool servers verify the token; only a server or guard you control can.
- It is transport-level proof of governance, not content inspection. What the call is allowed to do is still the policy layer's job.
