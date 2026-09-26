# 5. Forward and TLS interception

`acp-intercept` governs **arbitrary HTTP and API traffic** from agents, IDEs and browsers. It is a
forward proxy driven by a signed endpoint registry: for each destination it matches a rule and either
tunnels, inspects, or blocks. On managed devices it can also terminate TLS with an ACP certificate
authority to inspect body-bearing HTTPS endpoints.

## The endpoint registry

The registry maps destinations (by host, SNI or path) to actions:

- **`Pass`** tunnels the connection untouched.
- **`Block`** refuses it.
- **`InspectPrompt`** / **`GovernToolCall`** decrypts (where a CA is configured) and applies the
  content firewall and policy to the body.
- **`DlpOnly`** applies data-boundary checks without full governance.

The interceptor loads its rule set from a YAML file (`--rules`). You can sign a rule set with `acp
intercept sign` for tamper-evident distribution; note that the running interceptor loads the YAML
rules today (signature verification at load is not yet wired into the binary). A precedence-aware
least-inspection gate decides when to decrypt, so you only break TLS where a rule genuinely needs the
body.

## Generating a PAC file

Hand a proxy auto-config file to managed browsers and agents so their traffic flows through the
interceptor:

```sh
acp intercept pac endpoints.yaml --proxy 127.0.0.1:8890 > acp.pac
```

## TLS interception on managed devices

To inspect body-bearing HTTPS, generate an ACP CA and distribute its certificate to the managed
fleet:

```sh
acp-intercept gen-ca            # writes the ACP CA cert and key
acp-intercept --listen 127.0.0.1:8890 --ca-cert ca.pem --ca-key ca.key --rules endpoints.yaml
```

With a CA configured, the interceptor mints per-host leaf certificates on the fly, terminates the
client TLS, inspects the decrypted body with the content engine, and re-originates TLS upstream.
Certificate pinning and HTTP/2 handshake failures are detected and reported honestly rather than
silently passed, so you can see where interception is not possible.

Without a CA it still enforces block and pass at the CONNECT layer and inspects plain HTTP, it just
does not decrypt.

## Feeding rules from discovery and enrolment

You do not hand-write the registry. Discover shadow-AI endpoints, enrol dispositions for them, then
compile the enrolment into an interception registry:

```sh
acp discover egress.log                         # classify ungoverned AI endpoints
# register endpoints from the console AI Endpoints page or POST /endpoints/register
acp intercept from-enrollment enroll.json > endpoints.yaml
```

See [chapter 12](12-grc.md) for discovery and enrolment.

## SSRF hardening

The interceptor is where outbound destinations are decided, so it is the right place to block
server-side request forgery. An egress allowlist that hard-blocks loopback, private, link-local and
cloud-metadata targets is implemented and tested (`acp_core::egress`), and the same evaluator backs
the egress canary (`acp canary-egress`). Honest status: wiring that allowlist into the interceptor's
outbound dial path is tracked work, not yet on by default; today the canary uses it to detect a
reachable target, and the block-at-CONNECT rules are the enforced control.
