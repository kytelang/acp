# 5. Forward and TLS interception

`acp-intercept` governs **arbitrary HTTP and API traffic** from agents, IDEs and browsers. It is a
forward proxy driven by the governed endpoint set from the control plane: for each destination it
matches a rule and either tunnels, inspects, or blocks. On managed devices it can also terminate TLS
with an ACP certificate authority to inspect body-bearing HTTPS endpoints.

## The endpoint registry

The registry maps destinations (by host, SNI or path) to actions:

- **`Pass`** tunnels the connection untouched.
- **`Block`** refuses it.
- **`InspectPrompt`** / **`GovernToolCall`** decrypts (where a CA is configured) and applies the
  content firewall and policy to the body.
- **`DlpOnly`** applies data-boundary checks without full governance.

The interceptor pulls its rules from the control plane with `--registry-url <server>`: it fetches
`GET /intercept/rules`, which the server derives from the endpoints operators enrol on the console AI
Endpoints page (govern becomes inspect or govern-tool-call, block becomes block, accept-risk becomes
pass). It refreshes on an interval (`--refresh-secs`, default 30), so a change made in the console
takes effect without touching the workstation. For air-gapped or offline use, `--rules <file>` loads
a local YAML registry instead (and is the fallback if the control plane is unreachable at startup); a
rule set can be signed with `acp intercept sign` for tamper-evident distribution. A precedence-aware
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
# rules from the control plane (recommended); --rules <file> is the offline alternative
acp-intercept --listen 127.0.0.1:8890 --ca-cert ca.pem --ca-key ca.key --registry-url http://<host>:8787
```

With a CA configured, the interceptor mints per-host leaf certificates on the fly, terminates the
client TLS, inspects the decrypted body with the content engine, and re-originates TLS upstream.
Certificate pinning and HTTP/2 handshake failures are detected and reported honestly rather than
silently passed, so you can see where interception is not possible.

Without a CA it still enforces block and pass at the CONNECT layer and inspects plain HTTP, it just
does not decrypt.

## Feeding rules from discovery and enrolment

You do not hand-write the registry. Discover shadow-AI endpoints, then enrol a disposition for each
from the console AI Endpoints page (or `POST /endpoints/register`). An interceptor started with
`--registry-url` picks those up automatically on its next refresh. For an offline build, compile a
stored enrolment log into a local YAML registry instead:

```sh
acp discover egress.log                         # classify ungoverned AI endpoints
# enrol endpoints from the console AI Endpoints page or POST /endpoints/register (the interceptor then
# pulls them via --registry-url); or, for offline use, build a local file:
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

## A browser extension for managed Chromium

For managed browsers you can ship a small Chromium MV3 extension instead of hand-distributing a PAC.
It installs the same proxy auto-config and, in addition, badges a tab with `ACP` when it is on a
governed AI endpoint, so users can see the interaction is monitored:

```sh
acp intercept extension endpoints.yaml \
  --proxy 127.0.0.1:8890 \
  --out acp-guard-extension \
  [--catch-all]
```

This writes `manifest.json`, `background.js` and a `README.md` into the output directory (default
`acp-guard-extension/`). The manifest declares the `proxy`, `tabs`, `storage` and `webNavigation`
permissions; the service worker applies the generated PAC on install and startup, and badges governed
tabs based on the host list derived from the registry. `--catch-all` routes everything (not only the
matched hosts) through the interceptor, the same switch as `acp intercept pac`.

Load it for development from `chrome://extensions` (enable Developer mode, then Load unpacked). For a
fleet, package it and push it with an enterprise policy (`ExtensionInstallForcelist`), and install the
ACP CA on the device first so TLS interception works. Regenerate the extension whenever the endpoint
registry changes so the PAC and the badge list stay in sync. This is a starting scaffold and has not
been run-verified in a browser here; treat it as the wiring, to be validated against your managed
browser build.

## Suggesting rules from observed traffic

You do not have to hand-write the registry from scratch. Point `acp intercept suggest` at a file of
observed egress endpoints (one per line) and it classifies the shadow-AI destinations and emits a draft
registry with a `flag-and-pass` default, ready to review before you enforce:

```sh
acp intercept suggest observed.txt                      # draft registry as YAML on stdout
acp intercept suggest observed.txt --governed known.txt # exclude what is already governed
acp intercept suggest observed.txt --key <32-byte-hex>  # emit a signed JSON registry instead
```

With `--governed` it drops endpoints you already cover, so the suggestion is only the newly-seen ones.
With `--key` it prints a signed registry (the same signed form as `acp intercept sign`) for
tamper-evident distribution; without a key it prints reviewable YAML. This closes discover to enrol from
real traffic: run `acp discover` to see what is ungoverned, then `acp intercept suggest` to turn it into
rules. See [chapter 12](12-grc.md) for discovery and enrolment.
