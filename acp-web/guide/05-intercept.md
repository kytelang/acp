# 5. Forward and TLS interception

`acp-agent firewall` governs **arbitrary HTTP and API traffic** from agents, IDEs and browsers. It is
the `firewall` capability of the [workstation agent](01-overview.md): a forward proxy (plus the content
firewall) driven by the governed endpoint set from the control plane. For each destination it
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
acp-agent firewall gen-ca       # writes acp-ca.pem and acp-ca-key.pem (0600)
# rules from the control plane (recommended); --rules <file> is the offline alternative
acp-agent firewall --listen 127.0.0.1:8890 --ca-cert acp-ca.pem --ca-key acp-ca-key.pem --control-plane http://<host>:8787
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
acp discover purview-export.jsonl --from purview   # import an endpoint-DLP / CASB export instead
# enrol endpoints from the console AI Endpoints page or POST /endpoints/register (the interceptor then
# pulls them via --registry-url); or, for offline use, build a local file:
acp intercept from-enrollment enroll.json > endpoints.yaml
```

`acp discover` reads a plain host list by default, or a real-world export with `--from`:
`squid`, `csv`, `jsonl`, and the endpoint / CASB connectors `purview`, `zscaler` and `netskope`. This
is the partner-first path to endpoint DLP: import the exports your Purview / Zscaler / Netskope tools
already produce, and their AI destinations flow straight into shadow-AI discovery and these interception
rules, with no new endpoint agent to deploy.

See [chapter 12](12-grc.md) for discovery and enrolment.

## SSRF hardening

The interceptor is where outbound destinations are decided, so it is the right place to block
server-side request forgery. By default it refuses to dial loopback, private, link-local and
cloud-metadata targets (for example `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16` and the
`169.254.169.254` cloud-metadata address): such a target is blocked with a `403` on both the CONNECT
and the plain-HTTP absolute-form paths, and the deny is recorded as an `ssrf-block` event. The same
evaluator (`acp_core::egress`) backs the egress canary (`acp canary-egress`). If you genuinely need
the interceptor to reach an internal host (for example to govern an internal API), pass
`--allow-internal-egress` to turn the SSRF guard off; leave it on otherwise.

## Reporting and break-glass

Like the other enforcement points, the interceptor can report to the control plane. With
`--report-url <control-plane>` and `--report-token <token>` it posts a heartbeat and a governance event
on each block (including SSRF and break-glass denials), so the console liveness, alerts and violation
views cover egress too; `--proxy-id <id>` sets the name it reports under. It also honours the emergency
kill-switch: point `--break-glass-file` at the signed grant (and pin it with `--break-glass-key`), and
an engaged `lockdown_all` blocks all interceptor egress with a `403`. See [chapter 11](11-containment.md)
and [chapter 14](14-operations.md).

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

## Firewall rules schema

This is the interception rule registry the acp-agent firewall consults for every destination. It is
the same signed, versioned structure the interceptor uses, taken from
`crates/acp-core/src/interception.rs`. The matcher is pure and first-match: given a destination it
returns exactly one decision.

### A complete annotated example

```yaml
version: 1                         # registry schema version (integer)
default: flag-and-pass             # action for destinations that match no rule
endpoints:
  - id: anthropic                  # optional, for readability and reporting
    match:                         # all present predicates must hold (AND); absent are ignored
      host_contains: claude.ai
    classify: model-api            # optional label carried into the decision
    action: inspect-prompt

  - id: openai
    match:
      host_exact: api.openai.com
    classify: model-api
    action: inspect-prompt

  - id: internal-mcp
    match:
      host_suffix: internal        # host ends with "internal"
      path_contains: /mcp          # a path predicate can only be decided after TLS is terminated
    classify: mcp
    action: govern-tool-call

  - id: risky-provider
    match:
      host_contains: deepseek.com
    action: block

  - id: analytics-egress
    match:
      host_suffix: telemetry.example.com
      port: 443
    action: dlp-only
```

### Registry fields

| Field | Type | Notes |
|---|---|---|
| `version` | integer | Schema version of the registry. |
| `default` | default-action | Action taken when a destination matches no rule (see below). |
| `endpoints` | list | Ordered list of rules. First match wins, so put specific rules ahead of broad ones. |

### Rule fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | no | Identifier, echoed back in the decision and useful in reports. |
| `match` | object | yes | The predicates. All present ones must hold (AND). An empty `match` matches every destination. |
| `classify` | string | no | A free-form label such as `model-api` or `mcp`. Defaults to `other` in the decision when absent. |
| `action` | action | yes | What ACP does with matching traffic (see below). |

### Match predicates

Every predicate is optional and combined with AND. Absent predicates are ignored. Host, SNI and port
are decidable before decryption; the path predicates can only be evaluated once TLS is terminated.

| Predicate | Type | Meaning |
|---|---|---|
| `host_contains` | string | The host contains this substring (case-insensitive). |
| `host_suffix` | string | The host ends with this suffix (case-insensitive). |
| `host_exact` | string | The host equals this exactly (case-insensitive). |
| `sni` | string | Matched against the TLS server name, the same way as `host_contains` at this layer. |
| `path_contains` | string | The request path contains this substring (case-sensitive). |
| `path_prefix` | string | The request path starts with this prefix (case-sensitive). |
| `port` | integer | The destination port equals this value. |

### Actions

| Action | Meaning | Needs a CA (body inspection) |
|---|---|---|
| `inspect-prompt` | Decrypt, extract the prompt or completion body, and run the content engine and the policy engine over it. | yes |
| `govern-tool-call` | Treat the body as a tool call and run the full MCP decision path (the same policy evaluation the MCP guard uses). | yes |
| `dlp-only` | Scan the body for exfiltration (PII and secrets) only, with no model-call or tool-call governance. | yes |
| `block` | Refuse the connection. | no |
| `pass` | Allow the connection without inspection. It is still recorded as seen. | no |

The three body-reading actions (`inspect-prompt`, `govern-tool-call`, `dlp-only`) can only work where
a TLS-terminating certificate authority is configured, because the plaintext body is not otherwise
visible. `block` and `pass` are decided at the connection layer and need no CA. A precedence-aware,
least-inspection gate uses this: for a given host, the first rule whose host-level predicates match
decides whether to decrypt at all. It decrypts only if that rule has a path predicate (the path is
invisible until after termination) or its action needs the body. A `block` or `pass` rule ahead of any
path rule short-circuits, so such a host is never decrypted needlessly.

### The default action

When no rule matches, `default` decides. There are four values:

| `default` | Records as shadow AI | Then |
|---|---|---|
| `flag-and-pass` | yes | passes the connection |
| `flag-and-block` | yes | blocks the connection |
| `pass` | no | passes the connection |
| `block` | no | blocks the connection |

A `flag-*` default is how ungoverned, unseen destinations get surfaced as shadow AI rather than
silently allowed or dropped.

### Where the rules come from today

The registry served at `GET /intercept/rules` is, at present, **derived from the enrolled endpoint
dispositions** (see [chapter 12](12-grc.md)). Each disposition maps to an action:

| Enrolment disposition | Rule action |
|---|---|
| govern (enroll) | `inspect-prompt`, or `govern-tool-call` when the endpoint is classified `mcp` |
| block (quarantine) | `block` |
| accept-risk | `pass` (a deliberate, time-boxed, recorded exception) |

The acp-agent firewall fetches this registry over the control plane: you give it one
`--control-plane <url>`, which is expanded into the per-capability URLs (including the rules URL), and
it refreshes on an interval. For air-gapped use, a local YAML registry file is loaded instead, and a
registry can be signed for tamper-evident distribution.

Operator-authored rules sit on top of this. The console **Content firewall** page has a **Firewall
rules** card where you author a rule (a match predicate plus an action, and an optional classify
label); it is stored in the control plane (`POST /firewall/rules`) and served **ahead** of the
enrolment-derived rules by `GET /intercept/rules`, so a hand-authored rule wins (first match). Every
acp-agent fetches the merged set via `--control-plane`, so a rule you add in the console reaches the
fleet on the next refresh. List and delete rules from the same screen (`GET`/`POST
/firewall/rules/:id/delete`).
