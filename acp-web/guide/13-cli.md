# 13. Command-line tools

Management does not happen on the command line any more. Registration, policy, approvals, the
kill-switch, AI endpoints and the GRC records are all created and changed from the **console** (for
people) or the **control-plane API** (for automation), and stored centrally in the control-plane
database. The command line is for three things only: independent verification, CI gates, and a few
offline or generation tools.

## What runs on the command line

### acp-verify (the one durable tool)

Independent, offline verification of the evidence, run by an auditor on their own machine with only
the public key. It never contacts or trusts the server.

```sh
acp-verify <ledger.db>          # verify a ledger, public key only
acp-verify --pack <pack.json>   # verify a downloaded evidence pack on a clean machine
```

Exit 0 if the evidence verifies, non-zero if it was tampered with. See [chapter 9](09-evidence.md) and
[chapter 15](15-security.md).

### The enforcement binaries

Not "commands to manage", but the data plane you deploy: `acp-proxy`, `acp-gateway`, `acp-intercept`,
`acp-guard`. Their flags are in chapters [3](03-proxy.md) to [6](06-guard.md).

### CI and offline helpers (the `acp` tool)

The `acp` tool ships in the server archive and carries the tasks that genuinely belong on a command
line: they change no governance state, or they run in a pipeline, or they must work offline.

| Command | Job |
| --- | --- |
| `acp policy-compile` / `policy-test` | compile and test a policy in CI, before it is deployed from the console |
| `acp redteam` / `content-eval` / `content-scan` / `groundedness` | firewall CI gates and one-off checks |
| `acp coverage` / `canary-egress` / `posture` | measure unavoidability and default-deny readiness |
| `acp export` / `grc-report` / `siem` | produce an evidence pack, a framework report, or a SIEM feed from a ledger |
| `acp ledger-backup` / `purge` / `replay` | evidence maintenance |
| `acp native-compile` | compile a policy into coding-agent settings |
| `acp discover` | classify shadow-AI endpoints from an egress log (then enrol them in the console) |
| `acp intercept sign` / `pac` / `from-enrollment` | build TLS-interception rule sets, PAC files and browser config |
| `acp verify-enforcement` | check a PEP is actually enforcing, not bypassed |
| `acp sign-artifact` / `verify-artifact` | sign and verify a build artifact |

This table is a curated subset; run `acp help` for the full command list (including `init`, `learn`,
`classify-eval`, `canary`, `diagnose` and `bench-ledger`).

## What moved to the console and the API

These commands are **retired**. Do the same thing from the console or the control-plane API; the
record is stored in the database and signed server-side.

| Retired command | Now |
| --- | --- |
| `acp app register`, `acp agent register`, `acp registry` | console Teams / Agents pages, or `POST /apps`, `POST /agents` |
| `acp enroll` (AI endpoints) | console AI Endpoints page, or `POST /endpoints/register` |
| `acp approve` / `deny` / `approvals` | console Approvals inbox, or `POST /approvals/:id/approve` |
| `acp break-glass` | console Kill-switch, or `POST /break-glass/engage` |
| `acp assess`, `conformity`, `risk`, `modelcard`, `usecase`, `attest`, `aibom`, `controls` | console Governance page, or `POST /grc` |
| policy deploy | console Policy page, or `POST /policy-store/deploy` |

The proxy no longer needs a registry file: point `--registry-url` at the control plane and it verifies
each agent against the database ([chapter 8](08-identity.md)).

## Why verification stays local

Everything else can move to the server because the server is trusted to *do* it. Verification cannot:
if an auditor checks the ledger through the console, they are trusting the server, which is the one
thing the tamper-evidence design refuses to require. So `acp-verify` runs on the auditor's machine,
with the public key alone, and that is the only management-free command that must exist.
