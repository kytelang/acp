# 13. The acp CLI

> Direction: management is moving to the console and the control-plane API, with records stored
> centrally. On a workstation the only long-term command-line tool is `acp-verify` (independent
> evidence verification); the enforcement binaries (`acp-proxy`, `acp-intercept`, `acp-guard`) are
> deployed, not "run to manage". The `acp` commands below still work and ship in the server archive as
> the interim admin tool, but prefer the console for anything that changes governance state.


`acp-cli`, invoked as `acp`, is the operator's tool for everything that is not sitting in the request
path: authoring and testing policy, managing identity, verifying and exporting evidence, discovery
and enrolment, red-teaming the firewall, and the GRC surface. It talks to files and to a running
control plane; it holds no signing key of its own for the data path.

Run `acp` with no arguments for the banner, or `acp <command>` with no arguments for that command's
usage.

## Getting started

```sh
acp init acp-demo        # scaffold a workspace: a starter policy and the run commands
acp version
```

`acp init` writes a starter `policy.yaml` (with guidance toward default-deny), and prints how to run
the proxy, resolve an approval, verify the evidence, and check posture.

## Policy

| Command | Purpose |
| --- | --- |
| `acp policy-compile <policy.yaml>` | compile to Cedar and report errors, without deploying |
| `acp policy-test <policy.yaml> <tests>` | evaluate example requests against a policy |
| `acp policy ...` | inspect the deployed policy store |
| `acp posture <ledger.db> [--required <0..1>]` | is coverage high enough to flip to default-deny? |

## Identity

| Command | Purpose |
| --- | --- |
| `acp app register <registry> <name> <owner>` | register an application |
| `acp agent register <registry> <app-id> <name>` | register an agent, prints a one-time token |
| `acp registry ...` | inspect apps, agents and principals |

## Evidence

| Command | Purpose |
| --- | --- |
| `acp verify <ledger.db>` | re-derive and verify the ledger, public-key only |
| `acp export <ledger.db>` | write a standalone, self-verifying evidence pack |
| `acp verify-pack <pack.json>` | verify an exported pack on a clean machine |
| `acp replay <ledger.db> <seq> <policy.yaml>` | replay one recorded decision against a policy |
| `acp purge <ledger.db> --before <ms>` | drop argument payloads older than a cutoff (retention) |
| `acp ledger-backup <src.db> <dst.db>` | copy and re-verify a backup |
| `acp siem <ledger.db> --format cef|ocsf|syslog` | project decisions into a SIEM |

## Approvals and emergency

| Command | Purpose |
| --- | --- |
| `acp approvals <store>` | list pending step-up holds |
| `acp approve <store> <id> <approver>` | approve a held action |
| `acp deny <store> <id>` | deny a held action |
| `acp break-glass engage|clear ...` | operate the signed kill-switch |

## Content firewall

| Command | Purpose |
| --- | --- |
| `acp content-scan <text>` | scan one input for injection, PII, secrets |
| `acp content-eval <dataset.jsonl>` | precision / recall on a labelled set |
| `acp redteam [model.json] [--min-catch <r>]` | adversarial corpus gate for CI |
| `acp groundedness --answer <f> --context <f>` | context-grounded faithfulness check |
| `acp classify-eval <dataset.jsonl>` | evaluate the PII / secret classifiers |

## Coverage, discovery, enrolment

| Command | Purpose |
| --- | --- |
| `acp discover` | classify shadow-AI endpoints from an egress log |
| `acp enroll ...` | signed dispositions; `governed`, `export-mdm`, ... |
| `acp coverage <observed> <governed> [--require-full]` | signed governance-coverage report |
| `acp canary-egress <probes.json>` | fail if a model / tool is reachable off-ACP |
| `acp intercept pac|from-enrollment ...` | build interceptor rules |

## Governing coding agents

| Command | Purpose |
| --- | --- |
| `acp native-compile <policy.yaml> --vendor claude|copilot|gemini [--gateway <url>]` | compile to managed settings |

## GRC

| Command | Purpose |
| --- | --- |
| `acp grc-report <ledger.db>` | framework report graded from real records |
| `acp controls [framework]` | the control library |
| `acp assess ...` | EU AI Act risk tiering |
| `acp conformity init|set|report ...` | worked conformity checklist |
| `acp risk ...` | the AI risk register |
| `acp modelcard add|list ...` | the model-card registry |
| `acp usecase register|link-assessment|advance|list ...` | the use-case lifecycle |
| `acp attest ...` | signed attestations |
| `acp aibom <artifacts.json> [--require-scan]` | signed CycloneDX AI-BOM |

## Diagnostics and artifacts

| Command | Purpose |
| --- | --- |
| `acp diagnose ...` | environment and configuration checks |
| `acp canary ...` | enforcement canaries |
| `acp verify-enforcement ...` | check the enforcement attestation path |
| `acp sign-artifact` / `acp verify-artifact` | sign and verify an arbitrary artifact |
| `acp bench-ledger` | micro-benchmark the ledger append path |
| `acp learn <ledger.db>` | propose a starter policy from observed tools |

Chapters [2](02-policy.md), [9](09-evidence.md), [10](10-content-firewall.md) and [12](12-grc.md)
cover the commands in these groups in depth.
