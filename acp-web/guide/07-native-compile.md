# 7. Governing coding agents

Coding agents (Claude Code, GitHub Copilot, Gemini CLI) have powers that are not MCP tool calls:
they run shell commands, edit files, and reach the network directly. Varman does not re-implement
their sandboxes. Instead it becomes the **single source of policy** and compiles one ACP policy into
each vendor's own managed-settings format, which the vendor's agent then enforces. ACP is the policy
origin; the agent stays the enforcer of its own sandbox.

## Compiling a policy

```sh
acp native-compile policy.yaml --vendor claude
acp native-compile policy.yaml --vendor copilot
acp native-compile policy.yaml --vendor gemini
```

The command reads your ACP policy and prints the vendor's managed-settings JSON. It maps the
policy's native resources (`filesystem`, `network`, `source-code`, `secrets`) to that vendor's
permission selectors, files them under the vendor's deny or ask lists by verdict, and **reports
which rules it could not express** so those are visibly routed to the proxy rather than silently
dropped. The mapping is deliberately lossy, because each vendor expresses less than the full model,
and the tool tells you exactly what it dropped.

For example, a rule denying `resource: filesystem, operation: write` becomes a deny on `Edit` and
`Write` for Claude, on `Write` and `Edit` for Copilot, and a `tools.exclude` entry for Gemini. A
`step_up` rule maps to the vendor's "ask" list where one exists; Gemini has no clean "ask", so such a
rule is reported uncovered and routed to the proxy.

Distribute the compiled settings through your MDM so a developer cannot loosen them, and you have one
policy authored once, enforced by each agent's own trusted mechanism.

## Pinning the agent's model traffic

A coding agent also makes its own model calls. To force those through the [gateway](04-gateway.md)
too, so even the agent's direct model use cannot bypass ACP, compile with a gateway URL:

```sh
acp native-compile policy.yaml --vendor claude --gateway http://127.0.0.1:8799
```

This adds an `env` block to the settings that pins each vendor SDK's base-URL variable
(`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `GOOGLE_GEMINI_BASE_URL`) to the
gateway. Combined with a network allowlist that only lets the gateway reach model hosts, even a
leaked key cannot reach a model off-ACP.

## What this is and is not

This governs the coding agent's non-MCP powers through the vendor's own controls. It is not a second
operating-system sandbox, and it does not emit machine code despite the name "native-compile", it
emits settings JSON. Rules the vendor cannot express are not lost; they are reported so you route
them to a PEP that can enforce them.
