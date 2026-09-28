# Roadmap: second-opinion feature analysis, grounded in the current repo

This takes an external second-opinion review of 19 candidate features and grounds each one against
what the repo actually contains today (after the crate consolidation to six crates). For every item it
records the verified current state, the real remaining gap, an effort estimate, and a build order. Where
the second opinion over or understated the current state, that is called out, because a plan is only
useful if its starting point is accurate.

Effort key: S = about 1 to 2 weeks, M = about 3 to 6 weeks, L = a quarter or more (often a data or ML
programme, not just wiring).

## Corrections to the starting assumptions

- **Item 1 (least-privilege from observed behaviour) is already half-built.** `acp learn <ledger>` reads
  the shadow-mode decision records and emits a compilable draft policy today (`crates/acp-cli`, plus
  `acp_core::posture` and `acp posture` for default-deny readiness). It is coarse: it proposes a step-up
  gate per high or medium impact tool and default-allow for the rest, not a minimal allow-only policy
  over subjects, resources and arguments, and there is no console diff or sign-off. So this is an
  extension, not a green field, which makes it cheaper than the review implied.
- **Item 12 (output-side scanning) already exists for injection and tool results.** The response
  direction is scanned in `acp_agent::proxy` (stdio and http) and the gateway `response_gate`, including
  indirect-injection screening of tool results and the external-hook `response`/`tool_result`
  directions. What is genuinely missing is first-class OUTPUT DLP: PII, secret and system-prompt-leak
  detection on responses as its own control with its own report. So this is "extend", not "barely
  covered".
- **Item 4 (delegation) has a single hop today.** `acp_core::registry::Delegation` binds one human to
  one agent with a TTL and injects the principal into the policy context. The multi-hop A to B chain
  with narrowing rights is the real gap.
- **Item 13 (groundedness) is lexical by design, with the NLI upgrade already stubbed** in
  `acp_core::groundedness` comments. Correct as stated.
- Items 3, 5, 7, 8 (end-to-end), 9, 10, 11, 16, 17 (against customers), 18, 19 are genuinely absent.
  Items that already exist and are correctly excluded by the review: erasure, anomaly detection,
  metering, shadow evaluation, AI-BOM, ATLAS mapping, discovery connectors.

## Tier 1: highest value, extends the core strength

| # | Feature | Current state | Remaining gap | Effort |
| --- | --- | --- | --- | --- |
| 1 | Least-privilege policy from observed behaviour | `acp learn` drafts a coarse review policy from shadow traffic | Minimal allow-only synthesis over subject/resource/args, Cedar output, console diff + human sign-off | M |
| 2 | Plain-English policy authoring with verification | Cedar engine + analyzer present (`acp_core::policy`) | LLM draft from NL, generated test cases, show allows/blocks before deploy | M |
| 3 | Permission-aware retrieval (RAG) | none | Enforce per-document access against the acting human at retrieval time | M |
| 4 | Multi-agent delegation chains | single-hop `Delegation` | Authorize each hop U to A to B, rights narrow along the chain, record chain in ledger | M |
| 5 | Oversight-quality monitoring | approval records exist; no analysis | Detect rubber-stamp approvals (approve-all, sub-second, bulk); flag as control weakness (EU AI Act Art. 14) | S |
| 6 | Agent-memory protection | none | Govern writes to persistent memory / vector store; scan for planted instructions; record writes in ledger | M |

## Tier 2: needed to stand alone against Credo and Aegis

| # | Feature | Current state | Remaining gap | Effort |
| --- | --- | --- | --- | --- |
| 7 | Fundamental-rights impact assessment (Art. 27) | assessment framework exists; not this template | Add FRIA template linked to use-case registry + DPIA | S |
| 8 | Serious-incident workflow (Art. 73) | fragments (violations, ledger) | Detection to case to root-cause to report, deadline tracking, evidence from ledger | M |
| 9 | Post-market monitoring (Art. 72) | drift/block/incident data exists | Generate the monitoring plan + periodic reports from runtime data | S |
| 10 | Transparency obligations (Art. 50) | none | Obligations "disclose AI", "label generated content"; C2PA stamping; proof in ledger | M |
| 11 | Bias/performance testing of customer models | known gap (model cards carry a flag only) | Fairness + quality harness; store signed results as evidence | L |
| 12 | Output-side scanning | injection + tool-result scanning exists | First-class output DLP: PII/secret/system-prompt-leak on responses, own report | S |
| 13 | Local semantic groundedness model | lexical baseline; NLI stubbed | Bundle a local NLI model behind the groundedness interface | M |
| 14 | Transformer injection detector | signatures + logistic-regression + external hook | Small fine-tuned model via ONNX as a second stage | L |
| 15 | More regulatory content packs | 5 signed packs (EU AI Act, NIST, ISO 42001, SOC 2, GDPR) | Add India DPDP and the UK approach as signed versioned packs | S |

## Tier 3: expands the market later

| # | Feature | Current state | Remaining gap | Effort |
| --- | --- | --- | --- | --- |
| 16 | Browser extension for employee AI use | discovery finds usage; no control | Inline DLP + policy for staff on consumer tools | L |
| 17 | Continuous red-teaming of customer agents | red-team corpus tests our own detector | Scheduled attack service against customer agents, results filed as evidence | M |
| 18 | Self-service auditor portal | signed evidence packs + `acp verify` exist | Scoped read-only access: pick a window, download a signed pack, verify with the pubkey | M |
| 19 | Public trust page | signed ledger exists | Publish a verifiable summary of controls in force for the customer's own clients | S |

## Recommended build order

Grounded in what already exists, the cheapest high-value wins come first:

1. **Item 5 (oversight-quality monitoring), S.** The approval data is already in the store; this is
   analysis plus a console panel. Unique, demoable, directly answers EU AI Act Art. 14. Start here.
2. **Item 1 (least-privilege synthesis), M, but discounted.** Extend the existing `acp learn` into
   minimal allow-only Cedar synthesis with a console diff and sign-off. Biggest adoption unlock, and the
   scaffolding is already there.
3. **Item 2 (plain-English authoring + verification), M.** Pairs naturally with item 1 and reuses the
   Cedar analyzer. These three (5, 1, 2) are the "weeks not months" set the review flagged, and none is
   quick for a GRC or firewall vendor to copy.
4. **Items 9 then 8 (post-market monitoring, serious-incident workflow), S then M.** These turn the
   runtime evidence into the exact reports regulators ask for, which is the strongest GRC-credibility
   move. Item 9 is cheap because the drift/block/incident data already exists.
5. **Item 12 (output DLP), S.** Extend the existing response-scan path with a dedicated PII/secret/
   prompt-leak report. Cheap because the response direction is already wired.
6. Then, as capacity allows: 3, 4, 6 (Tier 1 mid-effort), 7/10/15 (cheap GRC breadth), and the
   ML-programme items 11, 13, 14 which are a quarter-plus each.

## Honest notes

- Items 11, 14, 16 are genuinely large (a fairness harness, a trained transformer, a deployed endpoint
  agent). They are not "weeks" work and should not be sequenced as if they were.
- Items 13 and 14 slot behind interfaces that already exist (the groundedness provider seam and the
  external scan-hook), so they are drop-ins when the models are ready, not re-architecture.
- Nothing here needs a new crate. All of it lands as modules in `acp-core` (engine, GRC, monitors) or
  the relevant binary, consistent with the six-crate layout.
