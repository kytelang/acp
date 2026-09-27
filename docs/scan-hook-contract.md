# The ACP external scan-hook contract (v1)

ACP is deliberately neutral on content classification. The built-in engine (signatures, a trained
hashed n-gram logistic-regression model, a toxicity lexicon and es/fr/de injection signatures) gives a
solid on-prem floor, but it is not a Lakera-grade transformer. When you want a specialist classifier,
you point ACP at it with one flag and ACP calls it as a policy-enforcement hook. This document is the
stable contract that any such scanner (or an adapter in front of it) must satisfy. It is versioned so a
vendor adapter is drop-in, and it is covered by a conformance suite in the code
(`crates/acp-proxy/src/dispatch.rs`, module `scan_hook_conformance`).

## Where it runs

Set `--scan-url <url>` on `acp-proxy` (the MCP PEP) or the equivalent gateway flag. Add
`--block-on-scanner-error` to fail closed when the scanner is unreachable or replies with something the
contract does not understand. With no URL set, only the built-in engine runs.

The hook fires on both directions and on all content parts:

- request side: `prompt` and `tool_args` (text), and `tool_args` image/audio parts.
- response side: `response` and `tool_result` (text), and `tool_result` image/audio parts.

## Request

ACP POSTs one JSON body per content part. Text and non-text parts share the same envelope; they differ
only in which fields are populated.

Text part:

```json
{
  "modality": "text",
  "text": "the exact text extracted from the frame",
  "direction": "prompt | tool_args | tool_result | response",
  "context": { "transport": "stdio | http" }
}
```

Non-text part (image or audio):

```json
{
  "modality": "image | audio",
  "content_ref": "<base64 blob> or <https URL the scanner can fetch>",
  "mime": "image/png",
  "direction": "tool_args | tool_result",
  "context": { "transport": "stdio | http", "modality": "image" }
}
```

Notes:
- `content_ref` is taken verbatim from the MCP content part's `data`/`blob` (base64) or `url`/`uri`.
  ACP does not decode or transcode it; the scanner consumes it as-is.
- `context` is advisory metadata. Adapters may ignore it. ACP never puts secrets in it.

## Response

```json
{
  "block": true,
  "redactions": "optional replacement text for the scanned part"
}
```

Semantics (these are exactly what the conformance suite asserts):

- `block: true` -> ACP refuses the call. A blocked request never reaches the tool server; the client
  gets a JSON-RPC error. A blocked response is replaced with a safe `isError` result frame.
- `block: false` with `redactions` present -> ACP forwards, replacing the text part with the redaction
  string. Redaction currently applies to text parts.
- `block: false`, no `redactions` -> forward unchanged.
- Any transport error, non-2xx, or a body that is not valid JSON is a scanner error. ACP then fails
  closed (block) only if `--block-on-scanner-error` is set; otherwise it fails open and falls back to
  the built-in engine.

## Versioning

This is v1. Additive fields (new `context` keys, new optional response fields) do not bump the version.
A breaking change (renamed/removed field, changed default semantics) bumps it, and the request will
carry a `"contract": "v2"` marker so an adapter can branch. Adapters should ignore unknown fields.

## Conformance

The in-repo suite `scan_hook_conformance` runs a mock scanner that decides purely from the request body
and drives it through the real Controller hook. It covers: text `block`, clean pass, `redactions`, image
modality block, and fail-open vs fail-closed on a scanner error. Run it with:

```
cargo test -p acp-proxy scan_hook_conformance
```

Any adapter that makes these cases pass is contract-conformant.

## Reference adapter mappings

ACP ships a mock adapter (the conformance mock). Below is the request/response mapping for three common
specialists. Each is a thin sidecar: it receives the ACP request, calls the vendor, and returns the ACP
response. None of this is a classifier ACP runs itself.

### Azure AI Content Safety

- ACP `text` -> Content Safety `POST /contentsafety/text:analyze` with `{ "text": <text> }`.
- ACP `modality: image`, `content_ref` base64 -> `POST /contentsafety/image:analyze` with
  `{ "image": { "content": <base64> } }`. A URL `content_ref` is fetched by the adapter first.
- Map any category severity at or above your threshold (Hate, SelfHarm, Sexual, Violence) to
  `block: true`. Content Safety does not return redactions, so the adapter omits `redactions`.

### Lakera Guard

- ACP `text` -> Guard `POST /v2/guard` with `{ "messages": [{ "role": "user", "content": <text> }] }`.
- Map `flagged: true` (prompt injection, PII, etc.) to `block: true`. If you run Guard in a
  detect-and-mask mode, put the masked text in `redactions` and set `block: false`.
- Guard is text-first; for image/audio, route those modalities to a multimodal specialist and keep
  Guard for text.

### Protect AI (LLM Guard / Rebuff-style)

- ACP `text` -> the scanner pipeline (PromptInjection, Secrets, Anonymize, Toxicity).
- A tripped input/output scanner maps to `block: true`. The Anonymize/Deanonymize scanners produce a
  sanitised string; return it as `redactions` with `block: false` when you want redact-not-block.
- For model artifacts (not this text/media hook) use Protect AI ModelScan behind the separate
  `--model-scanner-url` admission hook; its findings feed the MITRE ATLAS enrichment (see R4).

## Raising the built-in floor (optional)

The built-in ML detector can be retrained from a grown corpus with `scripts/train_injection_lr.py`
(pure Python, no deps), which emits `crates/acp-core/models/injection-lr.json` for the Rust
`LinearScorer`. The featurisation is fixed and must match `acp_core::content::features`. The CI efficacy
gate (recall/FPR over `crates/acp-core/corpus/detection-corpus.jsonl`) guards regressions. This lifts
the floor; it does not claim transformer parity, which is what the external hook is for.
