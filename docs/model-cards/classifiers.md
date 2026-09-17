# Model card: data-class classifiers (pii, secret)

## Identity
- Name: acp data-class classifiers
- Version: rules-v1 (see `acp-core::classify`)
- Type: deterministic, versioned rule-sets (regex), NOT trained or opaque ML (decision D15).
  Chosen so every gated decision is reproducible, verifiable, explainable, and auditable.

## Intended use
- Flag whether a string argument contains a named data class (`pii` or `secret`) so a policy can
  gate on `contains_class`. The flag is written into the trusted `derived` context namespace, never
  under agent-controlled `args` (D9).
- Advisory only on `deny` paths: an attacker can obfuscate to evade, so a classifier must never be
  the sole barrier on a deny (D9/D15).

## Method
- `secret`: keyword-led token patterns (sk/pk/akia/bearer/api_key/secret/token/password/...) with a
  separator and an 8+ char token, plus a 32+ char high-entropy run. `secret` takes precedence.
- `pii`: email, US-style SSN, and international phone patterns.
- Linear-time (`regex` crate), so a pathological input cannot blow the latency budget.

## Measured performance
Evaluated with `acp classify-eval crates/acp-core/tests/data/classify-eval.jsonl` (16 labelled
samples; reproduce any time). Baselines enforced by the CI regression gate
(`crates/acp-core/tests/classify_eval_tests.rs`):

| Class | Precision | Recall | FPR | Target |
|---|---|---|---|---|
| pii | 1.00 | 1.00 | 0.00 | recall >= 0.80, fpr <= 0.30 |
| secret | 1.00 | 1.00 | 0.00 | recall >= 0.80, fpr <= 0.30 |
| overall accuracy | | 1.00 | | >= 0.80 |

## Locales tested
US phone, +91 (India) phone, US SSN, and emails across `.com`, `.co.uk`, `.es`. Coverage of
non-Latin scripts and more national ID formats is a known gap (bias/fairness slice, D5).

## Known evasions (tracked, D7)
Reversal, character-spacing, and zero-width splits can bypass detection; the standing corpus in
`classify_eval_tests.rs` measures the bypass rate over releases. Because classifiers are advisory
on deny paths, non-zero evasion is expected and must not be relied upon as the only control.

## Limitations
- Rule-based: no semantic understanding; real-world false positives (for example the word
  "password" followed by any long token) are possible and are the subject of ongoing tuning via
  the eval harness (D1/D2) and the production feedback loop (D3, governed like `args_blob`).
- Versioned: the classifier version is stamped into evidence provenance so a historical decision
  is reproducible.
