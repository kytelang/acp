# Model card: data-class classifiers (pii, secret)

## Identity
- Name: acp data-class classifiers
- Version: rules-v1 (see `acp-core::classify`)
- Type: a mix: deterministic regex rule-sets for PII and secrets (decision D15), plus a trained ML classifier for prompt injection (see below).
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
| pii | 1.00 | 1.00 | 0.00 | recall >= 0.80, accuracy >= 0.80 (FPR reported, not gated) |
| secret | 1.00 | 1.00 | 0.00 | recall >= 0.80, accuracy >= 0.80 (FPR reported, not gated) |
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

## Trained injection classifier (ML)

The content firewall's primary injection and jailbreak detector is a trained machine-learning model,
not a rule-set:

- Model: hashed word and character n-gram logistic regression (`acp_core::content::LinearScorer`,
  detector id `logreg-hashed-ngram`), trained by `scripts/train_injection_lr.py`, shipped at
  `crates/acp-core/models/injection-lr.json`.
- Featurisation: lowercase, alphanumeric tokens, word uni and bi-grams plus character 4-grams over the
  de-spaced text, FNV-1a hashed into a fixed space, binary presence; sigmoid over learned weights.
- Robustness: it runs on a normalised view of the text (base64 decode, zero-width strip, homoglyph
  fold, de-spacing), so common obfuscations do not evade it, and it is applied to tool results as well
  as prompts and arguments.
- Evaluation and CI gate: a held-out set (`crates/acp-core/models/injection-eval.json`) plus
  `acp content-eval` and the adversarial corpus `acp redteam` gate the model so a regression cannot
  ship. On the shipped corpus, signatures plus the model catch every obfuscation variant with no false
  positives.
- Honest boundary: this is a lightweight trained classifier, not a heavyweight transformer. It is
  defence in depth; the authorisation layer is what contains a successful injection.

## Content firewall detectors (signatures and topics)

Alongside the trained model, `acp_core::content` ships a `SignatureScorer` (prompt-injection and
jailbreak signatures, denied-topic rules) and reuses the PII and secret classifiers above for
redaction. All detectors sit behind one `Scorer` seam.

## Groundedness detector (baseline)

`acp_core::groundedness` scores an answer against its source context by per-sentence content-word
support, flagging unsupported claims. It is a lexical baseline for on-premises and air-gapped use;
production-grade groundedness is delegated to an external specialist service. See
`docs/design/groundedness.md`.
