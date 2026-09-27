# ACP detection corpus

A labelled corpus for the content-firewall efficacy gate (gap C3).

- **Size:** 45 examples: 15 `injection`, 12 `pii`, 18 `benign`.
- **Provenance:** hand-authored by the ACP team. The `injection` examples are drawn from the
  first-party prompt-injection signature set (`acp_core::content::injection_res`); the `pii` examples
  use common email, US SSN and payment-card formats; the `benign` examples are ordinary operational
  text with no signatures, PII or long digit runs.
- **Format:** JSONL, one `{ "label": "injection" | "pii" | "benign", "text": "..." }` per line.
- **Gate:** the `corpus_gate` test in `content.rs` runs the built-in engine over this corpus and fails
  CI if injection or PII precision, recall, or the benign false-positive rate regress below the
  thresholds published in the guide (chapter 15).

This is a seed corpus. Grow it as new attack families and PII shapes appear; keep the thresholds in
the test and the numbers in the guide in step.
