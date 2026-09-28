//! A real, reproducible benchmark of the injection detector (G14): a deterministic held-out split of
//! the labelled corpus, trained on the train split and evaluated on the UNSEEN test split, with a
//! metric gate. This is stricter than the corpus_gate (which scores on data the shipped model saw):
//! it measures generalisation. It runs in CI on every `cargo test`.
//!
//! The model here is the hashed n-gram logistic regression (fast, on-prem, zero-dependency). A
//! transformer via ONNX is the documented next tier behind the same `Scorer` seam; it needs a training
//! data programme, not wiring, so it is not bundled.

use acp_core::content::{eval_injection, train_linear, LinearScorer};

fn corpus() -> Vec<(String, bool)> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/detection-corpus.jsonl");
    let text = std::fs::read_to_string(path).expect("corpus present");
    text.lines().filter(|l| !l.trim().is_empty()).map(|l| {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        let label = v["label"].as_str().unwrap_or("");
        // Injection detector: "injection" is positive; benign and pii are negative.
        (v["text"].as_str().unwrap_or("").to_string(), label == "injection")
    }).collect()
}

// Deterministic hash for a stable train/test split (FNV-1a).
fn h(s: &str) -> u32 {
    let mut x = 2166136261u32;
    for b in s.bytes() { x ^= b as u32; x = x.wrapping_mul(16777619); }
    x
}

#[test]
fn injection_detector_generalises_on_a_held_out_split() {
    let all = corpus();
    let (mut train, mut test) = (Vec::new(), Vec::new());
    for s in &all {
        if h(&s.0) % 10 < 3 { test.push(s.clone()); } else { train.push(s.clone()); }
    }
    assert!(!train.is_empty() && !test.is_empty(), "both splits non-empty (train {} test {})", train.len(), test.len());
    // No leakage: the test texts are not in the training set.
    let train_texts: std::collections::HashSet<&String> = train.iter().map(|(t, _)| t).collect();
    assert!(test.iter().all(|(t, _)| !train_texts.contains(t)), "no train/test overlap");

    let model = train_linear(&train, 4096, 300, 0.5, "prompt-injection");
    let scorer = LinearScorer::new(model);
    let m = eval_injection(&scorer, &test);
    println!(
        "held-out injection benchmark: train={} test={} precision={:.3} recall={:.3} fpr={:.3} accuracy={:.3}",
        train.len(), test.len(), m.precision, m.recall, m.fpr, m.accuracy
    );
    // Generalisation gate on the unseen split. Conservative floors for a small-corpus LR; raise as the
    // corpus grows. A regression below these fails CI.
    assert!(m.recall >= 0.70, "held-out recall {:.3} below gate 0.70", m.recall);
    assert!(m.precision >= 0.70, "held-out precision {:.3} below gate 0.70", m.precision);
    assert!(m.fpr <= 0.20, "held-out benign FPR {:.3} above gate 0.20", m.fpr);
}
