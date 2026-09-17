//! Deterministic data-class classifiers (decision D15): rule-sets, not opaque ML.
//!
//! v0 ships two, `pii` and `secret`. They are advisory on deny paths (evasion is expected) and
//! use the linear-time `regex` crate, so a pathological input cannot blow the latency budget.
//! The proxy runs these over string arguments and sets flags in the un-spoofable `derived`
//! context namespace (D9), never inside agent-controlled `args`.

use regex::Regex;
use std::sync::OnceLock;

fn pii_res() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(), // email
            Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap(),                  // US SSN-like
            Regex::new(r"\b(?:\+?\d[\s\-]?){10,14}\b").unwrap(),                      // phone-like
        ]
    })
}

fn secret_res() -> &'static [Regex] {
    static R: OnceLock<Vec<Regex>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            Regex::new(r"(?i)\b(sk|pk|akia|bearer|api[_-]?key|secret|token|password|passwd|pwd)[\s:=_-]?[A-Za-z0-9_\-]{8,}").unwrap(),
            Regex::new(r"\b[A-Za-z0-9_\-]{32,}\b").unwrap(), // long high-entropy-ish token
        ]
    })
}

/// Classify a string value into a data class, or None. `secret` takes precedence over `pii`.
pub fn classify(value: &str) -> Option<&'static str> {
    if secret_res().iter().any(|re| re.is_match(value)) {
        return Some("secret");
    }
    if pii_res().iter().any(|re| re.is_match(value)) {
        return Some("pii");
    }
    None
}

/// Precision/recall/FPR for one data class (D1 eval harness).
#[derive(Debug, Clone)]
pub struct ClassMetrics {
    pub precision: f64,
    pub recall: f64,
    pub fpr: f64,
    pub support: usize,
}

/// Evaluation report over a labelled dataset.
#[derive(Debug, Clone)]
pub struct EvalReport {
    pub pii: ClassMetrics,
    pub secret: ClassMetrics,
    pub accuracy: f64,
    pub total: usize,
}

fn metrics_for(class: &str, samples: &[(String, String)]) -> ClassMetrics {
    let (mut tp, mut fp, mut fn_, mut tn) = (0usize, 0usize, 0usize, 0usize);
    for (text, label) in samples {
        let predicted = classify(text).unwrap_or("none");
        match (predicted == class, label == class) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
            (false, false) => tn += 1,
        }
    }
    let div = |a: usize, b: usize| if b == 0 { 1.0 } else { a as f64 / b as f64 };
    ClassMetrics {
        precision: div(tp, tp + fp),
        recall: div(tp, tp + fn_),
        fpr: div(fp, fp + tn),
        support: tp + fn_,
    }
}

/// Evaluate the classifiers against a labelled dataset of (text, label) where label is one of
/// "pii" | "secret" | "none" (D1). Deterministic; used by the CI regression gate (D2).
pub fn evaluate(samples: &[(String, String)]) -> EvalReport {
    let correct = samples
        .iter()
        .filter(|(t, l)| classify(t).unwrap_or("none") == l.as_str())
        .count();
    EvalReport {
        pii: metrics_for("pii", samples),
        secret: metrics_for("secret", samples),
        accuracy: if samples.is_empty() {
            0.0
        } else {
            correct as f64 / samples.len() as f64
        },
        total: samples.len(),
    }
}
