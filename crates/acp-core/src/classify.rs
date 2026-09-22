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

/// High-precision keyword rule: a known secret prefix or field name followed by a value.
fn secret_keyword_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b(sk|pk|akia|ghp|glpat|xox[baprs]|bearer|api[_-]?key|secret|token|password|passwd|pwd)[\s:=_-]?[A-Za-z0-9_\-]{8,}").unwrap()
    })
}

/// Candidate tokens for the unprefixed high-entropy rule: runs of key-shaped characters (base64,
/// base64url, hex) of at least 24 characters. Length alone is NOT enough (see `high_entropy_secret`).
fn secret_token_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9_+/=\-]{24,}").unwrap())
}

/// Shannon entropy (bits per character) of a token.
fn shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let pr = c as f64 / n;
            h -= pr * pr.log2();
        }
    }
    h
}

/// Decide whether an unprefixed token looks like a real secret rather than a long word, path, git
/// SHA or UUID. Two gates, either sufficient:
///   1. Key-shaped: at least 32 chars with lower, upper AND digit all present (classic API key).
///   2. Very high entropy: at least two character classes and entropy above hex (log2(16) = 4.0).
/// Pure-lowercase words, slash paths, all-hex hashes (entropy ~4.0) and dashed UUIDs (no upper) are
/// intentionally not flagged, which is where the old length-only rule produced false positives.
fn high_entropy_secret(tok: &str) -> bool {
    let len = tok.chars().count();
    if len < 24 {
        return false;
    }
    let has_lower = tok.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = tok.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let classes = [has_lower, has_upper, has_digit]
        .iter()
        .filter(|b| **b)
        .count();
    let ent = shannon_entropy(tok);
    (len >= 32 && has_lower && has_upper && has_digit) || (classes >= 2 && ent > 4.2)
}

/// True if `re` matches a numeric span (SSN, phone) that is NOT embedded in a larger letter-bearing
/// token. Expanding the match over identifier characters (alnum, `-`, `_`) and finding a letter means
/// the digits are part of a UUID, hash or identifier, not a real phone or SSN. Phone numbers use
/// spaces or dashes and carry no letters, so they survive; a UUID tail like `...-446655440000` does
/// not, because expansion pulls in the hex letters of the UUID.
fn clean_numeric_match(value: &str, re: &Regex) -> bool {
    let bytes = value.as_bytes();
    let is_idchar = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    for m in re.find_iter(value) {
        let mut s = m.start();
        while s > 0 && is_idchar(bytes[s - 1]) {
            s -= 1;
        }
        let mut e = m.end();
        while e < bytes.len() && is_idchar(bytes[e]) {
            e += 1;
        }
        if !value[s..e].bytes().any(|b| b.is_ascii_alphabetic()) {
            return true;
        }
    }
    false
}

/// Classify a string value into a data class, or None. `secret` takes precedence over `pii`.
pub fn classify(value: &str) -> Option<&'static str> {
    if secret_keyword_re().is_match(value)
        || secret_token_re()
            .find_iter(value)
            .any(|m| high_entropy_secret(m.as_str()))
    {
        return Some("secret");
    }
    let pii = pii_res();
    if pii[0].is_match(value) || clean_numeric_match(value, &pii[1]) || clean_numeric_match(value, &pii[2]) {
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_real_secrets() {
        assert_eq!(classify("AKIAIOSFODNN7EXAMPLE"), Some("secret")); // AWS key id (keyword)
        assert_eq!(classify("sk_live_51H8xЫ".to_string().as_str()).is_some(), true.then_some(true).is_some());
        assert_eq!(classify("api_key=aGVsbG8Xy9zZWNyZXQ1234"), Some("secret")); // keyword=value
        assert_eq!(
            classify("Zm9vYmFyQmF6MTIzNDU2Nzg5MFFXRXJ0eVVJT1A="),
            Some("secret")
        ); // base64, mixed classes, high entropy
        assert_eq!(classify("ghp_16C7e42F292c6912E7710c838347Ae178B4a"), Some("secret")); // GitHub PAT
    }

    #[test]
    fn catches_pii() {
        assert_eq!(classify("alice@example.com"), Some("pii"));
        assert_eq!(classify("123-45-6789"), Some("pii"));
        assert_eq!(classify("+1 415 555 0100"), Some("pii"));
    }

    #[test]
    fn does_not_flag_common_non_secrets() {
        // The exact false positives the old length-only rule produced.
        let benign = [
            "thisisareallylongvariablenamethatisnotsecret",         // long lowercase word
            "src/main/java/com/example/service/UserRepositoryImpl", // long path
            "550e8400-e29b-41d4-a716-446655440000",                 // UUID (no upper)
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",             // git SHA-1 (hex, entropy ~4.0)
            "The quick brown fox jumps over the lazy dog repeatedly",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",             // low entropy run
        ];
        for b in benign {
            assert_eq!(classify(b), None, "false positive on {b:?}");
        }
    }

    #[test]
    fn eval_precision_and_recall_gate() {
        let samples: Vec<(String, String)> = vec![
            ("AKIAIOSFODNN7EXAMPLE".into(), "secret".into()),
            ("ghp_16C7e42F292c6912E7710c838347Ae178B4a".into(), "secret".into()),
            ("Zm9vYmFyQmF6MTIzNDU2Nzg5MFFXRXJ0eVVJT1A=".into(), "secret".into()),
            ("alice@example.com".into(), "pii".into()),
            ("123-45-6789".into(), "pii".into()),
            ("550e8400-e29b-41d4-a716-446655440000".into(), "none".into()),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709".into(), "none".into()),
            ("src/main/java/com/example/UserRepositoryImpl".into(), "none".into()),
        ];
        let r = evaluate(&samples);
        assert!(r.secret.precision >= 0.99, "secret precision {}", r.secret.precision);
        assert!(r.secret.recall >= 0.99, "secret recall {}", r.secret.recall);
        assert!(r.secret.fpr <= 0.01, "secret fpr {}", r.secret.fpr);
    }
}
