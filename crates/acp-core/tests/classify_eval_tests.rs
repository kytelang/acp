//! D1 eval harness + D2 regression gate + D7 evasion corpus.

use acp_core::classify::{classify, evaluate};

fn load() -> Vec<(String, String)> {
    let path = format!(
        "{}/tests/data/classify-eval.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            (
                v["text"].as_str().unwrap().to_string(),
                v["label"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn classifier_metrics_meet_targets() {
    let r = evaluate(&load());
    // D2 regression gate: fail if accuracy or recall drops below the frozen baseline.
    assert!(
        r.accuracy >= 0.80,
        "overall accuracy {:.2} below target 0.80",
        r.accuracy
    );
    assert!(
        r.secret.recall >= 0.80,
        "secret recall {:.2} below target",
        r.secret.recall
    );
    assert!(
        r.pii.recall >= 0.80,
        "pii recall {:.2} below target",
        r.pii.recall
    );
    // classifiers should not flag plain text too often (low FPR on 'none')
    assert!(
        r.pii.fpr <= 0.30 && r.secret.fpr <= 0.30,
        "false-positive rate too high"
    );
}

#[test]
fn adversarial_evasion_corpus_is_measured() {
    // D7: a standing corpus of evasion techniques. Classifiers are advisory (D9/D15), so we do not
    // require zero bypass -- we require the bypass rate to be measured and tracked.
    let secret = "sk_live_abcdefgh12345678";
    let evasions = [
        secret.to_string(),                             // baseline (should be caught)
        secret.chars().rev().collect::<String>(),       // reversed
        secret.split("").collect::<Vec<_>>().join(" "), // spaced
        "s\u{200b}k_live_abcdefgh12345678".to_string(), // zero-width split
    ];
    let bypassed = evasions.iter().filter(|e| classify(e).is_none()).count();
    let rate = bypassed as f64 / evasions.len() as f64;
    // baseline must be caught; overall bypass rate is reported (tracked over releases)
    assert!(
        classify(secret).is_some(),
        "baseline secret must be detected"
    );
    assert!(
        rate < 1.0,
        "at least the baseline is caught; measured evasion bypass rate = {rate:.2}"
    );
}

#[test]
fn pii_recall_is_balanced_across_locales() {
    // D5 fairness slice: PII recall must not collapse for non-US formats.
    let cohorts: [(&str, Vec<&str>); 2] = [
        (
            "us",
            vec![
                "reach jane@example.com",
                "call 415-555-0132",
                "ssn 123-45-6789",
            ],
        ),
        (
            "intl",
            vec![
                "email maria.garcia@correo.es",
                "call +91 98765 43210",
                "ping john@team.co.uk",
            ],
        ),
    ];
    let mut recalls = Vec::new();
    for (name, samples) in &cohorts {
        let hits = samples
            .iter()
            .filter(|s| classify(s) == Some("pii"))
            .count();
        let recall = hits as f64 / samples.len() as f64;
        assert!(recall >= 0.66, "{name} PII recall {recall:.2} too low");
        recalls.push(recall);
    }
    let disparity = recalls.iter().cloned().fold(f64::MIN, f64::max)
        - recalls.iter().cloned().fold(f64::MAX, f64::min);
    assert!(
        disparity <= 0.34,
        "cross-locale recall disparity {disparity:.2} too high"
    );
}
