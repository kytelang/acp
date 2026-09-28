//! acp CLI commands: content.
use crate::common::*;
use serde_json::Value;
use std::process::ExitCode;

pub(crate) fn cmd_classify_eval(path: Option<&str>) -> ExitCode {
    let path = match path {
        Some(p) => p,
        None => return usage("acp classify-eval <dataset.jsonl>"),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut samples = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("acp: bad dataset line: {e}");
                return ExitCode::from(1);
            }
        };
        samples.push((
            v["text"].as_str().unwrap_or("").to_string(),
            v["label"].as_str().unwrap_or("none").to_string(),
        ));
    }
    let r = acp_core::classify::evaluate(&samples);
    println!(
        "classifier evaluation over {} samples (accuracy {:.3})",
        r.total, r.accuracy
    );
    println!(
        "  pii    precision {:.3}  recall {:.3}  fpr {:.3}  support {}",
        r.pii.precision, r.pii.recall, r.pii.fpr, r.pii.support
    );
    println!(
        "  secret precision {:.3}  recall {:.3}  fpr {:.3}  support {}",
        r.secret.precision, r.secret.recall, r.secret.fpr, r.secret.support
    );
    ExitCode::SUCCESS
}

/// Scan text with the first-party content firewall (injection / PII / secret / denied-topic).
///   acp content-scan <text-or-@file> [--deny-topic <t>]... [--block-secrets] [--no-redact-pii]
/// Prints the verdict JSON; exits 3 if the text is blocked.
pub(crate) fn cmd_content_scan(rest: &[String]) -> ExitCode {
    use acp_core::content::{scan_text, ContentPolicy};
    let Some(arg) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp content-scan <text-or-@file> [--deny-topic <t>] [--block-secrets] [--no-redact-pii]");
    };
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).unwrap_or_default()
    } else {
        arg.clone()
    };
    let mut topics = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--deny-topic" {
            if let Some(v) = it.next() { topics.push(v.clone()); }
        }
    }
    let policy = ContentPolicy {
        block_injection: true,
        block_secrets: rest.iter().any(|a| a == "--block-secrets"),
        redact_pii: !rest.iter().any(|a| a == "--no-redact-pii"),
        block_toxicity: rest.iter().any(|a| a == "--block-toxicity"),
        denied_topics: topics,
    };
    let v = scan_text(&policy, &text);
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    if v.block { ExitCode::from(3) } else { ExitCode::SUCCESS }
}

/// Evaluate a trained content model against a labelled dataset (the CI gate for ML models).
///   acp content-eval <model.json> <dataset.json> [--min-recall <r>] [--min-precision <p>]
/// dataset.json is an array of {"text": "...", "label": 0|1}. Exits 3 if below either threshold.
pub(crate) fn cmd_content_eval(rest: &[String]) -> ExitCode {
    use acp_core::content::{eval_injection, LinearScorer};
    let pos: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(model_path), Some(ds_path)) = (pos.first(), pos.get(1)) else {
        return usage("acp content-eval <model.json> <dataset.json> [--min-recall <r>] [--min-precision <p>]");
    };
    let scorer = match std::fs::read_to_string(model_path.as_str()).ok().and_then(|s| LinearScorer::from_json(&s).ok()) {
        Some(s) => s, None => { eprintln!("acp: cannot load model {model_path}"); return ExitCode::from(1); }
    };
    let items: Vec<Value> = match std::fs::read_to_string(ds_path.as_str()).ok().and_then(|s| serde_json::from_str(&s).ok()) {
        Some(Value::Array(a)) => a, _ => { eprintln!("acp: {ds_path} must be a JSON array of {{text,label}}"); return ExitCode::from(2); }
    };
    let samples: Vec<(String, bool)> = items.iter()
        .filter_map(|v| Some((v.get("text")?.as_str()?.to_string(), v.get("label")?.as_i64()? == 1)))
        .collect();
    if samples.is_empty() { eprintln!("acp: no samples in {ds_path}"); return ExitCode::from(2); }
    let m = eval_injection(&scorer, &samples);
    let min_recall: f32 = flag_value(rest, "--min-recall").and_then(|s| s.parse().ok()).unwrap_or(0.8);
    let min_precision: f32 = flag_value(rest, "--min-precision").and_then(|s| s.parse().ok()).unwrap_or(0.8);
    println!("content-eval: n={} precision={:.3} recall={:.3} fpr={:.3} accuracy={:.3}", m.n, m.precision, m.recall, m.fpr, m.accuracy);
    if m.recall < min_recall || m.precision < min_precision {
        eprintln!("GATE FAILED: recall {:.3} (min {:.3}) precision {:.3} (min {:.3})", m.recall, min_recall, m.precision, min_precision);
        return ExitCode::from(3);
    }
    eprintln!("gate passed (min recall {min_recall}, min precision {min_precision})");
    ExitCode::SUCCESS
}

/// Continuous adversarial testing: run the built-in obfuscation corpus through the content engine.
///   acp redteam [model.json] [--min-catch <r>]
/// With a model, uses signatures + ML; without, signatures only. Exits 3 below the catch threshold
/// or on any false positive.
pub(crate) fn cmd_redteam(rest: &[String]) -> ExitCode {
    use acp_core::content::{ContentPolicy, LinearScorer};
    use acp_core::redteam::{corpus, run};
    let model = rest.iter().find(|a| !a.starts_with("--"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| LinearScorer::from_json(&s).ok());
    let min_catch: f32 = flag_value(rest, "--min-catch").and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let cases = corpus();
    let r = run(&ContentPolicy::default(), model.as_ref(), &cases);
    println!("redteam: {}/{} attacks caught ({:.1}%), {} false positive(s) on {} benign",
        r.caught, r.attacks, r.catch_rate * 100.0, r.false_positives, r.benign);
    for (name, caught, n) in &r.per_transform {
        println!("  {:12} {}/{}", name, caught, n);
    }
    for m in &r.missed {
        println!("  MISSED {m}");
    }
    if r.catch_rate < min_catch || r.false_positives > 0 {
        eprintln!("GATE FAILED: catch-rate {:.3} (min {:.3}), false positives {}", r.catch_rate, min_catch, r.false_positives);
        return ExitCode::from(3);
    }
    eprintln!("gate passed (min catch {min_catch}, zero false positives)");
    ExitCode::SUCCESS
}

/// Check an answer's groundedness against a source context (baseline lexical detector).
///   acp groundedness <answer-or-@file> <context-or-@file> [--block-below <r>] [--claim-threshold <r>]
/// Prints the score and unsupported claims; exits 3 when the score is below --block-below.
pub(crate) fn cmd_groundedness(rest: &[String]) -> ExitCode {
    use acp_core::groundedness::groundedness;
    let pos: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(a), Some(c)) = (pos.first(), pos.get(1)) else {
        return usage("acp groundedness <answer-or-@file> <context-or-@file> [--block-below <r>] [--claim-threshold <r>]");
    };
    let read = |s: &str| -> String { s.strip_prefix('@').map(|p| std::fs::read_to_string(p).unwrap_or_default()).unwrap_or_else(|| s.to_string()) };
    let answer = read(a);
    let context = read(c);
    let block_below: f32 = flag_value(rest, "--block-below").and_then(|s| s.parse().ok()).unwrap_or(0.6);
    let claim_threshold: f32 = flag_value(rest, "--claim-threshold").and_then(|s| s.parse().ok()).unwrap_or(0.5);
    let r = groundedness(&answer, &context, claim_threshold);
    println!("groundedness: {:.2} ({} claim(s), {} unsupported)", r.score, r.claims.len(), r.ungrounded.len());
    for u in &r.ungrounded {
        println!("  UNSUPPORTED  {}", u.chars().take(90).collect::<String>());
    }
    if r.score < block_below {
        eprintln!("BELOW THRESHOLD: {:.2} < {:.2}", r.score, block_below);
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}
