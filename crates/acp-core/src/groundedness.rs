//! Groundedness checking (baseline).
//!
//! Detects when an answer introduces claims not supported by its provided source context. This is
//! the reliable form of "hallucination detection": groundedness against a source, not open-ended
//! factuality (which is unreliable for everyone). Reference-free factuality is out of scope and, per
//! the market, not dependable.
//!
//! Honest boundary: this baseline is LEXICAL. It measures how much of each answer sentence's content
//! words appear in the context. It catches an answer that invents content absent from the source, and
//! flags paraphrases that reuse few source words (a false positive). It is not semantic. A fine-tuned
//! entailment / NLI groundedness model (or an external groundedness API) is the upgrade, and drops in
//! behind the same Scorer seam. Use it where a source context exists (RAG, tool-augmented answers).

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "be", "been", "being", "to",
    "of", "in", "on", "at", "for", "with", "as", "by", "that", "this", "these", "those", "it", "its",
    "i", "you", "he", "she", "they", "we", "them", "his", "her", "their", "our", "your", "from",
    "so", "if", "then", "than", "not", "no", "do", "does", "did", "can", "will", "would", "should",
    "there", "here", "what", "which", "who", "how", "when", "where", "about", "into", "out", "up",
    "yes", "ok", "okay", "sure", "maybe", "hello", "hi", "thanks", "please", "also", "just", "very",
];

fn is_stop(w: &str) -> bool {
    STOPWORDS.contains(&w)
}

/// Content tokens: lowercased alphanumeric words longer than two characters, minus stopwords.
fn content_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_alphanumeric() {
            cur.push(lc);
        } else {
            if cur.len() > 2 && !is_stop(&cur) {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() > 2 && !is_stop(&cur) {
        out.push(cur);
    }
    out
}

/// Split into sentences on '.', '!', '?'.
fn sentences(text: &str) -> Vec<String> {
    text.split(|c| c == '.' || c == '!' || c == '?')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// One answer sentence and how much of it is supported by the context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimSupport {
    pub sentence: String,
    /// Fraction of the sentence's content words found in the context, in [0,1].
    pub support: f32,
    pub grounded: bool,
}

/// The groundedness result for an answer against a context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundednessReport {
    /// Fraction of sentences that are grounded, in [0,1]. 1.0 when there are no content sentences.
    pub score: f32,
    pub claims: Vec<ClaimSupport>,
    pub ungrounded: Vec<String>,
}

/// Check an answer against its source context. `claim_threshold` is the per-sentence support needed
/// to call a sentence grounded (for example 0.5). A sentence with no content words is treated as
/// grounded (nothing to hallucinate).
pub fn groundedness(answer: &str, context: &str, claim_threshold: f32) -> GroundednessReport {
    let ctx: BTreeSet<String> = content_tokens(context).into_iter().collect();
    let mut claims = Vec::new();
    let mut ungrounded = Vec::new();
    let mut grounded_count = 0usize;
    let sents = sentences(answer);
    let mut scored = 0usize;
    for s in &sents {
        let toks = content_tokens(s);
        if toks.is_empty() {
            continue;
        }
        scored += 1;
        let hit = toks.iter().filter(|t| ctx.contains(*t)).count();
        let support = hit as f32 / toks.len() as f32;
        let grounded = support >= claim_threshold;
        if grounded {
            grounded_count += 1;
        } else {
            ungrounded.push(s.clone());
        }
        claims.push(ClaimSupport { sentence: s.clone(), support, grounded });
    }
    let score = if scored == 0 { 1.0 } else { grounded_count as f32 / scored as f32 };
    GroundednessReport { score, claims, ungrounded }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grounded_answer_scores_high() {
        let ctx = "The Eiffel Tower is in Paris and was completed in 1889. It is made of iron.";
        let ans = "The Eiffel Tower is in Paris. It was completed in 1889.";
        let r = groundedness(ans, ctx, 0.5);
        assert!(r.score >= 0.9, "grounded answer score {}", r.score);
        assert!(r.ungrounded.is_empty());
    }

    #[test]
    fn fabricated_claim_is_flagged() {
        let ctx = "The Eiffel Tower is in Paris and was completed in 1889.";
        // The second sentence invents facts absent from the context.
        let ans = "The Eiffel Tower is in Paris. It was designed by Napoleon and hides a submarine base.";
        let r = groundedness(ans, ctx, 0.5);
        assert!(r.score < 1.0, "fabrication should lower the score");
        assert!(r.ungrounded.iter().any(|s| s.contains("submarine")), "the fabricated claim is flagged");
    }

    #[test]
    fn empty_or_contentless_answer_is_grounded() {
        assert_eq!(groundedness("Yes. OK.", "anything", 0.5).score, 1.0);
    }
}
