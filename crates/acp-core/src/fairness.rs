//! Fairness and performance testing of a model's outcomes (gap G15).
//!
//! ACP does not train or host the model; a harness feeds it labelled examples with a protected-group
//! attribute and the model's prediction, and this computes the standard fairness metrics so the result
//! can be stored as signed evidence linked to the model card. It is pure: predictions and labels come
//! from the caller, so the same inputs always produce the same metrics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One evaluation row: the protected group, the model's prediction (positive/negative) and the ground
/// truth label.
#[derive(Debug, Clone)]
pub struct EvalRow {
    pub group: String,
    pub predicted_positive: bool,
    pub actual_positive: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupMetrics {
    pub group: String,
    pub n: u64,
    pub positive_rate: f64,     // selection rate
    pub true_positive_rate: f64,
    pub accuracy: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FairnessReport {
    pub groups: Vec<GroupMetrics>,
    /// max positive-rate difference between groups (demographic parity gap).
    pub demographic_parity_gap: f64,
    /// max true-positive-rate difference between groups (equal-opportunity gap).
    pub equal_opportunity_gap: f64,
    pub overall_accuracy: f64,
}

/// Compute per-group and cross-group fairness metrics from labelled predictions.
pub fn evaluate(rows: &[EvalRow]) -> FairnessReport {
    let mut by: BTreeMap<String, Vec<&EvalRow>> = BTreeMap::new();
    for r in rows {
        by.entry(r.group.clone()).or_default().push(r);
    }
    let mut groups = Vec::new();
    let (mut correct, mut total) = (0u64, 0u64);
    for (group, rs) in &by {
        let n = rs.len() as u64;
        let pos = rs.iter().filter(|r| r.predicted_positive).count() as f64;
        let actual_pos: Vec<&&EvalRow> = rs.iter().filter(|r| r.actual_positive).collect();
        let tp = rs.iter().filter(|r| r.actual_positive && r.predicted_positive).count() as f64;
        let acc = rs.iter().filter(|r| r.predicted_positive == r.actual_positive).count() as f64;
        correct += acc as u64;
        total += n;
        groups.push(GroupMetrics {
            group: group.clone(),
            n,
            positive_rate: if n > 0 { pos / n as f64 } else { 0.0 },
            true_positive_rate: if !actual_pos.is_empty() { tp / actual_pos.len() as f64 } else { 0.0 },
            accuracy: if n > 0 { acc / n as f64 } else { 0.0 },
        });
    }
    let gap = |f: &dyn Fn(&GroupMetrics) -> f64| -> f64 {
        let vals: Vec<f64> = groups.iter().map(|g| f(g)).collect();
        match (vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max), vals.iter().cloned().fold(f64::INFINITY, f64::min)) {
            (hi, lo) if hi.is_finite() && lo.is_finite() => hi - lo,
            _ => 0.0,
        }
    };
    FairnessReport {
        demographic_parity_gap: gap(&|g| g.positive_rate),
        equal_opportunity_gap: gap(&|g| g.true_positive_rate),
        overall_accuracy: if total > 0 { correct as f64 / total as f64 } else { 0.0 },
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(g: &str, p: bool, a: bool) -> EvalRow { EvalRow { group: g.into(), predicted_positive: p, actual_positive: a } }

    #[test]
    fn detects_a_demographic_parity_gap() {
        // group A selected 100%, group B 0% -> parity gap 1.0.
        let mut rows = vec![];
        for _ in 0..10 { rows.push(row("A", true, true)); }
        for _ in 0..10 { rows.push(row("B", false, true)); }
        let r = evaluate(&rows);
        assert!((r.demographic_parity_gap - 1.0).abs() < 1e-9, "gap={}", r.demographic_parity_gap);
        assert!((r.equal_opportunity_gap - 1.0).abs() < 1e-9);
    }

    #[test]
    fn a_fair_model_has_near_zero_gaps() {
        let rows = vec![row("A", true, true), row("A", false, false), row("B", true, true), row("B", false, false)];
        let r = evaluate(&rows);
        assert_eq!(r.demographic_parity_gap, 0.0);
        assert_eq!(r.overall_accuracy, 1.0);
    }
}
