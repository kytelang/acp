//! Exhaustive conformance engine (decision B.8-4).
//!
//! Given a subject profile (the role played, risk tier, sector, jurisdiction, asset type), this
//! computes which controls in a framework APPLY, and assigns each a conformity state. "Exhaustive"
//! means every applicable control is assessed and every non-applicable control is recorded as
//! not-applicable with the predicate that excluded it: that pairing is the definition (see the plan,
//! Part B.5/B.6). The lightweight EU risk-tier screening in `assessment.rs` proposes the tier that
//! feeds `risk_tier` here; this module is the general, per-framework conformity mechanism the reports
//! (B.8-5) render from.

use crate::controls::{self, Control};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// What a subject IS, for deciding which controls bind it. Empty or None fields do not gate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectProfile {
    /// provider, deployer, developer, importer, distributor, controller, processor.
    #[serde(default)]
    pub roles: Vec<String>,
    /// EU-style risk tier: unacceptable, high, limited, minimal. None when the framework has no tier.
    #[serde(default)]
    pub risk_tier: Option<String>,
    #[serde(default)]
    pub sector: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    /// gpai, gpai_systemic, and similar asset qualifiers used by applicability predicates.
    #[serde(default)]
    pub asset_type: Option<String>,
}

/// The conformity state of a single control for a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Conformity {
    Conformant,
    Partial,
    NonConformant,
    NotApplicable,
    NotAssessed,
}

impl Conformity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Conformity::Conformant => "conformant",
            Conformity::Partial => "partial",
            Conformity::NonConformant => "non-conformant",
            Conformity::NotApplicable => "not-applicable",
            Conformity::NotAssessed => "not-assessed",
        }
    }
}

/// One control's assessment for a subject: whether it applies, its conformity state, and (for a
/// non-applicable control) the predicate that excluded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlAssessment {
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub reference: String,
    pub obligation_type: String,
    pub applicable: bool,
    pub conformity: Conformity,
    /// For a not-applicable control, why it was excluded (the failed predicate or role mismatch).
    #[serde(default)]
    pub exclusion_reason: String,
}

/// Split an applicability predicate on ` and ` into its conjuncts.
fn conjuncts(pred: &str) -> Vec<&str> {
    pred.split(" and ").map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
}

/// Parse a `risk_tier in [a, b]` list into its members.
fn in_list(rest: &str) -> Vec<String> {
    rest.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Evaluate one conjunct against the profile. An unrecognised conjunct is treated as satisfied
/// (permissive): an unknown predicate never silently excludes a control from assessment.
fn eval_conjunct(c: &str, p: &SubjectProfile) -> bool {
    if c == "always" {
        return true;
    }
    if let Some(rest) = c.strip_prefix("risk_tier in ") {
        let set = in_list(rest);
        return match &p.risk_tier {
            Some(t) => set.iter().any(|s| s == t),
            None => false, // the predicate needs a tier and the subject has none
        };
    }
    if let Some(v) = c.strip_prefix("role=") {
        return p.roles.iter().any(|r| r == v.trim());
    }
    if let Some(v) = c.strip_prefix("asset_type=") {
        return p.asset_type.as_deref() == Some(v.trim());
    }
    if let Some(v) = c.strip_prefix("sector=") {
        return p.sector.as_deref() == Some(v.trim());
    }
    if let Some(v) = c.strip_prefix("jurisdiction=") {
        return p.jurisdiction.as_deref() == Some(v.trim());
    }
    true
}

/// Does a control's role binding overlap the subject's roles? A control with no declared roles binds
/// any subject.
fn role_match(control_roles: &[String], subject_roles: &[String]) -> bool {
    control_roles.is_empty()
        || subject_roles.is_empty()
        || control_roles.iter().any(|r| subject_roles.contains(r))
}

/// Whether a control applies to a subject, and if not, the reason. Applies when its applicability
/// predicate holds AND its role binding overlaps the subject's roles.
pub fn applies(c: &Control, p: &SubjectProfile) -> (bool, String) {
    for conj in conjuncts(&c.applicability) {
        if !eval_conjunct(conj, p) {
            return (false, format!("predicate not met: {conj}"));
        }
    }
    if !role_match(&c.roles, &p.roles) {
        return (false, format!("binds roles [{}], subject is [{}]", c.roles.join(", "), p.roles.join(", ")));
    }
    (true, String::new())
}

/// The applicable controls of a framework for a subject.
pub fn applicable(framework: &str, p: &SubjectProfile) -> Vec<Control> {
    controls::for_framework(framework)
        .into_iter()
        .filter(|c| applies(c, p).0)
        .collect()
}

/// Assess every control of a framework for a subject. `satisfied` holds the control ids (within this
/// framework) that carry sufficient evidence; `partial` holds those with some but not sufficient
/// evidence. Applicable controls not in either set are `NotAssessed`; non-applicable controls are
/// `NotApplicable` with the exclusion reason. This is the exhaustive per-control result the reports
/// render (each applicable control assessed, each excluded control justified).
pub fn assess_framework(
    framework: &str,
    p: &SubjectProfile,
    satisfied: &HashSet<String>,
    partial: &HashSet<String>,
) -> Vec<ControlAssessment> {
    controls::for_framework(framework)
        .into_iter()
        .map(|c| {
            let (ok, why) = applies(&c, p);
            let conformity = if !ok {
                Conformity::NotApplicable
            } else if satisfied.contains(&c.id) {
                Conformity::Conformant
            } else if partial.contains(&c.id) {
                Conformity::Partial
            } else {
                Conformity::NotAssessed
            };
            ControlAssessment {
                framework: c.framework,
                control_id: c.id,
                title: c.title,
                reference: c.reference,
                obligation_type: c.obligation_type,
                applicable: ok,
                conformity,
                exclusion_reason: why,
            }
        })
        .collect()
}

/// A roll-up of an assessment: counts by conformity state and an applicable total, so a report can
/// show the conformity summary and prove exhaustiveness (applicable + not-applicable == full count,
/// zero not-assessed once complete).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformitySummary {
    pub total: usize,
    pub applicable: usize,
    pub not_applicable: usize,
    pub conformant: usize,
    pub partial: usize,
    pub non_conformant: usize,
    pub not_assessed: usize,
}

pub fn summarise(rows: &[ControlAssessment]) -> ConformitySummary {
    let mut s = ConformitySummary { total: rows.len(), ..Default::default() };
    for r in rows {
        match r.conformity {
            Conformity::NotApplicable => s.not_applicable += 1,
            Conformity::Conformant => { s.applicable += 1; s.conformant += 1; }
            Conformity::Partial => { s.applicable += 1; s.partial += 1; }
            Conformity::NonConformant => { s.applicable += 1; s.non_conformant += 1; }
            Conformity::NotAssessed => { s.applicable += 1; s.not_assessed += 1; }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eu_high_risk_provider_gets_the_high_risk_set_but_not_deployer_only_controls() {
        let p = SubjectProfile {
            roles: vec!["provider".into()],
            risk_tier: Some("high".into()),
            ..Default::default()
        };
        let ap = applicable("eu-ai-act", &p);
        let ids: HashSet<&str> = ap.iter().map(|c| c.id.as_str()).collect();
        // Core high-risk requirements apply to a provider.
        for want in ["art-9", "art-11", "art-12", "art-14", "art-15", "annex-iv-1"] {
            assert!(ids.contains(want), "provider high-risk should include {want}");
        }
        // A deployer-only obligation (FRIA, Art. 27) must NOT apply to a pure provider.
        assert!(!ids.contains("art-27"), "Art.27 (FRIA) binds deployers, not a pure provider");
        let _ = ids;
    }

    #[test]
    fn minimal_tier_excludes_high_risk_requirements() {
        let p = SubjectProfile {
            roles: vec!["provider".into()],
            risk_tier: Some("minimal".into()),
            ..Default::default()
        };
        let ap = applicable("eu-ai-act", &p);
        let ids: HashSet<&str> = ap.iter().map(|c| c.id.as_str()).collect();
        assert!(!ids.contains("art-9"), "risk_tier in [high] must not apply at minimal");
        // Prohibitions (applicability: always) still apply at any tier.
        assert!(ids.contains("art-5-a"), "Art.5 prohibitions always apply");
    }

    #[test]
    fn assessment_is_exhaustive_and_summarises() {
        let p = SubjectProfile { roles: vec!["provider".into()], risk_tier: Some("high".into()), ..Default::default() };
        let mut satisfied = HashSet::new();
        satisfied.insert("art-12".to_string());
        let rows = assess_framework("eu-ai-act", &p, &satisfied, &HashSet::new());
        let s = summarise(&rows);
        // Every control is either applicable or not-applicable: exhaustive coverage of the framework.
        assert_eq!(s.total, controls::for_framework("eu-ai-act").len());
        assert_eq!(s.applicable + s.not_applicable, s.total);
        assert_eq!(s.conformant, 1, "art-12 marked satisfied");
        assert!(s.not_assessed > 0, "other applicable controls are not yet assessed");
        // The excluded controls carry a reason.
        assert!(rows.iter().filter(|r| !r.applicable).all(|r| !r.exclusion_reason.is_empty()));
    }
}
