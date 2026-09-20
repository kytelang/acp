//! AI use-case / model registry with lifecycle gates (complete-platform GRC build).
//!
//! The governed object in a GRC programme is a registered use case moving through a lifecycle with
//! sign-off gates. This adds that: use cases move proposed -> assessed -> approved -> deployed ->
//! retired, and a transition is refused unless its gate is met (an assessment before "assessed", a
//! valid attestation before "approved"). Pure; the caller supplies the assessment id and the
//! attestation check.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Proposed,
    Assessed,
    Approved,
    Deployed,
    Retired,
}

impl Stage {
    pub fn parse(s: &str) -> Option<Stage> {
        match s.to_ascii_lowercase().as_str() {
            "proposed" => Some(Stage::Proposed),
            "assessed" => Some(Stage::Assessed),
            "approved" => Some(Stage::Approved),
            "deployed" => Some(Stage::Deployed),
            "retired" => Some(Stage::Retired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseCase {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub stage: Stage,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub assessment_id: Option<String>,
    #[serde(default)]
    pub model_classes: Vec<String>,
    pub created_ms: u64,
}

/// The outcome of a transition request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Ok,
    Refused(String),
}

impl Transition {
    pub fn ok(&self) -> bool {
        matches!(self, Transition::Ok)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UseCaseRegistry {
    pub use_cases: Vec<UseCase>,
}

impl UseCaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, uc: UseCase) {
        if let Some(e) = self.use_cases.iter_mut().find(|u| u.id == uc.id) {
            *e = uc;
        } else {
            self.use_cases.push(uc);
        }
    }

    pub fn get(&self, id: &str) -> Option<&UseCase> {
        self.use_cases.iter().find(|u| u.id == id)
    }

    pub fn by_stage(&self, stage: Stage) -> Vec<&UseCase> {
        self.use_cases.iter().filter(|u| u.stage == stage).collect()
    }

    /// Advance a use case to `to`, enforcing the gate. `has_assessment` is whether an assessment is
    /// linked; `has_attestation` is whether a valid approval attestation exists for it. Retiring is
    /// always allowed. Skipping stages forward is refused.
    pub fn advance(
        &mut self,
        id: &str,
        to: Stage,
        has_assessment: bool,
        has_attestation: bool,
    ) -> Transition {
        let uc = match self.use_cases.iter_mut().find(|u| u.id == id) {
            Some(u) => u,
            None => return Transition::Refused(format!("no such use case '{id}'")),
        };
        let from = uc.stage;
        let allowed = match (from, to) {
            (_, Stage::Retired) => Ok(()),
            (Stage::Proposed, Stage::Assessed) => {
                if has_assessment {
                    Ok(())
                } else {
                    Err("gate: an assessment must be linked before 'assessed'")
                }
            }
            (Stage::Assessed, Stage::Approved) => {
                if has_attestation {
                    Ok(())
                } else {
                    Err("gate: a valid approval attestation is required before 'approved'")
                }
            }
            (Stage::Approved, Stage::Deployed) => Ok(()),
            (a, b) if a == b => Ok(()),
            _ => Err("gate: illegal stage transition (no skipping)"),
        };
        match allowed {
            Ok(()) => {
                uc.stage = to;
                Transition::Ok
            }
            Err(e) => Transition::Refused(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uc(id: &str) -> UseCase {
        UseCase {
            id: id.into(),
            name: "n".into(),
            owner: "o".into(),
            stage: Stage::Proposed,
            tier: None,
            assessment_id: None,
            model_classes: vec![],
            created_ms: 0,
        }
    }

    #[test]
    fn assess_gate_requires_an_assessment() {
        let mut r = UseCaseRegistry::new();
        r.upsert(uc("u1"));
        assert!(!r.advance("u1", Stage::Assessed, false, false).ok());
        assert!(r.advance("u1", Stage::Assessed, true, false).ok());
        assert_eq!(r.get("u1").unwrap().stage, Stage::Assessed);
    }

    #[test]
    fn approve_gate_requires_an_attestation() {
        let mut r = UseCaseRegistry::new();
        r.upsert(uc("u1"));
        r.advance("u1", Stage::Assessed, true, false);
        assert!(!r.advance("u1", Stage::Approved, true, false).ok());
        assert!(r.advance("u1", Stage::Approved, true, true).ok());
    }

    #[test]
    fn cannot_skip_stages_but_can_always_retire() {
        let mut r = UseCaseRegistry::new();
        r.upsert(uc("u1"));
        assert!(!r.advance("u1", Stage::Deployed, true, true).ok(), "cannot jump proposed->deployed");
        assert!(r.advance("u1", Stage::Retired, false, false).ok(), "retire always allowed");
        assert_eq!(r.get("u1").unwrap().stage, Stage::Retired);
    }
}
