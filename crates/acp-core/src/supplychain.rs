//! Supply-chain admission gate (gap-closure, section 3).
//!
//! Per positioning ACP does not build a model scanner; it builds the neutral admission gate and
//! calls an external scanner for the verdict. Before an MCP server, tool or model-class may be
//! allowed by any policy, it must carry provenance (a digest and a source) and pass admission. This
//! module is the pure decision; the caller supplies the provenance and the scanner verdict.

use serde::{Deserialize, Serialize};

/// An artifact entering the governed estate: an MCP server, a tool, or a model-class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// "mcp-server" | "tool" | "model-class".
    pub kind: String,
    pub name: String,
    /// Content digest (e.g. sha256 hex) of the artifact. Empty means no provenance: fail-closed.
    pub digest: String,
    /// Where it came from (URL, registry ref).
    pub source: String,
    /// Publisher identity, if known.
    pub publisher: String,
    /// Publisher signature over the digest, if the publisher provides attestation.
    pub signature: Option<String>,
}

/// The verdict from an external scanner (Protect AI ModelScan, HiddenLayer, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ScanVerdict {
    Clean,
    Findings { issues: Vec<String> },
    Unscanned,
}

/// The admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum Admission {
    Admit,
    Deny { reason: String },
}

impl Admission {
    pub fn admitted(&self) -> bool {
        matches!(self, Admission::Admit)
    }
    pub fn reason(&self) -> &str {
        match self {
            Admission::Admit => "admitted",
            Admission::Deny { reason } => reason,
        }
    }
}

/// Decide admission. Fail-closed:
///   - no digest (no provenance) is always denied;
///   - any scanner finding is denied;
///   - an unscanned artifact is denied when a scan is required for it (high-impact and the policy
///     requires scanning high-impact artifacts);
///   - otherwise admitted.
pub fn admit(
    artifact: &Artifact,
    scan: &ScanVerdict,
    require_scan_for_high_impact: bool,
    high_impact: bool,
) -> Admission {
    if artifact.digest.trim().is_empty() {
        return Admission::Deny {
            reason: "no provenance: artifact has no digest (fail-closed)".into(),
        };
    }
    match scan {
        ScanVerdict::Findings { issues } => Admission::Deny {
            reason: format!("scanner found {} issue(s): {}", issues.len(), issues.join("; ")),
        },
        ScanVerdict::Unscanned if require_scan_for_high_impact && high_impact => Admission::Deny {
            reason: "high-impact artifact is unscanned and a scan is required (fail-closed)".into(),
        },
        _ => Admission::Admit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(digest: &str) -> Artifact {
        Artifact {
            kind: "model-class".into(),
            name: "frontier/foo".into(),
            digest: digest.into(),
            source: "https://example/foo".into(),
            publisher: "acme".into(),
            signature: None,
        }
    }

    #[test]
    fn no_digest_is_denied() {
        assert!(!admit(&art(""), &ScanVerdict::Clean, false, false).admitted());
    }

    #[test]
    fn a_clean_scanned_artifact_is_admitted() {
        assert!(admit(&art("abc123"), &ScanVerdict::Clean, true, true).admitted());
    }

    #[test]
    fn findings_are_denied() {
        let d = admit(&art("abc123"), &ScanVerdict::Findings { issues: vec!["pickle exec".into()] }, false, false);
        assert!(!d.admitted());
        assert!(d.reason().contains("pickle exec"));
    }

    #[test]
    fn unscanned_high_impact_is_denied_when_required() {
        assert!(!admit(&art("abc123"), &ScanVerdict::Unscanned, true, true).admitted());
        // but a low-impact unscanned artifact is admitted
        assert!(admit(&art("abc123"), &ScanVerdict::Unscanned, true, false).admitted());
        // and if scanning is not required, unscanned is admitted
        assert!(admit(&art("abc123"), &ScanVerdict::Unscanned, false, true).admitted());
    }
}
