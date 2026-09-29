//! Control catalogue (exhaustive-conformance build).
//!
//! The catalogue is versioned DATA, not code literals: one YAML file per framework-version under
//! `catalogue/`, embedded at build time and parsed here. Each framework carries its metadata (label,
//! version, type, record-keeping reference) and a coverage manifest (the source-of-truth section list),
//! and each control carries the exhaustive-conformance fields (hierarchy path, normative reference,
//! obligation type, bound roles, applicability predicate, evidence type, assessment method, crosswalk
//! and citation). `assessment.rs` and the reports draw from this, so control ids are one source of
//! truth across ACP.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

fn applic_always() -> String {
    "always".to_string()
}

/// One control (a single normative obligation) in a framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    pub framework: String,
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required_evidence: String,
    /// Hierarchy path, for example ["Chapter III", "Section 2", "Article 14"].
    #[serde(default)]
    pub path: Vec<String>,
    /// Normative reference, for example "Art. 14", "A.8.2", "CC6.1", "GOVERN 1.1".
    #[serde(default)]
    pub reference: String,
    /// govern | document | technical | process | transparency | oversight | record-keeping | prohibition.
    #[serde(default)]
    pub obligation_type: String,
    /// The roles this obligation binds: provider, deployer, developer, importer, distributor,
    /// controller, processor. Empty means it binds any role.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Applicability predicate over a subject profile (see `assessment`), for example
    /// "risk_tier in [high]", "role=deployer", "asset_type=gpai". Default "always".
    #[serde(default = "applic_always")]
    pub applicability: String,
    /// attestation | artefact | test | ledger.
    #[serde(default)]
    pub assessment_method: String,
    /// Equivalent controls in other frameworks, as "framework:id".
    #[serde(default)]
    pub crosswalk: Vec<String>,
    /// Citation to the official source (regulation article, standard clause).
    #[serde(default)]
    pub citation: String,
}

/// Framework-level metadata (one per catalogue file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Framework {
    pub slug: String,
    pub label: String,
    pub version: String,
    /// statutory_conformity | principles_based | standard | sectoral. This is what makes a UK
    /// principles-based report render differently from an EU statutory-conformity report.
    #[serde(default)]
    pub framework_type: String,
    #[serde(default)]
    pub effective_date: String,
    /// The record-keeping (or equivalent) reference used in the signed-pack envelope.
    #[serde(default)]
    pub record_keeping_reference: String,
    #[serde(default)]
    pub source: String,
}

/// A parsed catalogue file: the framework metadata, its coverage manifest, and its controls.
#[derive(Debug, Clone, Deserialize)]
struct CatalogueFile {
    #[serde(flatten)]
    framework: Framework,
    #[serde(default)]
    manifest: Vec<String>,
    controls: Vec<ControlDef>,
}

/// A control as authored in a catalogue file (the framework is injected from the file metadata).
#[derive(Debug, Clone, Deserialize)]
struct ControlDef {
    id: String,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    required_evidence: String,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    reference: String,
    #[serde(default)]
    obligation_type: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default = "applic_always")]
    applicability: String,
    #[serde(default)]
    assessment_method: String,
    #[serde(default)]
    crosswalk: Vec<String>,
    #[serde(default)]
    citation: String,
}

/// Every embedded catalogue file. Adding a framework is adding a file and a line here.
static CATALOGUE_YAML: &[(&str, &str)] = &[
    ("eu-ai-act@2024", include_str!("../catalogue/eu-ai-act@2024.yaml")),
    ("nist-ai-rmf@1.0", include_str!("../catalogue/nist-ai-rmf@1.0.yaml")),
    ("iso-42001@2023", include_str!("../catalogue/iso-42001@2023.yaml")),
    ("iso-27001@2022", include_str!("../catalogue/iso-27001@2022.yaml")),
    ("soc-2@2017", include_str!("../catalogue/soc-2@2017.yaml")),
    ("gdpr@2016", include_str!("../catalogue/gdpr@2016.yaml")),
    ("dpdp-2023@2023", include_str!("../catalogue/dpdp-2023@2023.yaml")),
    ("uk-ai@2023", include_str!("../catalogue/uk-ai@2023.yaml")),
    ("colorado-ai-act@2024", include_str!("../catalogue/colorado-ai-act@2024.yaml")),
    ("nyc-ll144@2023", include_str!("../catalogue/nyc-ll144@2023.yaml")),
    ("canada-aida@2022", include_str!("../catalogue/canada-aida@2022.yaml")),
    ("iso-23894@2023", include_str!("../catalogue/iso-23894@2023.yaml")),
];

struct Parsed {
    frameworks: Vec<Framework>,
    controls: Vec<Control>,
    // Read by the coverage-manifest completeness test; unused in non-test builds.
    #[cfg_attr(not(test), allow(dead_code))]
    manifests: Vec<(String, Vec<String>)>,
}

/// Parse a single catalogue file. Returns the framework, its controls (framework injected) and its
/// coverage manifest. Returns an error string so tests can assert every catalogue parses.
fn parse_one(name: &str, yaml: &str) -> Result<(Framework, Vec<Control>, Vec<String>), String> {
    let cf: CatalogueFile =
        serde_yaml::from_str(yaml).map_err(|e| format!("catalogue {name}: {e}"))?;
    let fw = cf.framework.clone();
    let controls = cf
        .controls
        .into_iter()
        .map(|d| Control {
            framework: fw.slug.clone(),
            id: d.id,
            title: d.title,
            description: d.description,
            required_evidence: d.required_evidence,
            path: d.path,
            reference: d.reference,
            obligation_type: d.obligation_type,
            roles: d.roles,
            applicability: d.applicability,
            assessment_method: d.assessment_method,
            crosswalk: d.crosswalk,
            citation: d.citation,
        })
        .collect();
    Ok((fw, controls, cf.manifest))
}

fn parsed() -> &'static Parsed {
    static CACHE: OnceLock<Parsed> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut frameworks = Vec::new();
        let mut controls = Vec::new();
        let mut manifests = Vec::new();
        for (name, yaml) in CATALOGUE_YAML {
            match parse_one(name, yaml) {
                Ok((fw, mut cs, manifest)) => {
                    manifests.push((fw.slug.clone(), manifest));
                    frameworks.push(fw);
                    controls.append(&mut cs);
                }
                // A malformed embedded catalogue is a build-asset error, caught by `catalogues_parse`.
                // At runtime we skip it rather than panic in a request handler.
                Err(e) => {
                    tracing::error!("{e}");
                }
            }
        }
        Parsed { frameworks, controls, manifests }
    })
}

/// The full built-in control library across every framework.
pub fn library() -> Vec<Control> {
    parsed().controls.clone()
}

/// Controls for one framework.
pub fn for_framework(framework: &str) -> Vec<Control> {
    parsed().controls.iter().filter(|c| c.framework == framework).cloned().collect()
}

/// Look up a control by (framework, id).
pub fn get(framework: &str, id: &str) -> Option<Control> {
    parsed().controls.iter().find(|c| c.framework == framework && c.id == id).cloned()
}

/// All framework metadata (label, version, type, record-keeping reference).
pub fn frameworks() -> Vec<Framework> {
    parsed().frameworks.clone()
}

/// Metadata for one framework slug.
pub fn framework(slug: &str) -> Option<Framework> {
    parsed().frameworks.iter().find(|f| f.slug == slug).cloned()
}

/// Resolved crosswalk edges across the whole catalogue: for each control that declares crosswalk
/// targets ("framework:token"), the resolved (from) -> (to) pairs as (framework, control_id). The
/// target token may be a control id or a reference (the catalogue uses both forms), so it is resolved
/// against the target framework's controls. Edges are directed as authored; callers usually treat the
/// relation as symmetric. Audit P1: this powers "author evidence once, satisfy many frameworks".
pub fn crosswalk_edges() -> Vec<((String, String), (String, String))> {
    let mut out = Vec::new();
    for c in library() {
        for x in &c.crosswalk {
            if let Some((fw, token)) = x.split_once(':') {
                let token = token.trim();
                if let Some(target) = for_framework(fw).into_iter().find(|t| t.id == token || t.reference == token) {
                    out.push(((c.framework.clone(), c.id.clone()), (fw.to_string(), target.id)));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogues_parse() {
        // Every embedded catalogue must parse; a syntax error fails CI here rather than at runtime.
        for (name, yaml) in CATALOGUE_YAML {
            parse_one(name, yaml).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn frameworks_are_canonical_and_unique() {
        let fws = frameworks();
        let canonical = [
            "eu-ai-act", "nist-ai-rmf", "iso-42001", "iso-27001", "soc-2", "gdpr", "dpdp-2023",
            "uk-ai", "colorado-ai-act", "nyc-ll144", "canada-aida", "iso-23894",
        ];
        let slugs: std::collections::BTreeSet<&str> = fws.iter().map(|f| f.slug.as_str()).collect();
        for want in canonical {
            assert!(slugs.contains(want), "missing canonical framework {want}");
        }
        // Each framework has a label, a version and a type.
        for f in &fws {
            assert!(!f.label.is_empty() && !f.version.is_empty(), "{} needs label+version", f.slug);
            assert!(!f.framework_type.is_empty(), "{} needs a framework_type", f.slug);
        }
    }

    #[test]
    fn control_ids_unique_per_framework() {
        for f in frameworks() {
            let cs = for_framework(&f.slug);
            let mut seen = std::collections::BTreeSet::new();
            for c in &cs {
                assert!(seen.insert(c.id.clone()), "duplicate id {}:{}", f.slug, c.id);
            }
            assert!(!cs.is_empty(), "{} has no controls", f.slug);
        }
    }

    #[test]
    fn coverage_manifest_is_satisfied() {
        // Exhaustiveness gate: every manifest section must be covered by at least one control whose
        // reference or path begins with that section string. An incomplete catalogue fails here.
        for (slug, manifest) in &parsed().manifests {
            let cs = for_framework(slug);
            for section in manifest {
                let covered = cs.iter().any(|c| {
                    c.reference.starts_with(section.as_str())
                        || c.path.iter().any(|p| p.starts_with(section.as_str()))
                });
                assert!(covered, "{slug}: manifest section '{section}' has no control covering it");
            }
        }
    }

    #[test]
    fn crosswalk_resolves_across_frameworks() {
        let edges = crosswalk_edges();
        assert!(!edges.is_empty(), "the catalogue authors crosswalk links");
        // EU AI Act art-12 (record-keeping) maps to GDPR records-of-processing.
        assert!(edges.iter().any(|((f, c), (tf, _))| f == "eu-ai-act" && c == "art-12" && tf == "gdpr"),
            "eu-ai-act:art-12 crosswalks to gdpr");
        // Every edge target resolves to a real control id in its framework.
        for (_, (tf, tid)) in &edges {
            assert!(get(tf, tid).is_some(), "crosswalk target {tf}:{tid} must resolve to a control");
        }
    }

    #[test]
    fn lookup_and_filter_work() {
        assert_eq!(get("eu-ai-act", "art-14").unwrap().title, "Human oversight");
        assert!(get("eu-ai-act", "art-999").is_none());
        assert!(for_framework("eu-ai-act").len() >= 40, "EU AI Act is authored exhaustively");
    }
}
