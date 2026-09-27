//! MLflow model-registry connector (named adapter over the model registry).
//!
//! ACP does not embed an MLflow client; it reads the MLflow REST registry response and maps each
//! registered model's latest version into an ACP model reference, which the server then puts through
//! its normal admission scan + signed AI-BOM path. This keeps ACP's inventory in sync with the data
//! science team's source of truth without ACP owning the training side. The mapping is pure and
//! unit-tested; the HTTP fetch lives in the server (which already has a client).

use serde_json::Value;

/// One model to import: its registry name, the version to record, its stage, and the artifact source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlflowModel {
    pub name: String,
    pub version: String,
    pub stage: String,
    pub source: String,
}

/// Parse an MLflow `registered-models/search` (or `/list`) response into one entry per model, taking
/// the highest version among its `latest_versions` (MLflow lists one latest per stage). Models with
/// no versions are skipped. Malformed entries are skipped rather than failing the whole import.
pub fn models_from_search(v: &Value) -> Vec<MlflowModel> {
    let mut out = Vec::new();
    let models = match v.get("registered_models").and_then(|m| m.as_array()) {
        Some(a) => a,
        None => return out,
    };
    for m in models {
        let name = match m.get("name").and_then(|n| n.as_str()) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        let versions = m.get("latest_versions").and_then(|l| l.as_array());
        let best = versions.and_then(|arr| {
            arr.iter()
                .filter_map(|lv| {
                    let ver = lv.get("version").and_then(|x| x.as_str())?;
                    let n: u64 = ver.parse().ok()?;
                    Some((n, lv))
                })
                .max_by_key(|(n, _)| *n)
                .map(|(_, lv)| lv)
        });
        if let Some(lv) = best {
            let version = lv.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let stage = lv.get("current_stage").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let source = lv.get("source").and_then(|x| x.as_str()).unwrap_or("").to_string();
            out.push(MlflowModel { name, version, stage, source });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn takes_highest_version_per_model_and_skips_empty() {
        let resp = json!({"registered_models": [
            {"name": "fraud-scorer", "latest_versions": [
                {"version": "2", "current_stage": "Staging", "source": "s3://a/2"},
                {"version": "5", "current_stage": "Production", "source": "s3://a/5"}
            ]},
            {"name": "no-versions", "latest_versions": []},
            {"name": "recommender", "latest_versions": [
                {"version": "1", "current_stage": "Production", "source": "s3://b/1"}
            ]}
        ]});
        let ms = models_from_search(&resp);
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0], MlflowModel { name: "fraud-scorer".into(), version: "5".into(), stage: "Production".into(), source: "s3://a/5".into() });
        assert_eq!(ms[1].name, "recommender");
    }

    #[test]
    fn empty_or_malformed_response_yields_nothing() {
        assert!(models_from_search(&json!({})).is_empty());
        assert!(models_from_search(&json!({"registered_models": "nope"})).is_empty());
    }
}
