//! Model-class taxonomy for the LLM gateway (phase C).
//!
//! Direct model API calls are governed by the same model-v2 policy as tools: a request is classified
//! into a RESOURCE (a model class, e.g. `frontier`, `standard`, `embeddings`) and an OPERATION
//! (`completion`, `embed`, `image`), both derived from the model name and API path, never from the
//! request body the caller controls. A rule like `when: { resource: frontier, principal: unattributed }
//! verdict: deny` then governs every frontier model at once. Same shape as the tool taxonomy beside it.

use crate::resource::pattern_matches;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRule {
    #[serde(rename = "match")]
    pub match_glob: String,
    pub class: String,
    pub operation: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelTaxonomy {
    pub version: String,
    #[serde(default)]
    pub rules: Vec<ModelRule>,
    #[serde(default = "default_class")]
    pub default_class: String,
    #[serde(default = "default_operation")]
    pub default_operation: String,
}

fn default_class() -> String {
    "other".to_string()
}
fn default_operation() -> String {
    "completion".to_string()
}

impl ModelTaxonomy {
    pub fn from_yaml(src: &str) -> Result<Self, String> {
        serde_yaml::from_str(src).map_err(|e| e.to_string())
    }

    /// Classify a model name into (class, operation), first matching rule wins, else the default.
    pub fn classify(&self, model: &str) -> (String, String) {
        for r in &self.rules {
            if pattern_matches(&r.match_glob, model) {
                return (r.class.clone(), r.operation.clone());
            }
        }
        (self.default_class.clone(), self.default_operation.clone())
    }
}

impl Default for ModelTaxonomy {
    fn default() -> Self {
        let rules = [
            ("*embedding*|text-embedding*", "embeddings", "embed"),
            ("gpt-4*|o1*|o3*|chatgpt-4o*", "frontier", "completion"),
            ("claude-3-opus*|claude-3.5*|claude-3-5*|claude-opus*|claude-sonnet-4*", "frontier", "completion"),
            ("gemini-1.5-pro*|gemini-2*pro*", "frontier", "completion"),
            ("gpt-3.5*|gpt-4o-mini*", "standard", "completion"),
            ("claude-3-haiku*|claude-haiku*", "standard", "completion"),
            ("gemini-1.5-flash*|gemini-*flash*", "standard", "completion"),
            ("dall-e*|*image*|stable-diffusion*", "image-gen", "image"),
        ]
        .iter()
        .map(|(m, c, o)| ModelRule {
            match_glob: (*m).to_string(),
            class: (*c).to_string(),
            operation: (*o).to_string(),
        })
        .collect();
        ModelTaxonomy {
            version: "model@default-1".into(),
            rules,
            default_class: "other".into(),
            default_operation: "completion".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_models() {
        let t = ModelTaxonomy::default();
        assert_eq!(t.classify("gpt-4o"), ("frontier".into(), "completion".into()));
        assert_eq!(t.classify("claude-3-opus-20240229"), ("frontier".into(), "completion".into()));
        assert_eq!(t.classify("gemini-1.5-pro"), ("frontier".into(), "completion".into()));
        assert_eq!(t.classify("gpt-3.5-turbo"), ("standard".into(), "completion".into()));
        assert_eq!(t.classify("text-embedding-3-large"), ("embeddings".into(), "embed".into()));
        assert_eq!(t.classify("dall-e-3"), ("image-gen".into(), "image".into()));
    }

    #[test]
    fn unknown_model_falls_to_other() {
        let t = ModelTaxonomy::default();
        assert_eq!(t.classify("some-new-llm"), ("other".into(), "completion".into()));
    }
}
