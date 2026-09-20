//! Discovery plane for un-governed AI usage (decision v2.3.1).
//!
//! Before you can govern agent traffic you have to find it. This compares observed tool endpoints
//! against the set already routed through the proxy and produces a "govern this next" worklist. It
//! also records what the discovery pass did NOT cover, so a partial scan never masquerades as
//! full coverage (the no-silent-truncation rule).

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// Observed endpoints not currently routed through the proxy: the worklist.
    pub ungoverned: Vec<String>,
    /// Scopes the pass could not inspect (e.g. a namespace with no read access).
    pub not_covered: Vec<String>,
}

/// Compare observed endpoints against the governed set. `uncovered_scopes` is passed through so the
/// report is explicit about gaps rather than silently complete.
pub fn discover(
    observed: &[String],
    governed: &[String],
    uncovered_scopes: &[String],
) -> DiscoveryReport {
    let gov: BTreeSet<&String> = governed.iter().collect();
    let mut ungoverned: Vec<String> = observed
        .iter()
        .filter(|e| !gov.contains(e))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    ungoverned.sort();
    let mut not_covered = uncovered_scopes.to_vec();
    not_covered.sort();
    not_covered.dedup();
    DiscoveryReport {
        ungoverned,
        not_covered,
    }
}


/// The kind of AI endpoint discovered in un-governed traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiKind {
    ModelApi,
    Mcp,
}

/// A shadow-AI endpoint: un-governed traffic that looks like AI usage, classified by provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiEndpoint {
    pub endpoint: String,
    pub kind: AiKind,
    pub provider: String,
}

/// Known model-API host fragments, mapped to a provider. Substring match so `host`, `host:443`, or a
/// full URL all classify. This is the "is this AI?" signal that turns a generic ungoverned worklist
/// into shadow-AI candidates.
const MODEL_API_HOSTS: &[(&str, &str)] = &[
    ("api.openai.com", "OpenAI"),
    ("openai.azure.com", "Azure OpenAI"),
    ("api.anthropic.com", "Anthropic"),
    ("claude.ai", "Anthropic"),
    ("bedrock-runtime", "AWS Bedrock"),
    ("bedrock.", "AWS Bedrock"),
    ("generativelanguage.googleapis.com", "Google Gemini"),
    ("aiplatform.googleapis.com", "Google Vertex"),
    ("api.cohere.ai", "Cohere"),
    ("api.cohere.com", "Cohere"),
    ("api.mistral.ai", "Mistral"),
    ("api.groq.com", "Groq"),
    ("api.together.xyz", "Together"),
    ("api.together.ai", "Together"),
    ("api.perplexity.ai", "Perplexity"),
    ("endpoints.huggingface", "HuggingFace"),
    ("api-inference.huggingface.co", "HuggingFace"),
    ("api.deepseek.com", "DeepSeek"),
    ("api.x.ai", "xAI"),
    ("githubcopilot.com", "GitHub Copilot"),
    ("chatgpt.com", "OpenAI"),
    ("gemini.google.com", "Google Gemini"),
];

/// Classify an endpoint as AI usage, if it looks like a model API or an MCP server.
pub fn classify_ai(endpoint: &str) -> Option<AiEndpoint> {
    let e = endpoint.to_ascii_lowercase();
    for (frag, provider) in MODEL_API_HOSTS {
        if e.contains(frag) {
            return Some(AiEndpoint { endpoint: endpoint.to_string(), kind: AiKind::ModelApi, provider: (*provider).to_string() });
        }
    }
    // MCP servers are custom, but a path or scheme hint is a useful weak signal.
    if e.contains("/mcp") || e.contains("mcp://") || e.ends_with("/sse") {
        return Some(AiEndpoint { endpoint: endpoint.to_string(), kind: AiKind::Mcp, provider: "MCP server".to_string() });
    }
    None
}

/// Find shadow AI: the un-governed observed endpoints that classify as AI usage. Callers route these
/// to a PEP (sanction) or block them at egress. Non-AI ungoverned endpoints are left to the worklist.
pub fn find_shadow_ai(observed: &[String], governed: &[String]) -> Vec<AiEndpoint> {
    let report = discover(observed, governed, &[]);
    let mut out: Vec<AiEndpoint> = report.ungoverned.iter().filter_map(|e| classify_ai(e)).collect();
    out.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ungoverned_endpoints_become_the_worklist() {
        let r = discover(
            &["a.tool".into(), "b.tool".into(), "c.tool".into()],
            &["b.tool".into()],
            &[],
        );
        assert_eq!(r.ungoverned, vec!["a.tool", "c.tool"]);
    }

    #[test]
    fn shadow_ai_is_classified_by_provider() {
        let observed = vec![
            "api.openai.com".to_string(),
            "api.anthropic.com:443".to_string(),
            "https://internal-payroll.corp/api".to_string(),
            "https://tools.corp/mcp".to_string(),
            "api.anthropic.com".to_string(), // already governed below
        ];
        let governed = vec!["api.anthropic.com".to_string()];
        let shadow = find_shadow_ai(&observed, &governed);
        // openai + anthropic:443 (ungoverned) + the mcp endpoint are shadow; internal-payroll is not
        // AI; bare api.anthropic.com is governed so excluded.
        let providers: Vec<&str> = shadow.iter().map(|s| s.provider.as_str()).collect();
        assert!(providers.contains(&"OpenAI"));
        assert!(providers.contains(&"Anthropic"));
        assert!(providers.contains(&"MCP server"));
        assert!(!shadow.iter().any(|s| s.endpoint.contains("payroll")), "non-AI not flagged");
        assert!(!shadow.iter().any(|s| s.endpoint == "api.anthropic.com"), "governed excluded");
    }

    #[test]
    fn uncovered_scopes_are_reported_not_hidden() {
        let r = discover(
            &["a.tool".into()],
            &[],
            &["ns:secret".into(), "ns:secret".into()],
        );
        assert_eq!(r.not_covered, vec!["ns:secret"], "gaps surfaced, deduped");
    }
}
