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
/// B6: extract candidate endpoint hosts from a real-world egress/proxy/audit log so `acp discover`
/// can ingest connector output, not just a hand-written host list. Supported `format` values:
///   - "squid": Squid/typical proxy access log (the URL is the 7th whitespace field).
///   - "csv": comma-separated; picks the first cell that looks like a URL or host (skips a header).
///   - "jsonl": one JSON object per line; reads `url` / `host` / `destination` / `dest`.
///   - anything else / "hosts": one host or URL per line (the original behaviour).
/// Each extracted value is reduced to its host and de-duplicated, preserving first-seen order.
pub fn parse_access_log(content: &str, format: &str) -> Vec<String> {
    let host_of = |s: &str| -> Option<String> {
        let s = s.trim().trim_matches('"');
        if s.is_empty() { return None; }
        // Strip scheme.
        let no_scheme = s.split("://").last().unwrap_or(s);
        // Take up to the first slash, then drop any userinfo and port.
        let hostport = no_scheme.split('/').next().unwrap_or(no_scheme);
        let host = hostport.rsplit('@').next().unwrap_or(hostport);
        let host = host.split(':').next().unwrap_or(host);
        if host.contains('.') && !host.contains(' ') { Some(host.to_string()) } else { None }
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut push = |h: Option<String>, out: &mut Vec<String>, seen: &mut std::collections::BTreeSet<String>| {
        if let Some(h) = h { if seen.insert(h.clone()) { out.push(h); } }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        match format {
            "squid" => {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // The URL is classically field index 6; fall back to any field with a scheme.
                let url = fields.get(6).copied().or_else(|| fields.iter().find(|f| f.contains("://")).copied());
                if let Some(u) = url { push(host_of(u), &mut out, &mut seen); }
            }
            "csv" => {
                if line.to_ascii_lowercase().starts_with("url,") || line.to_ascii_lowercase().starts_with("host,") || line.to_ascii_lowercase().starts_with("timestamp,") { continue; }
                let cell = line.split(',').find_map(|c| host_of(c));
                push(cell, &mut out, &mut seen);
            }
            "jsonl" => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    let val = v.get("url").or_else(|| v.get("host")).or_else(|| v.get("destination")).or_else(|| v.get("dest")).and_then(|x| x.as_str());
                    if let Some(u) = val { push(host_of(u), &mut out, &mut seen); }
                }
            }
            _ => { push(host_of(line), &mut out, &mut seen); }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_parses_squid_csv_jsonl_and_classifies_ai() {
        let squid = "1609459200.000 123 10.0.0.1 TCP_MISS/200 512 GET https://api.openai.com/v1/chat HTTP/1.1 -\n1609459201.000 45 10.0.0.2 TCP_MISS/200 100 POST https://intranet.example.com/ok HTTP/1.1 -";
        let hosts = parse_access_log(squid, "squid");
        assert!(hosts.contains(&"api.openai.com".to_string()), "squid connector extracts the model host");
        let ai: Vec<_> = hosts.iter().filter(|h| classify_ai(h).is_some()).collect();
        assert_eq!(ai.len(), 1, "only the model API classifies as AI");
        let csv = "timestamp,url\n2026,https://api.anthropic.com/v1/messages\n2026,https://example.com/x";
        assert!(parse_access_log(csv, "csv").contains(&"api.anthropic.com".to_string()));
        let jsonl = "{\"url\":\"https://generativelanguage.googleapis.com/v1\"}\n{\"host\":\"plain.example.com\"}";
        assert!(parse_access_log(jsonl, "jsonl").contains(&"generativelanguage.googleapis.com".to_string()));
    }

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
