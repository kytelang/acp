//! LLM destination classification (audit F3). At an egress proxy, host and SNI tell you where a flow
//! is going but not what it is. This classifies a destination host as an LLM/model API vs general web,
//! from a built-in set of known provider hosts plus a configurable extra set, so the firewall can tag
//! flows and scope deep prompt/response inspection to LLM traffic (bounding latency) rather than
//! inspecting all internet traffic. Pure and host-based, so it is unit-testable without a network.

/// Built-in suffixes of well-known LLM / model API hosts.
const BUILTIN_LLM_SUFFIXES: &[&str] = &[
    "api.openai.com",
    "openai.azure.com",       // *.openai.azure.com (Azure OpenAI)
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.cohere.ai",
    "api.cohere.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.together.xyz",
    "api.perplexity.ai",
    "api.deepseek.com",
    "api.x.ai",
    "bedrock-runtime",        // bedrock-runtime.<region>.amazonaws.com
    "api-inference.huggingface.co",
    "api.replicate.com",
];

fn host_matches(host: &str, suffix: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    // Match either an exact host, a dot-suffix (sub.domain), or a contained token for the region-y ones.
    h == suffix || h.ends_with(&format!(".{suffix}")) || h.contains(suffix)
}

/// True if `host` is a known LLM / model API destination, considering the built-in list and any extra
/// hosts an operator has registered (for self-hosted or private models).
pub fn is_llm_host(host: &str, extra: &[String]) -> bool {
    if host.is_empty() { return false; }
    BUILTIN_LLM_SUFFIXES.iter().any(|s| host_matches(host, s))
        || extra.iter().any(|s| !s.is_empty() && host_matches(host, s))
}

/// Classify a destination as "llm" or "web".
pub fn classify_destination(host: &str, extra: &[String]) -> &'static str {
    if is_llm_host(host, extra) { "llm" } else { "web" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_and_custom_llm_hosts() {
        assert!(is_llm_host("api.openai.com", &[]));
        assert!(is_llm_host("my-resource.openai.azure.com", &[]));
        assert!(is_llm_host("bedrock-runtime.us-east-1.amazonaws.com", &[]));
        assert_eq!(classify_destination("api.anthropic.com", &[]), "llm");
        // general web is not LLM.
        assert_eq!(classify_destination("example.com", &[]), "web");
        assert!(!is_llm_host("github.com", &[]));
        // a self-hosted model host via the extra set.
        assert!(is_llm_host("llm.internal.corp", &["llm.internal.corp".to_string()]));
        assert_eq!(classify_destination("llm.internal.corp", &["llm.internal.corp".into()]), "llm");
    }
}
