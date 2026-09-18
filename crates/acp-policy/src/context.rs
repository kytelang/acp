//! Building the namespaced Cedar context from a tool call (decision D9), shared by the proxy and
//! the CLI so enforcement and offline testing use exactly the same derivation.

use acp_core::classify::classify;
use acp_core::impact::ImpactTaxonomy;
use acp_core::resource::ResourceTaxonomy;
use acp_core::types::BlastRadius;
use serde_json::{json, Map, Value};

/// Tool names are restricted to a safe charset (D9, safe entity ids). A malformed name is
/// rejected by the caller (fail-closed).
pub fn valid_tool(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

fn level_str(b: BlastRadius) -> &'static str {
    match b {
        BlastRadius::Low => "low",
        BlastRadius::Medium => "medium",
        BlastRadius::High => "high",
    }
}

/// Build the namespaced context: agent data under `args`, proxy-derived impact and class flags in
/// the trusted `impact`/`derived` namespaces the agent cannot populate.
pub fn build_context(tool: &str, args: &Value, env: &str) -> Value {
    build_context_with(tool, args, env, &ImpactTaxonomy::default())
}

/// Build the namespaced context using a specific (per-tenant, versioned) impact taxonomy (E4).
pub fn build_context_with(tool: &str, args: &Value, env: &str, tax: &ImpactTaxonomy) -> Value {
    // Identity unknown (unregistered / not yet wired): agent and app are empty, so agent/app-scoped
    // rules simply do not match and the default verdict applies.
    build_context_identified(tool, args, env, "", "", tax)
}

/// Build the context with the proxy-verified caller identity (`agent`, `app`) in the trusted
/// namespace. The agent cannot populate these: they come from the registry-verified identity, so a
/// per-agent or per-app rule cannot be spoofed by argument content.
pub fn build_context_identified(
    tool: &str,
    args: &Value,
    env: &str,
    agent: &str,
    app: &str,
    tax: &ImpactTaxonomy,
) -> Value {
    build_context_identified_full(tool, args, env, agent, app, "", tax, &ResourceTaxonomy::default())
}

/// The full model-v2 context: the verified agent AND human principal (D1), plus the proxy-derived
/// resource and operation the tool touches (D2/D3), all in the trusted namespace. `principal` is the
/// human the agent acts for ("unattributed" when none is verified); it is never taken from arguments.
/// `resource`/`operation` are classified from the tool name by the resource taxonomy, never from args.
#[allow(clippy::too_many_arguments)]
pub fn build_context_identified_full(
    tool: &str,
    args: &Value,
    env: &str,
    agent: &str,
    app: &str,
    principal: &str,
    tax: &ImpactTaxonomy,
    rtax: &ResourceTaxonomy,
) -> Value {
    let mut derived = Map::new();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                if let Some(class) = classify(s) {
                    derived.insert(format!("{k}_class"), Value::String(class.to_string()));
                }
            }
        }
    }
    let (res, op) = rtax.classify(tool);
    json!({
        "tool": tool,
        "args": args,
        "env": env,
        "impact": level_str(tax.score(tool, args)),
        "impact_taxonomy": tax.version,
        "principal_scopes": [],
        "agent": agent,
        "app": app,
        "principal": principal,
        "resource": res.as_str(),
        "operation": op.as_str(),
        "resource_taxonomy": rtax.version,
        "derived": Value::Object(derived),
    })
}
