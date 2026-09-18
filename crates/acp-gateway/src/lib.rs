//! LLM gateway decision core (phase C). Governs a direct model API call with the SAME policy engine,
//! model-v2 context, and obligations as agent tool calls. The gateway service (main.rs) is a thin
//! reverse proxy around `decide`.

use acp_core::modelclass::ModelTaxonomy;
use acp_core::types::Verdict;
use acp_policy::build_model_context;
use acp_policy::dsl::Obligation;
use acp_policy::PolicyEngine;
use serde_json::Value;

/// The gateway's decision for one model call.
#[derive(Debug, Clone)]
pub struct GatewayDecision {
    pub verdict: Verdict,
    pub obligations: Vec<Obligation>,
    /// The model class the request was classified into (the policy resource).
    pub resource: String,
    pub operation: String,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

/// Evaluate a model API call: classify the model, build the trusted context, and ask the shared PDP.
/// `app` is the calling service identity (the subject), `principal` the verified human (or
/// "unattributed"), `args` a small non-sensitive summary of the request (model, max_tokens, ...),
/// never the raw prompt (that is for a scan obligation, not policy matching).
#[allow(clippy::too_many_arguments)]
pub fn decide(
    engine: &PolicyEngine,
    tax: &ModelTaxonomy,
    model: &str,
    app: &str,
    principal: &str,
    args: &Value,
    env: &str,
) -> GatewayDecision {
    let (class, operation) = tax.classify(model);
    let ctx = build_model_context(model, &class, &operation, app, principal, args, env);
    let outcome = engine.evaluate(ctx);
    GatewayDecision {
        verdict: outcome.verdict,
        obligations: outcome.obligations,
        resource: class,
        operation,
        rule_id: outcome.rule_id,
        reason: outcome.reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eng(src: &str) -> PolicyEngine {
        PolicyEngine::from_yaml(src).unwrap()
    }

    #[test]
    fn frontier_models_denied_to_unattributed_callers() {
        let e = eng("version: 1\ndefault: allow\nrules:\n  - id: no-anon-frontier\n    when: { resource: frontier, principal: unattributed }\n    verdict: deny\n");
        let tax = ModelTaxonomy::default();
        // gpt-4o -> frontier; no verified human -> deny.
        let d = decide(&e, &tax, "gpt-4o", "svc-billing", "unattributed", &json!({}), "prod");
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.resource, "frontier");
        // A verified human is allowed.
        let d2 = decide(&e, &tax, "gpt-4o", "svc-billing", "alice@corp", &json!({}), "prod");
        assert_eq!(d2.verdict, Verdict::Allow);
        // A standard model is allowed even for anon (rule is frontier-scoped).
        let d3 = decide(&e, &tax, "gpt-3.5-turbo", "svc-billing", "unattributed", &json!({}), "prod");
        assert_eq!(d3.verdict, Verdict::Allow);
    }

    #[test]
    fn a_token_budget_obligation_rides_the_decision() {
        let e = eng("version: 1\ndefault: allow\nrules:\n  - id: cap-standard\n    when: { resource: standard }\n    verdict: allow\n    obligations:\n      - kind: rate_limit\n        max: 1000000\n        window_ms: 86400000\n");
        let tax = ModelTaxonomy::default();
        let d = decide(&e, &tax, "gpt-3.5-turbo", "svc", "alice@corp", &json!({}), "prod");
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.obligations.len(), 1);
    }
}
