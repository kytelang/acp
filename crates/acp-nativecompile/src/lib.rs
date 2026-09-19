//! Agent-native policy sync (phase D): compile one ACP policy into each coding agent's own
//! managed-settings, so the agent's non-MCP powers (shell, file, network) are governed by the same
//! source of truth. ACP is the policy ORIGIN; the agent stays the ENFORCER of its own sandbox. The
//! mapping is deliberately lossy (each vendor expresses less than model-v2): we emit the strictest
//! faithful translation and REPORT what a vendor cannot express, so those rules are visibly routed
//! to the proxy instead of silently dropped.

use acp_core::types::Verdict;
use acp_policy::dsl::{Policy, Rule};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Claude,
    Copilot,
    Gemini,
}

impl Vendor {
    pub fn parse(s: &str) -> Option<Vendor> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Vendor::Claude),
            "copilot" | "github-copilot" => Some(Vendor::Copilot),
            "gemini" | "gemini-cli" => Some(Vendor::Gemini),
            _ => None,
        }
    }
}

/// The result of compiling a policy for one vendor: the native settings document, the ids of rules
/// that mapped, and the ids of rules that could not be expressed natively (route these to the proxy).
#[derive(Debug, Clone)]
pub struct Compiled {
    pub settings: Value,
    pub covered: Vec<String>,
    pub uncovered: Vec<String>,
}

/// Resources that map to a coding agent's own powers. Everything else (database, payments,
/// messaging, ...) is an MCP-tool resource the agent cannot self-enforce, so it stays proxy-governed.
fn is_native_resource(res: &str) -> bool {
    matches!(res, "filesystem" | "network" | "source-code" | "secrets")
}

/// Native rule entries for a (resource, operation, vendor). Returned as vendor-specific selector
/// strings; the caller files them under deny/ask by verdict.
fn native_entries(vendor: Vendor, res: &str, op: &str) -> Vec<String> {
    let write_like = matches!(op, "write" | "delete" | "execute" | "any");
    match (vendor, res) {
        (Vendor::Claude, "filesystem") if write_like => vec!["Edit".into(), "Write".into()],
        (Vendor::Claude, "filesystem") => vec!["Read".into()],
        (Vendor::Claude, "network") => vec!["WebFetch".into(), "Bash(curl *)".into(), "Bash(wget *)".into()],
        (Vendor::Claude, "source-code") => vec!["Bash(git push *)".into(), "Bash(git commit *)".into()],
        (Vendor::Claude, "secrets") => vec!["Read(**/.env)".into(), "Read(**/*secret*)".into()],

        (Vendor::Copilot, "filesystem") if write_like => vec!["Write".into(), "Edit".into()],
        (Vendor::Copilot, "filesystem") => vec!["Read".into()],
        (Vendor::Copilot, "network") => vec!["Domain(*)".into()],
        (Vendor::Copilot, "source-code") => vec!["Shell(git push *)".into()],
        (Vendor::Copilot, "secrets") => vec!["Read(**/*secret*)".into()],

        (Vendor::Gemini, "filesystem") if write_like => vec!["WriteFileTool".into(), "EditTool".into()],
        (Vendor::Gemini, "filesystem") => vec!["ReadFileTool".into()],
        (Vendor::Gemini, "network") => vec!["WebFetchTool".into()],
        (Vendor::Gemini, "source-code") => vec!["ShellTool(git push)".into()],
        (Vendor::Gemini, "secrets") => vec!["ReadFileTool".into()],
        _ => vec![],
    }
}

/// Compile a policy for a vendor.
pub fn compile(policy: &Policy, vendor: Vendor) -> Compiled {
    let (mut deny, mut ask) = (Vec::new(), Vec::new());
    let (mut covered, mut uncovered) = (Vec::new(), Vec::new());

    for r in &policy.rules {
        match native_bucket(r, vendor, &mut deny, &mut ask) {
            true => covered.push(r.id.clone()),
            false => uncovered.push(r.id.clone()),
        }
    }
    dedup(&mut deny);
    dedup(&mut ask);

    let settings = match vendor {
        Vendor::Claude => json!({
            "permissions": { "deny": deny, "ask": ask },
            "disableBypassPermissionsMode": "disable"
        }),
        Vendor::Copilot => json!({
            "permissions": { "deny": deny, "ask": ask },
            "disableBypassPermissionsMode": true
        }),
        // Gemini expresses deny via tools.exclude; ask is not cleanly expressible, so ask-rules are
        // reported uncovered above (routed to the proxy).
        Vendor::Gemini => json!({
            "security": { "disableYoloMode": true },
            "tools": { "exclude": deny }
        }),
    };
    Compiled { settings, covered, uncovered }
}

/// File a rule's native entries; returns whether it was expressible for this vendor.
fn native_bucket(r: &Rule, vendor: Vendor, deny: &mut Vec<String>, ask: &mut Vec<String>) -> bool {
    let res = match &r.when.resource {
        Some(x) if is_native_resource(x) => x.clone(),
        _ => return false, // no resource, or a proxy-governed (MCP-tool) resource
    };
    let op = r.when.operation.as_deref().unwrap_or("any");
    let entries = native_entries(vendor, &res, op);
    if entries.is_empty() {
        return false;
    }
    match r.verdict {
        Verdict::Deny => {
            deny.extend(entries);
            true
        }
        Verdict::StepUp => {
            // Gemini has no clean "ask"; treat step-up as uncovered there.
            if vendor == Vendor::Gemini {
                false
            } else {
                ask.extend(entries);
                true
            }
        }
        // allow/shadow: nothing to tighten natively; the agent's default already permits.
        _ => false,
    }
}

fn dedup(v: &mut Vec<String>) {
    let mut seen = std::collections::BTreeSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> Policy {
        acp_policy::dsl::parse_str(
            "version: 1\ndefault: allow\nrules:\n\
             \x20 - id: no-fs-write\n    when: { resource: filesystem, operation: write }\n    verdict: deny\n\
             \x20 - id: no-egress\n    when: { resource: network, operation: egress }\n    verdict: deny\n\
             \x20 - id: secrets-ask\n    when: { resource: secrets, operation: read }\n    verdict: step_up\n\
             \x20 - id: no-db-delete\n    when: { resource: database, operation: delete }\n    verdict: deny\n",
        )
        .unwrap()
    }

    #[test]
    fn claude_maps_native_rules_and_reports_the_rest() {
        let c = compile(&pol(), Vendor::Claude);
        let deny = c.settings["permissions"]["deny"].as_array().unwrap();
        let deny: Vec<&str> = deny.iter().filter_map(|v| v.as_str()).collect();
        assert!(deny.contains(&"Edit") && deny.contains(&"Write"), "fs write -> Edit/Write deny");
        assert!(deny.contains(&"WebFetch"), "network egress -> WebFetch deny");
        let ask = c.settings["permissions"]["ask"].as_array().unwrap();
        assert!(ask.iter().any(|v| v == "Read(**/.env)"), "secrets step-up -> ask");
        assert_eq!(c.settings["disableBypassPermissionsMode"], "disable");
        // database delete is an MCP-tool resource: not native, routed to the proxy.
        assert!(c.uncovered.contains(&"no-db-delete".to_string()));
        assert!(c.covered.contains(&"no-fs-write".to_string()));
    }

    #[test]
    fn copilot_and_gemini_differ_and_report_losses() {
        let cop = compile(&pol(), Vendor::Copilot);
        assert_eq!(cop.settings["disableBypassPermissionsMode"], true);
        assert!(cop.settings["permissions"]["deny"].as_array().unwrap().iter().any(|v| v == "Domain(*)"));

        let gem = compile(&pol(), Vendor::Gemini);
        assert_eq!(gem.settings["security"]["disableYoloMode"], true);
        // Gemini cannot express "ask", so the secrets step-up rule is reported uncovered.
        assert!(gem.uncovered.contains(&"secrets-ask".to_string()));
        assert!(gem.settings["tools"]["exclude"].as_array().unwrap().iter().any(|v| v == "WriteFileTool"));
    }
}
