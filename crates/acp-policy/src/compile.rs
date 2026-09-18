//! Compile the YAML policy DSL to Cedar policy text (decision D2), with D9 namespacing.
//!
//! Namespaces in the Cedar `context`:
//!   context.args.*     agent-supplied arguments (untrusted; the only place agent data lands)
//!   context.env        proxy-injected environment (trusted)
//!   context.impact     proxy-derived impact level (trusted)
//!   context.derived.*  proxy-derived flags such as data-class (trusted; un-spoofable by args)
//!
//! The four-way verdict rides on a `@verdict` annotation read back from the determining policy.

use crate::dsl::{Matcher, Policy, Rule};
use acp_core::types::Verdict;

pub fn compile_to_cedar(policy: &Policy) -> String {
    policy
        .rules
        .iter()
        .map(compile_rule)
        .collect::<Vec<_>>()
        .join("\n\n")
        + "\n"
}

fn compile_rule(rule: &Rule) -> String {
    let mut out = String::new();
    out.push_str(&format!("@id(\"{}\")\n", esc(&rule.id)));
    out.push_str(&format!("@verdict(\"{}\")\n", verdict_str(rule.verdict)));
    if !rule.approvers.is_empty() {
        out.push_str(&format!(
            "@approvers(\"{}\")\n",
            esc(&rule.approvers.join(","))
        ));
    }
    if let Some(reason) = &rule.reason {
        out.push_str(&format!("@reason(\"{}\")\n", esc(reason)));
    }
    if !rule.obligations.is_empty() {
        // Obligations are outcome metadata, not matching conditions: encode them as JSON on an
        // annotation the evaluator reads back and the proxy executes at enforcement time.
        let js = serde_json::to_string(&rule.obligations).unwrap_or_default();
        out.push_str(&format!("@obligations(\"{}\")\n", esc(&js)));
    }

    let effect = if rule.verdict == Verdict::Allow {
        "permit"
    } else {
        "forbid"
    };
    out.push_str(&format!("{effect}(principal, action, resource)\n"));

    let mut conds: Vec<String> = Vec::new();
    if let Some(t) = &rule.when.tool {
        if let Some(tc) = tool_cond(t) {
            conds.push(tc);
        }
    }
    if let Some(a) = &rule.when.app {
        if let Some(c) = id_cond("context.app", a) {
            conds.push(c);
        }
    }
    if let Some(a) = &rule.when.agent {
        if let Some(c) = id_cond("context.agent", a) {
            conds.push(c);
        }
    }
    if let Some(pr) = &rule.when.principal {
        if let Some(c) = id_cond("context.principal", pr) {
            conds.push(c);
        }
    }
    if let Some(r) = &rule.when.resource {
        if let Some(c) = id_cond("context.resource", r) {
            conds.push(c);
        }
    }
    if let Some(o) = &rule.when.operation {
        if let Some(c) = id_cond("context.operation", o) {
            conds.push(c);
        }
    }
    if let Some(m) = &rule.when.env {
        conds.push(trusted_cond("context.env", m));
    }
    if let Some(m) = &rule.when.impact {
        conds.push(trusted_cond("context.impact", m));
    }
    for (key, matcher) in &rule.when.arg {
        conds.push(arg_cond(key, matcher));
    }
    let body = if conds.is_empty() {
        "true".to_string()
    } else {
        conds.join(" &&\n    ")
    };
    out.push_str(&format!("when {{\n    {body}\n}};"));
    out
}

/// A trusted-identity condition (app/agent): exact, glob (`*`), or None for any. These fields are
/// always present in the context (the proxy injects the verified identity, empty when unknown).
fn id_cond(path: &str, val: &str) -> Option<String> {
    if val == "*" {
        None
    } else if val.contains('*') {
        Some(format!("{path} like \"{}\"", esc(val)))
    } else {
        Some(format!("{path} == \"{}\"", esc(val)))
    }
}

fn tool_cond(tool: &str) -> Option<String> {
    if tool == "*" {
        None
    } else if tool.contains('*') {
        Some(format!("context.tool like \"{}\"", esc(tool)))
    } else {
        Some(format!("context.tool == \"{}\"", esc(tool)))
    }
}

/// A matcher on a trusted top-level field (env, impact). These fields are always present in the
/// context, so no `has` guard is needed.
fn trusted_cond(path: &str, m: &Matcher) -> String {
    let (op, val) = match m.op() {
        Some(p) => p,
        None => return "true".into(),
    };
    cmp(path, op, val)
}

fn arg_cond(key: &str, m: &Matcher) -> String {
    let base = format!("context.args.{key}");
    let has = format!("context.args has {key}");
    let (op, val) = match m.op() {
        Some(pair) => pair,
        None => return format!("{has} /* empty matcher */"),
    };
    if op == "contains_class" {
        // Data class lives in the un-spoofable derived namespace, never under agent args (D9).
        return format!(
            "context.derived has {key}_class && context.derived.{key}_class == \"{}\"",
            esc(str_of(val))
        );
    }
    format!("{has} && {}", cmp(&base, op, val))
}

/// Render a comparator against a fully-qualified path.
fn cmp(path: &str, op: &str, val: &serde_yaml::Value) -> String {
    match op {
        "in" => {
            let items = val
                .as_sequence()
                .map(|s| s.iter().map(lit).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            format!("{path} in [{items}]")
        }
        "eq" => format!("{path} == {}", lit(val)),
        "ne" => format!("{path} != {}", lit(val)),
        "gt" => format!("{path} > {}", num(val)),
        "gte" => format!("{path} >= {}", num(val)),
        "lt" => format!("{path} < {}", num(val)),
        "lte" => format!("{path} <= {}", num(val)),
        "contains" => format!("{path} like \"*{}*\"", esc(str_of(val))),
        "exists" => path.to_string(), // presence handled by the caller's `has`
        other => format!("false /* unknown matcher '{other}' */"),
    }
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::StepUp => "step_up",
        Verdict::Shadow => "shadow",
    }
}

fn lit(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => format!("\"{}\"", esc(s)),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => "\"\"".to_string(),
    }
}

fn num(v: &serde_yaml::Value) -> String {
    match v.as_f64() {
        Some(n) if n.fract() == 0.0 => format!("{}", n as i64),
        Some(n) => n.to_string(),
        None => "0".to_string(),
    }
}

fn str_of(v: &serde_yaml::Value) -> &str {
    v.as_str().unwrap_or("")
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
