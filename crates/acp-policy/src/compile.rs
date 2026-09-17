//! Compile the YAML policy DSL to Cedar policy text (decision D2).
//!
//! Mapping:
//!   verdict     -> `@verdict(...)` annotation; `allow` -> `permit`, else -> `forbid`
//!   approvers   -> `@approvers("a,b")` annotation
//!   reason      -> `@reason("...")` annotation
//!   tool        -> `context.tool == "x"` / `like "x.*"` / omitted for `*`
//!   arg matcher -> guarded `context.args has k && <cond>` using Cedar operators
//!
//! At evaluation time (M2) the engine returns the determining policy id; its `@verdict`
//! resolves the four-way outcome.

use crate::dsl::{Matcher, Policy, Rule};
use acp_core::types::Verdict;

/// Compile a whole policy set to Cedar text.
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
        out.push_str(&format!("@approvers(\"{}\")\n", esc(&rule.approvers.join(","))));
    }
    if let Some(reason) = &rule.reason {
        out.push_str(&format!("@reason(\"{}\")\n", esc(reason)));
    }

    let effect = if rule.verdict == Verdict::Allow {
        "permit"
    } else {
        "forbid"
    };
    out.push_str(&format!("{effect}(principal, action, resource)\n"));

    let mut conds: Vec<String> = Vec::new();
    if let Some(tc) = tool_cond(&rule.when.tool) {
        conds.push(tc);
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

fn tool_cond(tool: &str) -> Option<String> {
    if tool == "*" {
        None
    } else if tool.contains('*') {
        Some(format!("context.tool like \"{}\"", esc(tool)))
    } else {
        Some(format!("context.tool == \"{}\"", esc(tool)))
    }
}

fn arg_cond(key: &str, m: &Matcher) -> String {
    let base = format!("context.args.{key}");
    let has = format!("context.args has {key}");
    let (op, val) = match m.op() {
        Some(pair) => pair,
        None => return format!("{has} /* empty matcher */"),
    };
    match op {
        "in" => {
            let items = val
                .as_sequence()
                .map(|s| s.iter().map(lit).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            format!("{has} && {base} in [{items}]")
        }
        "eq" => format!("{has} && {base} == {}", lit(val)),
        "ne" => format!("{has} && {base} != {}", lit(val)),
        "gt" => format!("{has} && {base} > {}", num(val)),
        "gte" => format!("{has} && {base} >= {}", num(val)),
        "lt" => format!("{has} && {base} < {}", num(val)),
        "lte" => format!("{has} && {base} <= {}", num(val)),
        "contains" => format!("{has} && {base} like \"*{}*\"", esc(str_of(val))),
        // Cedar has no regex; the proxy enforces it and sets a match flag in context.
        "regex" => format!("{has} /* regex enforced in proxy */"),
        "exists" => {
            if val.as_bool().unwrap_or(true) {
                has
            } else {
                format!("!({has})")
            }
        }
        // Data-class: the proxy classifies the value and sets `<key>_class` in context.
        "contains_class" => format!(
            "context.args has {key}_class && context.args.{key}_class == \"{}\"",
            esc(str_of(val))
        ),
        other => format!("{has} /* unknown matcher '{other}' */"),
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

/// Render a YAML scalar as a Cedar literal.
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
