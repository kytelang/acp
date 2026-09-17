//! acp: the single CLI (init, verify, export, policy-compile, policy-test).

use acp_policy::{build_context, PolicyEngine};
use serde_json::Value;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("help") {
        "policy-compile" => match args.get(2) {
            Some(p) => policy_compile(p),
            None => usage("acp policy-compile <policy.yaml>"),
        },
        "policy-test" => run_policy_test(&args[2..]),
        "verify" => match args.get(2) {
            Some(p) => cmd_verify(p),
            None => usage("acp verify <ledger.db>"),
        },
        "verify-pack" => match args.get(2) {
            Some(p) => cmd_verify_pack(p),
            None => usage("acp verify-pack <pack.json>"),
        },
        "export" => match args.get(2) {
            Some(p) => cmd_export(p),
            None => usage("acp export <ledger.db>"),
        },
        "approve" => cmd_resolve(&args[2..], true),
        "deny" => cmd_resolve(&args[2..], false),
        "approvals" => match args.get(2) {
            Some(p) => cmd_list_approvals(p),
            None => usage("acp approvals <approvals.db>"),
        },
        "init" => cmd_init(args.get(2).map(String::as_str).unwrap_or("acp-demo")),
        "replay" => cmd_replay(&args[2..]),
        "purge" => cmd_purge(&args[2..]),
        "learn" => cmd_learn(args.get(2).map(String::as_str)),
        _ => usage("acp [init|verify|verify-pack|export|policy-compile|policy-test|approve|deny|approvals]"),
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("usage: {msg}");
    ExitCode::from(2)
}

fn load(path: &str) -> Result<PolicyEngine, ExitCode> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("acp: cannot read {path}: {e}");
        ExitCode::from(1)
    })?;
    PolicyEngine::from_yaml(&src).map_err(|e| {
        eprintln!("acp: invalid policy {path}: {e}");
        ExitCode::from(1)
    })
}

fn policy_compile(path: &str) -> ExitCode {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match acp_policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: invalid policy {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = acp_policy::validate(&policy) {
        eprintln!("acp: invalid policy {path}: {e}");
        return ExitCode::from(1);
    }
    print!("{}", acp_policy::compile_to_cedar(&policy));
    ExitCode::SUCCESS
}

/// `acp policy-test <policy.yaml> <calls.jsonl>`            -> verdict per call
/// `acp policy-test --diff <old.yaml> <new.yaml> <calls.jsonl>` -> only the calls whose verdict flips
fn run_policy_test(rest: &[String]) -> ExitCode {
    if rest.first().map(String::as_str) == Some("--diff") {
        if rest.len() < 4 {
            return usage("acp policy-test --diff <old.yaml> <new.yaml> <calls.jsonl>");
        }
        let old = match load(&rest[1]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let new = match load(&rest[2]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let calls = match read_calls(&rest[3]) {
            Ok(c) => c,
            Err(c) => return c,
        };
        let mut flips = 0;
        for (i, ctx) in calls.iter().enumerate() {
            let a = old.evaluate(ctx.clone()).verdict;
            let b = new.evaluate(ctx.clone()).verdict;
            if a != b {
                flips += 1;
                println!("flip call#{i} {}: {a:?} -> {b:?}", label(ctx));
            }
        }
        println!("{flips} of {} calls change verdict", calls.len());
        ExitCode::SUCCESS
    } else {
        if rest.len() < 2 {
            return usage("acp policy-test <policy.yaml> <calls.jsonl>");
        }
        let engine = match load(&rest[0]) {
            Ok(e) => e,
            Err(c) => return c,
        };
        let calls = match read_calls(&rest[1]) {
            Ok(c) => c,
            Err(c) => return c,
        };
        for (i, ctx) in calls.iter().enumerate() {
            let out = engine.evaluate(ctx.clone());
            println!(
                "call#{i} {}: {:?}{}",
                label(ctx),
                out.verdict,
                out.rule_id
                    .map(|r| format!(" (rule {r})"))
                    .unwrap_or_default()
            );
        }
        ExitCode::SUCCESS
    }
}

/// Each line of the calls file is `{"tool":"...","args":{...},"env":"..."}`. It is turned into a
/// namespaced context exactly as the proxy would build it.
fn read_calls(path: &str) -> Result<Vec<Value>, ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("acp: cannot read {path}: {e}");
        ExitCode::from(1)
    })?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).map_err(|e| {
            eprintln!("acp: {path}:{}: invalid JSON: {e}", n + 1);
            ExitCode::from(1)
        })?;
        let tool = v.get("tool").and_then(Value::as_str).unwrap_or("");
        let args = v
            .get("args")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let env = v.get("env").and_then(Value::as_str).unwrap_or("prod");
        out.push(build_context(tool, &args, env));
    }
    Ok(out)
}

fn cmd_verify(path: &str) -> ExitCode {
    match acp_ledger::verify_file(path) {
        Ok(()) => {
            println!("OK: {path} verifies");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_verify_pack(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let pack: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("acp: invalid pack: {e}");
            return ExitCode::from(1);
        }
    };
    match acp_ledger::verify_pack(&pack) {
        Ok(()) => {
            println!("OK: export pack verifies standalone");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_export(path: &str) -> ExitCode {
    match acp_ledger::export_file(path) {
        Ok(pack) => {
            println!("{}", serde_json::to_string_pretty(&pack).unwrap());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("acp: export failed: {e}");
            ExitCode::from(1)
        }
    }
}

const SAMPLE_POLICY: &str = "\
version: 1
default: allow
rules:
  - id: cap-spend
    when: { tool: \"payments.charge\", arg: { amount_cents: { gt: 50000 } } }
    verdict: step_up
    approvers: [\"finance\"]
  - id: no-prod-delete
    when:
      tool: \"db.*\"
      env: { eq: \"prod\" }
      arg:
        operation: { in: [\"delete\", \"drop\", \"truncate\"] }
    verdict: deny
";

fn cmd_init(dir: &str) -> ExitCode {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("acp: cannot create {dir}: {e}");
        return ExitCode::from(1);
    }
    let policy = format!("{dir}/policy.yaml");
    if let Err(e) = std::fs::write(&policy, SAMPLE_POLICY) {
        eprintln!("acp: cannot write {policy}: {e}");
        return ExitCode::from(1);
    }
    println!("Initialised an ACP workspace in {dir}/");
    println!("  policy:   {policy}");
    println!("  ledger:   {dir}/ledger.db      (created on first run)");
    println!();
    println!("Run the proxy in front of your MCP server:");
    println!(
        "  acp-proxy stdio --policy {policy} --ledger {dir}/ledger.db -- <your-mcp-server> [args]"
    );
    println!();
    println!("Then, after a step-up hold:");
    println!("  acp approvals {dir}/ledger.db.approvals        # list pending");
    println!("  acp approve   {dir}/ledger.db.approvals <id>   # approve one");
    println!("  acp verify    {dir}/ledger.db                  # verify the evidence");
    println!("  acp export    {dir}/ledger.db > pack.json      # regulator-ready pack");
    ExitCode::SUCCESS
}

fn cmd_learn(ledger: Option<&str>) -> ExitCode {
    let ledger = match ledger {
        Some(l) => l,
        None => return usage("acp learn <ledger.db>"),
    };
    let tools = match acp_ledger::observed_tools(ledger) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acp: {e}");
            return ExitCode::from(1);
        }
    };
    if tools.is_empty() {
        eprintln!("acp: no decision records observed in {ledger}; run the proxy in --shadow first");
        return ExitCode::from(1);
    }
    // Emit a compilable draft policy: high/medium-impact tools get a step-up gate; the rest default-allow.
    println!("# Draft policy proposed by `acp learn` from observed traffic in {ledger}.");
    println!(
        "# Review before enforcing. Tools observed: {}",
        tools
            .iter()
            .map(|(t, i)| format!("{t}({i})"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("version: 1");
    println!("default: allow");
    println!("rules:");
    for (tool, impact) in &tools {
        if impact == "high" || impact == "medium" {
            println!("  - id: review-{}", tool.replace(['.', '/'], "-"));
            println!("    when: {{ tool: \"{tool}\" }}");
            println!("    verdict: step_up");
            println!("    approvers: [\"review\"]");
            println!(
                "    reason: \"{impact}-impact tool seen in traffic; review before allowing\""
            );
        }
    }
    ExitCode::SUCCESS
}

fn cmd_purge(rest: &[String]) -> ExitCode {
    if rest.len() < 2 {
        return usage("acp purge <ledger.db> <older-than-days>");
    }
    let days: u64 = match rest[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("acp: days must be a number");
            return ExitCode::from(2);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let before = now.saturating_sub(days.saturating_mul(86_400_000));
    match acp_ledger::purge_args_file(&rest[0], before) {
        Ok(n) => {
            println!("purged {n} argument payloads older than {days} days");
            match acp_ledger::verify_file(&rest[0]) {
                Ok(()) => {
                    println!("ledger still verifies");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("WARNING: ledger verify after purge: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("acp: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_replay(rest: &[String]) -> ExitCode {
    if rest.len() < 3 {
        return usage("acp replay <ledger.db> <seq> <policy.yaml>");
    }
    let seq: u64 = match rest[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("acp: seq must be a number");
            return ExitCode::from(2);
        }
    };
    let (record, args) = match acp_ledger::read_record(&rest[0], seq) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("acp: {e}");
            return ExitCode::from(1);
        }
    };
    let action = &record["action"];
    let tool = action["tool"].as_str().unwrap_or("");
    let env = action["env"].as_str().unwrap_or("prod");
    let recorded = record["decision"]["verdict"].as_str().unwrap_or("");
    let policy_hash = record["decision"]["policy_hash"].as_str().unwrap_or("");
    if tool.is_empty() {
        eprintln!("acp: record #{seq} is not a decision (nothing to replay)");
        return ExitCode::from(1);
    }
    let args = match args {
        Some(a) => a,
        None => {
            eprintln!("acp: args for record #{seq} were purged; cannot replay");
            return ExitCode::from(1);
        }
    };
    let engine = match load(&rest[2]) {
        Ok(e) => e,
        Err(c) => return c,
    };
    if engine.hash() != policy_hash {
        eprintln!("WARNING: supplied policy hash {} differs from the recorded {} (policy changed since the decision)", &engine.hash()[..12], policy_hash.chars().take(12).collect::<String>());
    }
    let out = engine.evaluate(build_context(tool, &args, env));
    let replayed = match out.verdict {
        acp_core::types::Verdict::Allow => "allow",
        acp_core::types::Verdict::Deny => "deny",
        acp_core::types::Verdict::StepUp => "step_up",
        acp_core::types::Verdict::Shadow => "shadow",
    };
    if replayed == recorded {
        println!(
            "REPRODUCED: record #{seq} ({tool}) re-evaluates to '{replayed}', matching the ledger"
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "DRIFT: record #{seq} ({tool}) recorded '{recorded}' but now evaluates to '{replayed}'"
        );
        ExitCode::from(1)
    }
}

fn cmd_resolve(rest: &[String], approve: bool) -> ExitCode {
    if rest.len() < 2 {
        return usage("acp approve|deny <approvals.db> <id> [approver]");
    }
    let store = match acp_approvals::ApprovalStore::open(&rest[0]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot open approvals {}: {e}", rest[0]);
            return ExitCode::from(1);
        }
    };
    let approver = rest.get(2).map(String::as_str).unwrap_or("cli-user");
    match store.resolve(&rest[1], approve, approver, "cli") {
        Ok(()) => {
            println!(
                "{} {}",
                if approve { "approved" } else { "denied" },
                rest[1]
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("acp: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_list_approvals(path: &str) -> ExitCode {
    let store = match acp_approvals::ApprovalStore::open(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot open approvals {path}: {e}");
            return ExitCode::from(1);
        }
    };
    match store.list_pending() {
        Ok(list) => {
            if list.is_empty() {
                println!("(no pending approvals)");
            }
            for v in list {
                println!("{}  tool={}  presented={}", v.id, v.tool, v.presented);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("acp: {e}");
            ExitCode::from(1)
        }
    }
}

fn label(ctx: &Value) -> String {
    ctx.get("tool")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string()
}
