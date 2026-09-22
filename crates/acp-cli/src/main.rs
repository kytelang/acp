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
        "classify-eval" => cmd_classify_eval(args.get(2).map(String::as_str)),
        "canary" => cmd_canary(&args[2..]),
        "diagnose" => cmd_diagnose(&args[2..]),
        "sign-artifact" => cmd_sign_artifact(&args[2..]),
        "verify-artifact" => cmd_verify_artifact(&args[2..]),
        "bench-ledger" => cmd_bench_ledger(&args[2..]),
        "break-glass" => cmd_break_glass(&args[2..]),
        "app" => cmd_app(&args[2..]),
        "agent" => cmd_agent(&args[2..]),
        "native-compile" => cmd_native_compile(&args[2..]),
        "discover" => cmd_discover(&args[2..]),
        "coverage" => cmd_coverage(&args[2..]),
        "canary-egress" => cmd_canary_egress(&args[2..]),
        "aibom" => cmd_aibom(&args[2..]),
        "enroll" => cmd_enroll(&args[2..]),
        "siem" => cmd_siem(&args[2..]),
        "risk" => cmd_risk(&args[2..]),
        "content-scan" => cmd_content_scan(&args[2..]),
        "content-eval" => cmd_content_eval(&args[2..]),
        "redteam" => cmd_redteam(&args[2..]),
        "groundedness" => cmd_groundedness(&args[2..]),
        "controls" => cmd_controls(&args[2..]),
        "assess" => cmd_assess(&args[2..]),
        "attest" => cmd_attest(&args[2..]),
        "usecase" => cmd_usecase(&args[2..]),
        "conformity" => cmd_conformity(&args[2..]),
        "modelcard" => cmd_modelcard(&args[2..]),
        "intercept" => cmd_intercept(&args[2..]),
        "grc-report" => cmd_grc_report(&args[2..]),
        "ledger-backup" => cmd_ledger_backup(&args[2..]),
        "verify-enforcement" => cmd_verify_enforcement(&args[2..]),
        "registry" => cmd_registry(&args[2..]),
        "policy" => cmd_policy(&args[2..]),
        "posture" => cmd_posture(&args[2..]),
        "help" | "--help" | "-h" | "version" | "--version" | "-V" => print_help(),
        _ => usage("acp [init|verify|verify-pack|export|policy-compile|policy-test|approve|deny|approvals|canary|learn|replay|purge|classify-eval]"),
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("usage: {msg}");
    ExitCode::from(2)
}

fn print_help() -> ExitCode {
    println!("Varman, the Agent Control Plane (ACP)");
    println!("Vendor-neutral, on-premises runtime authorization and verifiable evidence for AI actions.");
    println!();
    println!("Common commands:");
    println!("  verify | export | verify-pack     evidence: verify a ledger, export a signed pack");
    println!("  policy-compile | policy-test      author and test policy");
    println!("  approve | deny | approvals        human-in-the-loop approvals");
    println!("  coverage | canary-egress          unavoidability posture");
    println!("  redteam | content-scan | content-eval | groundedness   content firewall + adversarial gate");
    println!("  discover | enroll | intercept     shadow-AI discovery and traffic interception");
    println!("  grc-report | assess | conformity | controls | attest | usecase | risk | modelcard   GRC");
    println!("  aibom | siem | native-compile | break-glass | init      supply chain, SIEM, agents, kill-switch");
    println!();
    println!("Run a command with no arguments to see its usage.");
    ExitCode::SUCCESS
}

/// Read the value following a `--flag` in an argv slice, if present.
fn flag_value(rest: &[String], flag: &str) -> Option<String> {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
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
# Posture: this starter uses default: allow so you can observe first (shadow mode). The governance
# goal is default: deny. Path there: run real traffic, then check `acp coverage` and
# `acp posture <ledger.db>`; once coverage is high and you understand the would-block list, add
# explicit allow rules for what should pass and switch this to default: deny.
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
    println!();
    println!("Move toward default-deny when ready:");
    println!("  acp posture   {dir}/ledger.db                  # is coverage high enough to flip?");
    ExitCode::SUCCESS
}

/// `acp posture <ledger.db> [--required <0..1>]`: read real decisions and report whether the tenant
/// is ready to switch the policy default from allow to deny (E6 staged path). Coverage is the
/// fraction of decisions that matched a named rule; the would-block set is the distinct tools whose
/// decisions matched no rule (they would newly deny under default-deny). Wires acp_core::posture.
fn cmd_posture(rest: &[String]) -> ExitCode {
    let path = match rest.first() {
        Some(p) => p,
        None => return usage("acp posture <ledger.db> [--required <0..1>]"),
    };
    let mut required = 0.8f64;
    let mut i = 1;
    while i < rest.len() {
        if rest[i] == "--required" {
            if let Some(v) = rest.get(i + 1).and_then(|s| s.parse::<f64>().ok()) {
                required = v;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    let pack = match acp_ledger::export_file(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: {e}");
            return ExitCode::from(1);
        }
    };
    let (mut decisions, mut with_rule) = (0u64, 0u64);
    let mut unmatched: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Some(recs) = pack["records"].as_array() {
        for r in recs {
            let canon = r["canonical"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            if let Some(c) = canon {
                if c["type"] == "decision" {
                    decisions += 1;
                    if c["decision"]["rule_id"].is_string() {
                        with_rule += 1;
                    } else if let Some(tool) = c["action"]["tool"].as_str() {
                        if !tool.is_empty() {
                            unmatched.insert(tool.to_string());
                        }
                    }
                }
            }
        }
    }
    let coverage = if decisions > 0 {
        with_rule as f64 / decisions as f64
    } else {
        0.0
    };
    let unmatched_v: Vec<String> = unmatched.into_iter().collect();
    let mut posture = acp_core::posture::Posture::new(required);
    match posture.enable_default_deny(coverage, &unmatched_v) {
        acp_core::posture::Enable::Ready { would_block } => {
            println!(
                "READY for default-deny: coverage {:.1}% >= required {:.1}% ({decisions} decisions)",
                coverage * 100.0,
                required * 100.0
            );
            if would_block.is_empty() {
                println!("  nothing would newly block.");
            } else {
                println!("  {} tool(s) would newly block; add explicit allow rules first:", would_block.len());
                for tname in &would_block {
                    println!("    - {tname}");
                }
            }
        }
        acp_core::posture::Enable::BlockedByCoverage { coverage, required } => {
            println!(
                "NOT READY: coverage {:.1}% < required {:.1}% ({decisions} decisions)",
                coverage * 100.0,
                required * 100.0
            );
            println!("  stay in shadow or partial; run more traffic and add rules, then re-check.");
        }
    }
    ExitCode::SUCCESS
}

fn cmd_classify_eval(path: Option<&str>) -> ExitCode {
    let path = match path {
        Some(p) => p,
        None => return usage("acp classify-eval <dataset.jsonl>"),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut samples = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("acp: bad dataset line: {e}");
                return ExitCode::from(1);
            }
        };
        samples.push((
            v["text"].as_str().unwrap_or("").to_string(),
            v["label"].as_str().unwrap_or("none").to_string(),
        ));
    }
    let r = acp_core::classify::evaluate(&samples);
    println!(
        "classifier evaluation over {} samples (accuracy {:.3})",
        r.total, r.accuracy
    );
    println!(
        "  pii    precision {:.3}  recall {:.3}  fpr {:.3}  support {}",
        r.pii.precision, r.pii.recall, r.pii.fpr, r.pii.support
    );
    println!(
        "  secret precision {:.3}  recall {:.3}  fpr {:.3}  support {}",
        r.secret.precision, r.secret.recall, r.secret.fpr, r.secret.support
    );
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

/// B2: canary / synthetic decisions prove the gate is actually live.
/// `acp canary <policy.yaml> <canaries.json>` evaluates a set of probe calls, each declaring the
/// verdict it must produce. Any mismatch exits non-zero so a scheduler pages: a mis-loaded policy
/// that lets a must-deny probe through is caught within one probe interval.
fn cmd_canary(rest: &[String]) -> ExitCode {
    let (policy, probes) = match (rest.first(), rest.get(1)) {
        (Some(p), Some(c)) => (p, c),
        _ => return usage("acp canary <policy.yaml> <canaries.json>"),
    };
    let engine = match load(policy) {
        Ok(e) => e,
        Err(c) => return c,
    };
    let raw = match std::fs::read_to_string(probes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {probes}: {e}");
            return ExitCode::from(1);
        }
    };
    let cases: Vec<serde_json::Value> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("acp: invalid canaries file: {e}");
            return ExitCode::from(1);
        }
    };
    let mut failures = 0;
    for (i, case) in cases.iter().enumerate() {
        let tool = case["tool"].as_str().unwrap_or("");
        let expect = case["expect"].as_str().unwrap_or("");
        let env = case["env"].as_str().unwrap_or("prod");
        let args = case.get("args").cloned().unwrap_or(serde_json::json!({}));
        let out = engine.evaluate(build_context(tool, &args, env));
        let got = match out.verdict {
            acp_core::types::Verdict::Allow => "allow",
            acp_core::types::Verdict::Deny => "deny",
            acp_core::types::Verdict::StepUp => "step_up",
            acp_core::types::Verdict::Shadow => "shadow",
        };
        if got == expect {
            println!("CANARY OK  #{i} {tool}: {got}");
        } else {
            failures += 1;
            println!("CANARY FAIL #{i} {tool}: expected '{expect}', got '{got}'");
        }
    }
    if failures == 0 {
        println!(
            "canary: all {} probes passed; the gate is live",
            cases.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("canary: {failures} probe(s) failed; policy may be mis-loaded (PAGE)");
        ExitCode::from(1)
    }
}

/// X.4: support without seeing arguments. `acp diagnose <ledger.db> <seq>` prints a redacted
/// bundle a support engineer can use to explain a deny/hold, decision id, tool, verdict, rule,
/// impact, hlc, and the args HASH, but never the raw arguments. Redaction is never disabled.
fn cmd_diagnose(rest: &[String]) -> ExitCode {
    let (ledger, seq_s) = match (rest.first(), rest.get(1)) {
        (Some(l), Some(s)) => (l, s),
        _ => return usage("acp diagnose <ledger.db> <seq>"),
    };
    let seq: u64 = match seq_s.parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("acp: seq must be a number");
            return ExitCode::from(2);
        }
    };
    // Deliberately ignore the args half of the tuple: the support bundle never carries payloads.
    let (record, _args) = match acp_ledger::read_record(ledger, seq) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("acp: cannot read record #{seq}: {e}");
            return ExitCode::from(1);
        }
    };
    let action = &record["action"];
    let decision = &record["decision"];
    let bundle = serde_json::json!({
        "seq": seq,
        "hlc": record["hlc"],
        "tool": action["tool"],
        "env": action["env"],
        "impact": action["impact"],
        "args_hash": action["args_hash"],
        "verdict": decision["verdict"],
        "rule_id": decision["rule_id"],
        "matched": decision["matched"],
        "policy_hash": decision["policy_hash"],
        "redacted": true
    });
    println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
    ExitCode::SUCCESS
}


/// H0.9: sign a release artifact (SBOM, binary, manifest) with an Ed25519 key. Writes <file>.sig
/// (hex signature) and <keyfile>.pub (hex public key). Generates the key if it does not exist.
fn cmd_sign_artifact(rest: &[String]) -> ExitCode {
    use acp_core::sign::{Ed25519Signer, Signer};
    let (file, keyfile) = match (rest.first(), rest.get(1)) {
        (Some(f), Some(k)) => (f, k),
        _ => return usage("acp sign-artifact <file> <keyfile>"),
    };
    let signer = match std::fs::read(keyfile) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = Ed25519Signer::generate();
            if acp_core::secret::write_key_secure(keyfile, &s.seed()).is_err() {
                eprintln!("acp: cannot write key {keyfile}");
                return ExitCode::from(1);
            }
            s
        }
    };
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("acp: cannot read {file}: {e}");
            return ExitCode::from(1);
        }
    };
    let sig = signer.sign(&data);
    let _ = std::fs::write(format!("{file}.sig"), hex::encode(&sig));
    let _ = std::fs::write(format!("{keyfile}.pub"), hex::encode(signer.public_key()));
    println!("signed {file} -> {file}.sig (public key {keyfile}.pub)");
    ExitCode::SUCCESS
}

/// H0.9: verify a release artifact's signature under a public key.
fn cmd_verify_artifact(rest: &[String]) -> ExitCode {
    use acp_core::sign::verify_ed25519;
    let (file, pubfile, sigfile) = match (rest.first(), rest.get(1), rest.get(2)) {
        (Some(f), Some(p), Some(s)) => (f, p, s),
        _ => return usage("acp verify-artifact <file> <keyfile.pub> <file.sig>"),
    };
    let read_hex = |path: &str| -> Option<Vec<u8>> {
        std::fs::read_to_string(path).ok().and_then(|s| hex::decode(s.trim()).ok())
    };
    let (pk, sig, data) = match (read_hex(pubfile), read_hex(sigfile), std::fs::read(file).ok()) {
        (Some(p), Some(s), Some(d)) => (p, s, d),
        _ => {
            eprintln!("acp: cannot read inputs");
            return ExitCode::from(1);
        }
    };
    if verify_ed25519(&pk, &data, &sig) {
        println!("VERIFIED: {file} signature is valid");
        ExitCode::SUCCESS
    } else {
        println!("INVALID: {file} signature does not verify");
        ExitCode::from(1)
    }
}


/// H2.1: load-run tooling. Append N decision records to a fresh ledger and time append + verify, so
/// the large-ledger cost model can be measured on real hardware (the 100M run is the same command
/// with a bigger N on a load box).
fn cmd_bench_ledger(rest: &[String]) -> ExitCode {
    use acp_core::sign::Ed25519Signer;
    use acp_ledger::Ledger;
    use std::time::Instant;
    let n: u64 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let path = std::env::temp_dir().join(format!("acp-bench-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut l = match Ledger::open(path.to_str().unwrap(), Box::new(Ed25519Signer::generate())) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("acp: {e}");
            return ExitCode::from(1);
        }
    };
    let rec = |i: u64| serde_json::json!({"schema":1,"type":"decision","tool":"payments.charge","verdict":"deny","n":i});
    let t0 = Instant::now();
    for i in 0..n {
        let _ = l.append(&format!("d{i}"), "decision", &rec(i), None);
    }
    let append_s = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    let ok = l.verify().is_ok();
    let verify_s = t1.elapsed().as_secs_f64();
    let _ = std::fs::remove_file(&path);
    println!(
        "bench-ledger n={n}: append {append_s:.3}s ({:.0} rec/s), verify {verify_s:.3}s ({:.0} rec/s), verified={ok}",
        n as f64 / append_s.max(1e-9),
        n as f64 / verify_s.max(1e-9)
    );
    if ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}


/// Verify an ACP enforcement attestation (P2 #14): the primitive a tool-server guard / sidecar uses
/// to reject un-proxied calls. Checks the x-acp-enforcement token against the pinned proxy pubkey and
/// a freshness bound. Exit 0 = valid, 1 = reject.
///   acp verify-enforcement <proxy-pubkey-hex> <token> [max-age-ms]
fn cmd_verify_enforcement(rest: &[String]) -> ExitCode {
    let (pk_hex, token) = match (rest.first(), rest.get(1)) {
        (Some(a), Some(b)) => (a, b),
        _ => return usage("acp verify-enforcement <proxy-pubkey-hex> <token> [max-age-ms]"),
    };
    let max_age: u64 = rest.get(2).and_then(|s| s.parse().ok()).unwrap_or(300_000);
    let pubkey = match hex::decode(pk_hex) {
        Ok(p) => p,
        Err(_) => { eprintln!("acp: pubkey must be hex"); return ExitCode::from(2); }
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).unwrap_or(0);
    if acp_core::attest::verify(&pubkey, token, now, max_age) {
        println!("VALID: attestation verifies (governed by the pinned proxy)");
        ExitCode::SUCCESS
    } else {
        eprintln!("REJECT: attestation missing, forged, wrong key, or stale");
        ExitCode::from(1)
    }
}

/// Backup the evidence ledger and verify the copy (P1 #8). Copies the db plus its WAL/SHM so the
/// snapshot is consistent, then runs the standalone verify on the destination and fails if it does
/// not check out. Quiesce writers for a fully consistent snapshot; for a live hot backup use the
/// sqlite backup API (future).
///   acp ledger-backup <src.db> <dst.db>
fn cmd_ledger_backup(rest: &[String]) -> ExitCode {
    let (src, dst) = match (rest.first(), rest.get(1)) {
        (Some(s), Some(d)) => (s, d),
        _ => return usage("acp ledger-backup <src.db> <dst.db>"),
    };
    for suffix in ["", "-wal", "-shm"] {
        let (s, d) = (format!("{src}{suffix}"), format!("{dst}{suffix}"));
        if std::path::Path::new(&s).exists() {
            if let Err(e) = std::fs::copy(&s, &d) {
                eprintln!("acp: copy {s} -> {d} failed: {e}");
                return ExitCode::from(1);
            }
        }
    }
    match acp_ledger::verify_file(dst) {
        Ok(()) => { println!("backup OK: {dst} copied and verifies"); ExitCode::SUCCESS }
        Err(e) => { eprintln!("acp: backup {dst} does NOT verify: {e}"); ExitCode::from(1) }
    }
}

/// Live discovery: poll an egress-log file and print each newly-seen shadow-AI endpoint. Runs until
/// interrupted. A weak but useful telemetry ingestion path; production feeds a sensor/eBPF stream.
fn discover_watch(file: &str) -> ExitCode {
    use acp_core::discovery::{classify_ai, AiKind};
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut offset: u64 = 0;
    eprintln!("acp: watching {file} for shadow AI (ctrl-c to stop)");
    loop {
        if let Ok(content) = std::fs::read_to_string(file) {
            let bytes = content.len() as u64;
            if bytes < offset {
                offset = 0; // file truncated/rotated
            }
            for line in content[offset as usize..].lines() {
                let ep = line.trim();
                if ep.is_empty() || ep.starts_with('#') || !seen.insert(ep.to_string()) {
                    continue;
                }
                if let Some(ai) = classify_ai(ep) {
                    let kind = match ai.kind { AiKind::ModelApi => "model-api", AiKind::Mcp => "mcp" };
                    println!("SHADOW AI [{kind:9}] {:22} {}", ai.provider, ai.endpoint);
                }
            }
            offset = bytes;
        }
        std::thread::sleep(std::time::Duration::from_millis(1500));
    }
}

/// GRC projection (phase F): read the tamper-evident ledger and print an evidence-backed compliance
/// report mapping the signed decisions to EU AI Act / NIST AI RMF / ISO 42001 controls.
///   acp grc-report <ledger.db>
fn cmd_grc_report(rest: &[String]) -> ExitCode {
    use acp_core::grc::{report, EvidenceSummary};
    let Some(ledger) = rest.first() else {
        return usage("acp grc-report <ledger.db>");
    };
    let pack = match acp_ledger::export_file(ledger) {
        Ok(p) => p,
        Err(e) => { eprintln!("acp: cannot read ledger {ledger}: {e}"); return ExitCode::from(1); }
    };
    let mut s = EvidenceSummary { signed_ledger: true, ..Default::default() };
    if let Some(recs) = pack.get("records").and_then(|v| v.as_array()) {
        for r in recs {
            let canon = match r.get("canonical").and_then(|v| v.as_str()).and_then(|h| hex::decode(h).ok()) {
                Some(b) => b, None => continue,
            };
            let rec: serde_json::Value = match serde_json::from_slice(&canon) { Ok(v) => v, Err(_) => continue };
            if rec.get("type").and_then(|v| v.as_str()) != Some("decision") { continue; }
            s.total_decisions += 1;
            let dec = rec.get("decision").cloned().unwrap_or_default();
            match dec.get("verdict").and_then(|v| v.as_str()) {
                Some("deny") => s.denies += 1,
                Some("step_up") => s.step_ups += 1,
                _ => {}
            }
            if dec.get("rule_id").and_then(|v| v.as_str()) == Some("break-glass") { s.kill_switch_events += 1; }
            if let Some(obs) = dec.get("obligations").and_then(|v| v.as_array()) {
                if obs.iter().any(|o| o.as_str().map(|x| x.contains("Redact")).unwrap_or(false)) { s.redactions += 1; }
            }
        }
    }
    s.policy_in_force = s.total_decisions > 0;
    println!("ACP evidence-backed compliance report  (ledger: {ledger})");
    println!("  {} decisions | {} denies | {} step-ups | {} kill-switch | {} redactions | signed ledger\n",
        s.total_decisions, s.denies, s.step_ups, s.kill_switch_events, s.redactions);
    let mut fw = "";
    for c in report(&s) {
        if c.framework != fw { println!("[{}]", c.framework); fw = c.framework; }
        let mark = match c.status.as_str() { "satisfied" => "PASS", "partial" => "PART", _ => "GAP " };
        println!("  {mark}  {:11} {:32} {}", c.control_id, c.title, c.rationale);
    }
    ExitCode::SUCCESS
}

/// Discovery plane (phase E): read observed egress endpoints (one per line) and report shadow AI,
/// classified by provider. Optional second file lists already-governed endpoints to exclude.
///   acp discover <observed.txt> [governed.txt]
fn cmd_discover(rest: &[String]) -> ExitCode {
    use acp_core::discovery::{find_shadow_ai, AiKind};
    let Some(obs_file) = rest.first() else {
        return usage("acp discover <observed.txt> [governed.txt]");
    };
    let read_lines = |f: &str| -> Vec<String> {
        std::fs::read_to_string(f)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };
    // --watch: continuously tail the observed file and flag newly-seen shadow AI (live telemetry
    // ingestion seed; point it at what a network sensor / egress proxy appends).
    if rest.iter().any(|a| a == "--watch") {
        return discover_watch(obs_file);
    }
    let observed = read_lines(obs_file);
    let governed = rest.get(1).map(|f| read_lines(f)).unwrap_or_default();
    let shadow = find_shadow_ai(&observed, &governed);
    if shadow.is_empty() {
        println!("no shadow AI found in {} observed endpoint(s)", observed.len());
        return ExitCode::SUCCESS;
    }
    println!("SHADOW AI: {} un-governed AI endpoint(s) found:", shadow.len());
    for s in &shadow {
        let kind = match s.kind { AiKind::ModelApi => "model-api", AiKind::Mcp => "mcp" };
        println!("  [{kind:9}] {:22} {}", s.provider, s.endpoint);
    }
    println!("\nnext: sanction (route through a PEP) or block (egress deny) each.");
    ExitCode::SUCCESS
}

/// Compute a coverage attestation: cross-reference observed AI endpoints against the governed
/// (enrolled) set, list ungoverned or leaky paths, and optionally sign the report.
///   acp coverage <observed.txt> <governed.txt> [--fail-open] [--leaky <msg>]... [--key <hex>] [--require-full]
/// Prints the (signed) report JSON to stdout and a summary to stderr. With --require-full, exits 3
/// when the estate is not fully contained (useful as a CI/rollout gate).
fn cmd_coverage(rest: &[String]) -> ExitCode {
    use acp_core::coverage::compute;
    use acp_core::discovery::{classify_ai, AiKind};
    use std::collections::BTreeSet;

    let positionals: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let Some(obs_file) = positionals.first() else {
        return usage("acp coverage <observed.txt> <governed.txt> [--fail-open] [--leaky <msg>] [--key <hex>] [--require-full]");
    };
    let read_lines = |f: &str| -> Vec<String> {
        std::fs::read_to_string(f)
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };
    let observed_raw = read_lines(obs_file);
    // Governed set: either from a --registry (what the interception registry actively covers) or a
    // plain governed-endpoints file (positional 2).
    let registry = flag_value(rest, "--registry")
        .and_then(|f| std::fs::read_to_string(&f).ok())
        .and_then(|s| acp_core::interception::EndpointRegistry::from_yaml(&s).ok());
    let governed: BTreeSet<String> = match &registry {
        Some(reg) => observed_raw.iter().filter(|ep| reg.covers(ep, "", 443)).cloned().collect(),
        None => positionals.get(1).map(|f| read_lines(f).into_iter().collect()).unwrap_or_default(),
    };

    // Derive a kind for each observed endpoint via the discovery classifier; unknown otherwise.
    let observed: Vec<(String, String)> = observed_raw
        .iter()
        .map(|ep| {
            let kind = match classify_ai(ep).map(|e| e.kind) {
                Some(AiKind::ModelApi) => "model-api",
                Some(AiKind::Mcp) => "mcp",
                None => "unknown",
            };
            (ep.clone(), kind.to_string())
        })
        .collect();

    // Leaky containment signals.
    let mut leaky: Vec<String> = Vec::new();
    if rest.iter().any(|a| a == "--fail-open") {
        leaky.push("a PEP is running with --fail-open (unrecorded calls possible)".into());
    }
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--leaky" {
            if let Some(m) = it.next() {
                leaky.push(m.clone());
            }
        }
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let report = compute(&observed, &governed, leaky, now_ms);

    // Optional signing.
    let key_hex = flag_value(rest, "--key");
    let out = match key_hex {
        Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
            Some(seed) => {
                let s = acp_core::sign::Ed25519Signer::from_seed(&seed);
                serde_json::to_string_pretty(&report.clone().sign(&s)).unwrap_or_default()
            }
            None => {
                eprintln!("acp: --key must be 32-byte hex");
                return ExitCode::from(2);
            }
        },
        None => serde_json::to_string_pretty(&report).unwrap_or_default(),
    };
    println!("{out}");
    eprintln!(
        "coverage: {}% ({}/{} governed); {} ungoverned; {} leaky signal(s)",
        report.coverage_pct,
        report.governed,
        report.total,
        report.ungoverned().len(),
        report.leaky.len()
    );
    for u in report.ungoverned() {
        eprintln!("  UNGOVERNED [{:9}] {}", u.kind, u.endpoint);
    }
    for l in &report.leaky {
        eprintln!("  LEAKY  {l}");
    }
    if rest.iter().any(|a| a == "--require-full") && !report.fully_contained() {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// Egress canary: attempt a DIRECT (un-proxied) TCP connection to each governed model/tool host and
/// assert it is refused. The network allowlist should make direct access impossible, so a reachable
/// host is a containment breach. Exits 3 if any breach is found.
///   acp canary-egress <targets.txt> [--timeout-ms <n>]
/// targets.txt: one "host:port [kind]" per line (the hosts that must NOT be directly reachable).
fn cmd_canary_egress(rest: &[String]) -> ExitCode {
    use acp_core::egress::{evaluate_probes, Probe};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let Some(targets_file) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp canary-egress <targets.txt> [--timeout-ms <n>]");
    };
    let timeout_ms: u64 = flag_value(rest, "--timeout-ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1500);

    let lines: Vec<String> = std::fs::read_to_string(targets_file)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.is_empty() {
        eprintln!("acp: no targets in {targets_file}");
        return ExitCode::from(2);
    }

    let mut probes = Vec::new();
    for line in &lines {
        let mut parts = line.split_whitespace();
        let target = parts.next().unwrap_or("").to_string();
        let kind = parts.next().unwrap_or("endpoint").to_string();
        // Try to resolve+connect directly; success means the host is reachable off-ACP.
        let reachable = match target.to_socket_addrs() {
            Ok(mut addrs) => addrs.any(|addr| {
                TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
            }),
            Err(_) => false, // cannot resolve => not directly reachable from here
        };
        probes.push(Probe { target, kind, reachable_directly: reachable });
    }

    let result = evaluate_probes(&probes);
    if result.ok() {
        println!("egress canary OK: {} target(s) all refused direct access", probes.len());
        ExitCode::SUCCESS
    } else {
        println!("egress canary BREACH: {} host(s) reachable off-ACP:", result.breaches.len());
        for b in &result.breaches {
            println!("  BREACH {b}");
        }
        for c in &result.contained {
            println!("  ok     {c}");
        }
        ExitCode::from(3)
    }
}

/// Emit a signed AI bill of materials (CycloneDX) from an artifacts file, running each artifact
/// through the supply-chain admission gate.
///   acp aibom <artifacts.json> [--require-scan] [--key <hex>] [--strict]
/// artifacts.json: an array of objects {kind,name,digest,source,publisher,signature?,scan?,
/// high_impact?,pin?,policy?} where scan is "clean" | "unscanned" | {"findings":[..]}.
/// Prints the (signed) CycloneDX doc to stdout, a summary to stderr; --strict exits 3 if any
/// artifact is denied admission.
fn cmd_aibom(rest: &[String]) -> ExitCode {
    use acp_core::aibom::{AiBom, BomEntry};
    use acp_core::supplychain::{admit, Artifact, ScanVerdict};

    let Some(file) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp aibom <artifacts.json> [--require-scan] [--key <hex>] [--strict]");
    };
    let raw = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {file}: {e}");
            return ExitCode::from(1);
        }
    };
    let items: Vec<Value> = match serde_json::from_str(&raw) {
        Ok(Value::Array(a)) => a,
        _ => {
            eprintln!("acp: {file} must be a JSON array of artifacts");
            return ExitCode::from(2);
        }
    };
    let require_scan = rest.iter().any(|a| a == "--require-scan");

    let parse_scan = |v: &Value| -> ScanVerdict {
        match v {
            Value::String(s) if s == "clean" => ScanVerdict::Clean,
            Value::String(s) if s == "unscanned" => ScanVerdict::Unscanned,
            Value::Object(o) => {
                let issues = o
                    .get("findings")
                    .and_then(|f| f.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                ScanVerdict::Findings { issues }
            }
            _ => ScanVerdict::Unscanned,
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut entries: Vec<BomEntry> = Vec::new();
    for it in &items {
        let s = |k: &str| it.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let artifact = Artifact {
            kind: s("kind"),
            name: s("name"),
            digest: s("digest"),
            source: s("source"),
            publisher: s("publisher"),
            signature: it.get("signature").and_then(|v| v.as_str()).map(String::from),
        };
        let scan = it.get("scan").map(parse_scan).unwrap_or(ScanVerdict::Unscanned);
        let high = it.get("high_impact").and_then(|v| v.as_bool()).unwrap_or(false);
        let admission = admit(&artifact, &scan, require_scan, high);
        entries.push(BomEntry {
            artifact,
            scan,
            admission,
            integrity_pin: it.get("pin").and_then(|v| v.as_str()).map(String::from),
            policy_in_force: it.get("policy").and_then(|v| v.as_str()).map(String::from),
        });
    }
    let bom = AiBom { generated_ms: now_ms, entries };
    let denied = bom.denied().len();

    let key_hex = flag_value(rest, "--key");
    let out = match key_hex {
        Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
            Some(seed) => {
                let s = acp_core::sign::Ed25519Signer::from_seed(&seed);
                serde_json::to_string_pretty(&bom.sign(&s)).unwrap_or_default()
            }
            None => {
                eprintln!("acp: --key must be 32-byte hex");
                return ExitCode::from(2);
            }
        },
        None => serde_json::to_string_pretty(&bom.cyclonedx()).unwrap_or_default(),
    };
    println!("{out}");
    eprintln!("AI-BOM: {} artifact(s); {denied} denied admission", bom.entries.len());
    for d in bom.denied() {
        eprintln!("  DENIED {:12} {}  ({})", d.artifact.kind, d.artifact.name, d.admission.reason());
    }
    if rest.iter().any(|a| a == "--strict") && denied > 0 {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// Manage shadow-AI dispositions (enroll / quarantine / accept-risk), feeding the coverage report
/// and the MDM/CASB allow+block export.
///   acp enroll record <log.json> <endpoint> <enroll|quarantine|accept-risk> [--kind K] [--operator O] [--reason R] [--expires-ms N] --key <hex>
///   acp enroll governed <log.json>        (enrolled endpoints, one per line; feed to `acp coverage`)
///   acp enroll export-mdm <log.json>      (allow/block JSON for MDM/CASB)
fn cmd_enroll(rest: &[String]) -> ExitCode {
    use acp_core::discovery::{classify_ai, AiKind};
    use acp_core::enrollment::{Disposition, EnrollmentLog};

    let sub = rest.first().map(String::as_str).unwrap_or("");
    let load_log = |path: &str| -> EnrollmentLog {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    match sub {
        "record" => {
            let Some(log_path) = rest.get(1) else {
                return usage("acp enroll record <log.json> <endpoint> <enroll|quarantine|accept-risk> [--kind K] [--operator O] [--reason R] [--expires-ms N] --key <hex>");
            };
            let Some(endpoint) = rest.get(2) else {
                return usage("acp enroll record <log.json> <endpoint> <enroll|quarantine|accept-risk> ...");
            };
            let Some(action) = rest.get(3) else {
                return usage("acp enroll record <log.json> <endpoint> <enroll|quarantine|accept-risk> ...");
            };
            let key_hex = match flag_value(rest, "--key") {
                Some(h) => h,
                None => {
                    eprintln!("acp: enroll record requires --key <hex> (dispositions are signed)");
                    return ExitCode::from(2);
                }
            };
            let seed: [u8; 32] = match hex::decode(&key_hex).ok().and_then(|b| b.try_into().ok()) {
                Some(s) => s,
                None => {
                    eprintln!("acp: --key must be 32-byte hex");
                    return ExitCode::from(2);
                }
            };
            let signer = acp_core::sign::Ed25519Signer::from_seed(&seed);
            let kind = flag_value(rest, "--kind").unwrap_or_else(|| {
                match classify_ai(endpoint).map(|e| e.kind) {
                    Some(AiKind::ModelApi) => "model-api".into(),
                    Some(AiKind::Mcp) => "mcp".into(),
                    None => "unknown".into(),
                }
            });
            let operator = flag_value(rest, "--operator").unwrap_or_else(|| "unknown".into());
            let reason = flag_value(rest, "--reason").unwrap_or_default();
            let disposition = match action.as_str() {
                "enroll" => Disposition::Enroll,
                "quarantine" => Disposition::Quarantine,
                "accept-risk" => {
                    let ttl: u64 = flag_value(rest, "--expires-ms").and_then(|s| s.parse().ok()).unwrap_or(86_400_000);
                    Disposition::AcceptRisk { expires_ms: now_ms + ttl }
                }
                other => {
                    eprintln!("acp: unknown disposition '{other}' (enroll|quarantine|accept-risk)");
                    return ExitCode::from(2);
                }
            };
            let mut log = load_log(log_path);
            log.record(&signer, endpoint, &kind, disposition, &operator, &reason, now_ms);
            match serde_json::to_string_pretty(&log) {
                Ok(s) => {
                    if std::fs::write(log_path, s).is_err() {
                        eprintln!("acp: cannot write {log_path}");
                        return ExitCode::from(1);
                    }
                }
                Err(_) => return ExitCode::from(1),
            }
            eprintln!("recorded {action} for {endpoint}; governed={}, blocked={}", log.governed().len(), log.blocklist().len());
            ExitCode::SUCCESS
        }
        "governed" => {
            let Some(log_path) = rest.get(1) else {
                return usage("acp enroll governed <log.json>");
            };
            for ep in load_log(log_path).governed() {
                println!("{ep}");
            }
            ExitCode::SUCCESS
        }
        "export-mdm" => {
            let Some(log_path) = rest.get(1) else {
                return usage("acp enroll export-mdm <log.json>");
            };
            let mdm = load_log(log_path).export_mdm(now_ms);
            println!("{}", serde_json::to_string_pretty(&mdm).unwrap_or_default());
            ExitCode::SUCCESS
        }
        _ => usage("acp enroll <record|governed|export-mdm> <log.json> ..."),
    }
}

/// Render a ledger's governed decisions to a SIEM line format for forwarding.
///   acp siem <ledger.db> --format <cef|ocsf|syslog>
fn cmd_siem(rest: &[String]) -> ExitCode {
    use acp_core::siem::{to_cef, to_ocsf, to_syslog, DecisionEvent};
    let Some(db) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp siem <ledger.db> --format <cef|ocsf|syslog>");
    };
    let format = flag_value(rest, "--format").unwrap_or_else(|| "cef".into());
    let pack = match acp_ledger::export_file(db) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: cannot export {db}: {e}");
            return ExitCode::from(1);
        }
    };
    let empty = vec![];
    let records = pack["records"].as_array().unwrap_or(&empty);
    let mut n = 0u64;
    for r in records {
        // Each record's canonical field is hex-encoded canonical JSON of the Record.
        let canon = match r["canonical"].as_str().and_then(|h| hex::decode(h).ok()) {
            Some(b) => b,
            None => continue,
        };
        let rec: Value = match serde_json::from_slice(&canon) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Only governed decisions carry a nested `decision.verdict`; skip other record kinds
        // (outcome, guard-reject, ...). Fields are nested under `action` and `decision`.
        let verdict = match rec.get("decision").and_then(|d| d.get("verdict")).and_then(|v| v.as_str()) {
            Some(v) => v.to_ascii_lowercase(),
            None => continue,
        };
        let action = rec.get("action");
        let decision = rec.get("decision");
        let get = |o: Option<&Value>, k: &str| o.and_then(|x| x.get(k)).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ev = DecisionEvent {
            decision_id: r["decision_id"].as_str().unwrap_or("").to_string(),
            ts_ms: rec.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0),
            agent: rec.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            principal: rec.get("principal").and_then(|p| p.get("id")).and_then(|v| v.as_str()).unwrap_or("").to_string(),
            tool: get(action, "tool"),
            resource: get(action, "resource"),
            operation: get(action, "operation"),
            verdict,
            rule_id: get(decision, "rule_id"),
            impact: get(action, "impact").to_ascii_lowercase(),
        };
        match format.as_str() {
            "cef" => println!("{}", to_cef(&ev)),
            "ocsf" => println!("{}", serde_json::to_string(&to_ocsf(&ev)).unwrap_or_default()),
            "syslog" => println!("{}", to_syslog(&ev)),
            other => {
                eprintln!("acp: unknown --format '{other}' (cef|ocsf|syslog)");
                return ExitCode::from(2);
            }
        }
        n += 1;
    }
    eprintln!("acp siem: {n} decision(s) rendered as {format}");
    ExitCode::SUCCESS
}

/// Maintain the AI risk register (evidence-linked; the full GRC lifecycle stays with the GRC platform).
///   acp risk add <register.json> --id X --title T --owner O --likelihood <low|medium|high> --impact <low|medium|high> --treatment <mitigate|accept|transfer|avoid> [--status <open|mitigating|accepted|closed>] [--control C]... [--decision D]... [--note N] [--key <hex>]
///   acp risk list <register.json>
///   acp risk report <register.json>
fn cmd_risk(rest: &[String]) -> ExitCode {
    use acp_core::riskregister::{Level, RiskItem, RiskRegister, RiskStatus, Treatment};
    let multi = |flag: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            if a == flag {
                if let Some(v) = it.next() {
                    out.push(v.clone());
                }
            }
        }
        out
    };
    let load = |path: &str| -> RiskRegister {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    };
    let sub = rest.first().map(String::as_str).unwrap_or("");
    match sub {
        "add" => {
            let Some(path) = rest.get(1) else { return usage("acp risk add <register.json> --id X --title T --owner O --likelihood L --impact I --treatment T ..."); };
            let id = match flag_value(rest, "--id") { Some(v) => v, None => return usage("acp risk add ... --id <id>") };
            let likelihood = match flag_value(rest, "--likelihood").and_then(|s| Level::parse(&s)) { Some(v)=>v, None=>{ eprintln!("acp: --likelihood <low|medium|high>"); return ExitCode::from(2);} };
            let impact = match flag_value(rest, "--impact").and_then(|s| Level::parse(&s)) { Some(v)=>v, None=>{ eprintln!("acp: --impact <low|medium|high>"); return ExitCode::from(2);} };
            let treatment = flag_value(rest, "--treatment").and_then(|s| Treatment::parse(&s)).unwrap_or(Treatment::Mitigate);
            let status = flag_value(rest, "--status").and_then(|s| RiskStatus::parse(&s)).unwrap_or(RiskStatus::Open);
            let item = RiskItem {
                id: id.clone(),
                title: flag_value(rest, "--title").unwrap_or_default(),
                owner: flag_value(rest, "--owner").unwrap_or_default(),
                likelihood, impact, treatment, status,
                linked_controls: multi("--control"),
                linked_decisions: multi("--decision"),
                notes: flag_value(rest, "--note").unwrap_or_default(),
            };
            let mut reg = load(path);
            reg.upsert(item);
            let out = match flag_value(rest, "--key") {
                Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
                    Some(seed) => serde_json::to_string_pretty(&reg.sign(&acp_core::sign::Ed25519Signer::from_seed(&seed))).unwrap_or_default(),
                    None => { eprintln!("acp: --key must be 32-byte hex"); return ExitCode::from(2); }
                },
                None => serde_json::to_string_pretty(&reg).unwrap_or_default(),
            };
            // Persist the plain register (signing is an export concern); print the (maybe signed) view.
            if std::fs::write(path, serde_json::to_string_pretty(&reg).unwrap_or_default()).is_err() {
                eprintln!("acp: cannot write {path}"); return ExitCode::from(1);
            }
            println!("{out}");
            let v = reg.view();
            eprintln!("risk {id} added; {} item(s): {} open, {} high, {} critical", reg.items.len(), v.open, v.high, v.critical);
            ExitCode::SUCCESS
        }
        "list" => {
            let Some(path) = rest.get(1) else { return usage("acp risk list <register.json>"); };
            for i in load(path).view().items {
                println!("{:6} [{:8}] score={} ({}) owner={} {}", i.id, format!("{:?}", i.status).to_lowercase(), i.score(), i.band(), i.owner, i.title);
            }
            ExitCode::SUCCESS
        }
        "report" => {
            let Some(path) = rest.get(1) else { return usage("acp risk report <register.json>"); };
            let v = load(path).view();
            println!("AI risk register: {} item(s); {} open, {} high, {} critical", v.items.len(), v.open, v.high, v.critical);
            for i in v.items.iter().filter(|i| i.band() == "critical" || i.band() == "high") {
                println!("  {:8} {:6} score={} {}  (controls: {}; decisions: {})", i.band(), i.id, i.score(), i.title, i.linked_controls.join(","), i.linked_decisions.join(","));
            }
            ExitCode::SUCCESS
        }
        _ => usage("acp risk <add|list|report> <register.json> ..."),
    }
}

/// Scan text with the first-party content firewall (injection / PII / secret / denied-topic).
///   acp content-scan <text-or-@file> [--deny-topic <t>]... [--block-secrets] [--no-redact-pii]
/// Prints the verdict JSON; exits 3 if the text is blocked.
fn cmd_content_scan(rest: &[String]) -> ExitCode {
    use acp_core::content::{scan_text, ContentPolicy};
    let Some(arg) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp content-scan <text-or-@file> [--deny-topic <t>] [--block-secrets] [--no-redact-pii]");
    };
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).unwrap_or_default()
    } else {
        arg.clone()
    };
    let mut topics = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--deny-topic" {
            if let Some(v) = it.next() { topics.push(v.clone()); }
        }
    }
    let policy = ContentPolicy {
        block_injection: true,
        block_secrets: rest.iter().any(|a| a == "--block-secrets"),
        redact_pii: !rest.iter().any(|a| a == "--no-redact-pii"),
        denied_topics: topics,
    };
    let v = scan_text(&policy, &text);
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    if v.block { ExitCode::from(3) } else { ExitCode::SUCCESS }
}

/// List the built-in control library (all frameworks, or one).
///   acp controls [eu-ai-act|nist-ai-rmf|iso-42001]
fn cmd_controls(rest: &[String]) -> ExitCode {
    let controls = match rest.first() {
        Some(fw) => acp_core::controls::for_framework(fw),
        None => acp_core::controls::library(),
    };
    for c in controls {
        println!("[{:11}] {:6} {}  -- evidence: {}", c.framework, c.id, c.title, c.required_evidence);
    }
    ExitCode::SUCCESS
}

/// Assess an AI system against the EU AI Act risk tiers and print its obligations.
///   acp assess <system> [--prohibited] [--safety-component] [--biometric] [--critical-infra]
///     [--employment] [--essential-services] [--law-enforcement] [--interacts] [--generates] [--key <hex>]
fn cmd_assess(rest: &[String]) -> ExitCode {
    use acp_core::assessment::{assess, Screening};
    let Some(system) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp assess <system> [--safety-component|--biometric|--employment|--interacts|...] [--key <hex>]");
    };
    let has = |f: &str| rest.iter().any(|a| a == f);
    let screening = Screening {
        prohibited_practice: has("--prohibited"),
        safety_component: has("--safety-component"),
        biometric_identification: has("--biometric"),
        critical_infrastructure: has("--critical-infra"),
        employment_or_education: has("--employment"),
        essential_services: has("--essential-services"),
        law_enforcement: has("--law-enforcement"),
        interacts_with_humans: has("--interacts"),
        generates_content: has("--generates"),
    };
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let a = assess(system, &screening, now_ms);
    let out = match flag_value(rest, "--key") {
        Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
            Some(seed) => serde_json::to_string_pretty(&a.clone().sign(&acp_core::sign::Ed25519Signer::from_seed(&seed))).unwrap_or_default(),
            None => { eprintln!("acp: --key must be 32-byte hex"); return ExitCode::from(2); }
        },
        None => serde_json::to_string_pretty(&a).unwrap_or_default(),
    };
    println!("{out}");
    eprintln!("assessment: {} -> {} risk; {} obligation(s): {}", a.system, a.tier.as_str(),
        a.obligations.len(), a.obligations.iter().map(|o| o.control_id.clone()).collect::<Vec<_>>().join(", "));
    ExitCode::SUCCESS
}

/// Record or verify signed attestations (governance sign-offs).
///   acp attest add <log.json> <subject> <statement> --attestor <who> --role <role> --key <hex>
///   acp attest verify <log.json>
fn cmd_attest(rest: &[String]) -> ExitCode {
    use acp_core::attestation::{attest, AttestationLog};
    let load = |path: &str| -> AttestationLog {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    };
    match rest.first().map(String::as_str).unwrap_or("") {
        "add" => {
            let (Some(log_path), Some(subject), Some(statement)) = (rest.get(1), rest.get(2), rest.get(3)) else {
                return usage("acp attest add <log.json> <subject> <statement> --attestor <who> --role <role> --key <hex>");
            };
            let attestor = flag_value(rest, "--attestor").unwrap_or_else(|| "unknown".into());
            let role = flag_value(rest, "--role").unwrap_or_else(|| "reviewer".into());
            let key_hex = match flag_value(rest, "--key") { Some(h)=>h, None=>{ eprintln!("acp: attest add requires --key <hex>"); return ExitCode::from(2);} };
            let seed: [u8;32] = match hex::decode(&key_hex).ok().and_then(|b| b.try_into().ok()) { Some(s)=>s, None=>{eprintln!("acp: --key must be 32-byte hex");return ExitCode::from(2);} };
            let signer = acp_core::sign::Ed25519Signer::from_seed(&seed);
            let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            let mut log = load(log_path);
            log.add(attest(&signer, subject, statement, &attestor, &role, now_ms));
            if std::fs::write(log_path, serde_json::to_string_pretty(&log).unwrap_or_default()).is_err() {
                eprintln!("acp: cannot write {log_path}"); return ExitCode::from(1);
            }
            eprintln!("attested '{subject}' by {attestor} ({role}); {} attestation(s)", log.attestations.len());
            ExitCode::SUCCESS
        }
        "verify" => {
            let Some(log_path) = rest.get(1) else { return usage("acp attest verify <log.json>"); };
            let log = load(log_path);
            if log.verify_all() {
                println!("OK: {} attestation(s) all verify", log.attestations.len());
                ExitCode::SUCCESS
            } else {
                println!("FAIL: at least one attestation does not verify");
                ExitCode::from(3)
            }
        }
        _ => usage("acp attest <add|verify> ..."),
    }
}

/// Manage the AI use-case registry with lifecycle gates.
///   acp usecase register <reg.json> --id X --name N --owner O [--model-class C]...
///   acp usecase link-assessment <reg.json> <id> <assessment-id>
///   acp usecase advance <reg.json> <id> <proposed|assessed|approved|deployed|retired> [--attestations <log.json>]
///   acp usecase list <reg.json>
fn cmd_usecase(rest: &[String]) -> ExitCode {
    use acp_core::usecase::{Stage, UseCase, UseCaseRegistry};
    let load = |path: &str| -> UseCaseRegistry {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    };
    let save = |path: &str, r: &UseCaseRegistry| -> bool {
        std::fs::write(path, serde_json::to_string_pretty(r).unwrap_or_default()).is_ok()
    };
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    match rest.first().map(String::as_str).unwrap_or("") {
        "register" => {
            let Some(path) = rest.get(1) else { return usage("acp usecase register <reg.json> --id X --name N --owner O [--model-class C]..."); };
            let id = match flag_value(rest, "--id") { Some(v)=>v, None=>return usage("acp usecase register ... --id <id>") };
            let mut classes = Vec::new();
            let mut it = rest.iter();
            while let Some(a) = it.next() { if a == "--model-class" { if let Some(v)=it.next(){ classes.push(v.clone()); } } }
            let mut r = load(path);
            r.upsert(UseCase { id: id.clone(), name: flag_value(rest,"--name").unwrap_or_default(), owner: flag_value(rest,"--owner").unwrap_or_default(), stage: Stage::Proposed, tier: None, assessment_id: None, model_classes: classes, created_ms: now_ms });
            if !save(path,&r) { eprintln!("acp: cannot write {path}"); return ExitCode::from(1); }
            eprintln!("registered use case '{id}' (proposed)");
            ExitCode::SUCCESS
        }
        "link-assessment" => {
            let (Some(path), Some(id), Some(aid)) = (rest.get(1), rest.get(2), rest.get(3)) else { return usage("acp usecase link-assessment <reg.json> <id> <assessment-id>"); };
            let mut r = load(path);
            let Some(uc) = r.use_cases.iter_mut().find(|u| &u.id == id) else { eprintln!("acp: no such use case '{id}'"); return ExitCode::from(1); };
            uc.assessment_id = Some(aid.clone());
            if !save(path,&r) { return ExitCode::from(1); }
            eprintln!("linked assessment '{aid}' to '{id}'");
            ExitCode::SUCCESS
        }
        "advance" => {
            let (Some(path), Some(id), Some(stage_s)) = (rest.get(1), rest.get(2), rest.get(3)) else { return usage("acp usecase advance <reg.json> <id> <stage> [--attestations <log.json>]"); };
            let Some(to) = Stage::parse(stage_s) else { eprintln!("acp: unknown stage '{stage_s}'"); return ExitCode::from(2); };
            let mut r = load(path);
            let has_assessment = r.get(id).map(|u| u.assessment_id.is_some()).unwrap_or(false);
            let has_attestation = match flag_value(rest, "--attestations") {
                Some(logp) => std::fs::read_to_string(&logp).ok()
                    .and_then(|s| serde_json::from_str::<acp_core::attestation::AttestationLog>(&s).ok())
                    .map(|l| l.has_valid(id)).unwrap_or(false),
                None => false,
            };
            let t = r.advance(id, to, has_assessment, has_attestation);
            match t {
                acp_core::usecase::Transition::Ok => {
                    if !save(path,&r) { return ExitCode::from(1); }
                    eprintln!("use case '{id}' advanced to {}", stage_s);
                    ExitCode::SUCCESS
                }
                acp_core::usecase::Transition::Refused(why) => { eprintln!("REFUSED: {why}"); ExitCode::from(3) }
            }
        }
        "list" => {
            let Some(path) = rest.get(1) else { return usage("acp usecase list <reg.json>"); };
            for u in load(path).use_cases {
                println!("{:8} [{:9}] owner={} assessment={} {}", u.id, format!("{:?}", u.stage).to_lowercase(), u.owner, u.assessment_id.unwrap_or_else(|| "-".into()), u.name);
            }
            ExitCode::SUCCESS
        }
        _ => usage("acp usecase <register|link-assessment|advance|list> ..."),
    }
}

/// Endpoint interception registry: validate, sign, or test how a destination would be handled.
///   acp intercept validate <rules.yaml>
///   acp intercept sign <rules.yaml> --key <hex>
///   acp intercept match <rules.yaml> <host> [path] [port]
fn cmd_intercept(rest: &[String]) -> ExitCode {
    use acp_core::interception::EndpointRegistry;
    let load = |path: &str| -> Result<EndpointRegistry, ExitCode> {
        let src = std::fs::read_to_string(path).map_err(|e| { eprintln!("acp: cannot read {path}: {e}"); ExitCode::from(1) })?;
        EndpointRegistry::from_yaml(&src).map_err(|e| { eprintln!("acp: {e}"); ExitCode::from(1) })
    };
    match rest.first().map(String::as_str).unwrap_or("") {
        "validate" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept validate <rules.yaml>"); };
            match load(f) { Ok(r) => { println!("ok: {} rule(s), default {:?}", r.endpoints.len(), r.default); ExitCode::SUCCESS } Err(c) => c }
        }
        "sign" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept sign <rules.yaml> --key <hex>"); };
            let reg = match load(f) { Ok(r)=>r, Err(c)=>return c };
            let key = match flag_value(rest, "--key") { Some(h)=>h, None=>{ eprintln!("acp: intercept sign requires --key <hex>"); return ExitCode::from(2);} };
            let seed: [u8;32] = match hex::decode(&key).ok().and_then(|b| b.try_into().ok()) { Some(s)=>s, None=>{eprintln!("acp: --key must be 32-byte hex");return ExitCode::from(2);} };
            let signed = reg.sign(&acp_core::sign::Ed25519Signer::from_seed(&seed));
            println!("{}", serde_json::to_string_pretty(&signed).unwrap_or_default());
            ExitCode::SUCCESS
        }
        "match" => {
            let (Some(f), Some(host)) = (rest.get(1), rest.get(2)) else { return usage("acp intercept match <rules.yaml> <host> [path] [port]"); };
            let reg = match load(f) { Ok(r)=>r, Err(c)=>return c };
            let path = rest.get(3).map(String::as_str).unwrap_or("/");
            let port: u16 = rest.get(4).and_then(|s| s.parse().ok()).unwrap_or(443);
            let d = reg.evaluate(host, path, port);
            let decrypt = reg.should_decrypt(host, port);
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "host": host, "path": path, "port": port,
                "rule_id": d.rule_id, "classification": d.classification,
                "action": format!("{:?}", d.action), "defaulted": d.defaulted, "flag": d.flag,
                "should_decrypt": decrypt,
            })).unwrap_or_default());
            ExitCode::SUCCESS
        }
        "extension" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept extension <rules.yaml> --proxy <host:port> --out <dir> [--catch-all]"); };
            let reg = match load(f) { Ok(r)=>r, Err(c)=>return c };
            let proxy = match flag_value(rest, "--proxy") { Some(p)=>p, None=>{ eprintln!("acp: intercept extension requires --proxy <host:port>"); return ExitCode::from(2);} };
            let out = flag_value(rest, "--out").unwrap_or_else(|| "acp-guard-extension".into());
            let catch_all = rest.iter().any(|a| a == "--catch-all");
            let pac = reg.to_pac(&proxy, catch_all);
            // Governed host substrings for the badge (host-level rules that govern).
            let hosts: Vec<String> = reg.endpoints.iter().filter(|r| r.action != acp_core::interception::Action::Pass)
                .filter_map(|r| r.match_.host_contains.clone().or_else(|| r.match_.host_suffix.clone()).or_else(|| r.match_.host_exact.clone()).or_else(|| r.match_.sni.clone()))
                .map(|h| h.to_ascii_lowercase()).collect();
            let hosts_json = serde_json::to_string(&hosts).unwrap_or_else(|_| "[]".into());
            if std::fs::create_dir_all(&out).is_err() { eprintln!("acp: cannot create {out}"); return ExitCode::from(1); }
            let manifest = r#"{
  "manifest_version": 3,
  "name": "ACP Guard",
  "version": "0.1.0",
  "description": "Routes AI-endpoint traffic through the ACP interception proxy and marks governed tabs.",
  "permissions": ["proxy", "tabs", "storage", "webNavigation"],
  "host_permissions": ["<all_urls>"],
  "background": { "service_worker": "background.js" },
  "action": { "default_title": "ACP Guard" }
}
"#;
            let background = format!(r##"// ACP Guard (generated by `acp intercept pac`/`extension`). Chromium MV3.
// 1) Route matching AI traffic through the ACP interception proxy via a PAC.
// 2) Badge governed tabs so users know the interaction is monitored.
const PAC = {pac};
const GOVERNED_HOSTS = {hosts};

function applyProxy() {{
  chrome.proxy.settings.set(
    {{ value: {{ mode: "pac_script", pacScript: {{ data: PAC }} }}, scope: "regular" }},
    () => {{}}
  );
}}
chrome.runtime.onInstalled.addListener(applyProxy);
chrome.runtime.onStartup.addListener(applyProxy);

function isGoverned(host) {{
  host = (host || "").toLowerCase();
  return GOVERNED_HOSTS.some(h => host.indexOf(h) !== -1);
}}
chrome.webNavigation.onCommitted.addListener((d) => {{
  try {{
    const host = new URL(d.url).hostname;
    if (isGoverned(host)) {{
      chrome.action.setBadgeText({{ tabId: d.tabId, text: "ACP" }});
      chrome.action.setBadgeBackgroundColor({{ tabId: d.tabId, color: "#1f6feb" }});
      chrome.action.setTitle({{ tabId: d.tabId, title: "This AI endpoint is governed by ACP" }});
    }} else {{
      chrome.action.setBadgeText({{ tabId: d.tabId, text: "" }});
    }}
  }} catch (e) {{}}
}});
"##, pac=serde_json::to_string(&pac).unwrap_or_default(), hosts=hosts_json);
            let readme = format!("# ACP Guard extension

Generated by `acp intercept extension` from the endpoint registry. Chromium MV3.

What it does:
- Installs a PAC that routes governed AI endpoints through the ACP interception proxy at `{proxy}` (browser traffic is then subject to the same rules as agents and IDEs).
- Badges a tab with `ACP` when it is on a governed AI endpoint, so users know the interaction is monitored.

Load (developer): open chrome://extensions, enable Developer mode, Load unpacked, select this folder.

Deploy (managed): package and push via enterprise policy (ExtensionInstallForcelist) with the ACP CA already installed on the device for TLS interception.

Note: this is a starting scaffold; it has not been run-verified in a browser here. Regenerate it whenever the registry changes so the PAC and badge list stay in sync.
");
            let w = |name: &str, content: &str| std::fs::write(format!("{out}/{name}"), content);
            if w("manifest.json", manifest).is_err() || w("background.js", &background).is_err() || w("README.md", &readme).is_err() {
                eprintln!("acp: cannot write extension files to {out}"); return ExitCode::from(1);
            }
            eprintln!("wrote ACP Guard extension to {out}/ (manifest.json, background.js, README.md); governed hosts: {}", hosts.len());
            ExitCode::SUCCESS
        }
        "pac" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept pac <rules.yaml> --proxy <host:port> [--catch-all]"); };
            let reg = match load(f) { Ok(r)=>r, Err(c)=>return c };
            let proxy = match flag_value(rest, "--proxy") { Some(p)=>p, None=>{ eprintln!("acp: intercept pac requires --proxy <host:port>"); return ExitCode::from(2);} };
            let catch_all = rest.iter().any(|a| a == "--catch-all");
            println!("{}", reg.to_pac(&proxy, catch_all));
            ExitCode::SUCCESS
        }
        "from-enrollment" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept from-enrollment <enroll.json> [--default <flag-and-pass|flag-and-block|pass|block>] [--key <hex>]"); };
            let log: acp_core::enrollment::EnrollmentLog = match std::fs::read_to_string(f).ok().and_then(|s| serde_json::from_str(&s).ok()) {
                Some(l) => l, None => { eprintln!("acp: cannot read enrollment log {f}"); return ExitCode::from(1); }
            };
            let default = match flag_value(rest, "--default").as_deref() {
                Some("flag-and-block") => acp_core::interception::DefaultAction::FlagAndBlock,
                Some("pass") => acp_core::interception::DefaultAction::Pass,
                Some("block") => acp_core::interception::DefaultAction::Block,
                _ => acp_core::interception::DefaultAction::FlagAndPass,
            };
            let registry = acp_core::interception::registry_from_enrollment(&log, default);
            emit_registry(&registry, flag_value(rest, "--key"))
        }
        "suggest" => {
            let Some(f) = rest.get(1) else { return usage("acp intercept suggest <observed.txt> [--governed <governed.txt>] [--key <hex>]"); };
            let read_lines = |p: &str| -> Vec<String> {
                std::fs::read_to_string(p).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
            };
            let observed = read_lines(f);
            let governed = flag_value(rest, "--governed").map(|g| read_lines(&g)).unwrap_or_default();
            let shadow = acp_core::discovery::find_shadow_ai(&observed, &governed);
            let endpoints: Vec<_> = shadow.iter().map(acp_core::interception::rule_from_discovered).collect();
            let registry = acp_core::interception::EndpointRegistry { version: 1, default: acp_core::interception::DefaultAction::FlagAndPass, endpoints };
            eprintln!("suggested {} rule(s) from {} observed endpoint(s)", registry.endpoints.len(), observed.len());
            emit_registry(&registry, flag_value(rest, "--key"))
        }
        _ => usage("acp intercept <validate|sign|match|from-enrollment|suggest|pac|extension> ..."),
    }
}

/// Print an endpoint registry as YAML (default) or, with --key, as a signed JSON registry.
fn emit_registry(registry: &acp_core::interception::EndpointRegistry, key: Option<String>) -> ExitCode {
    match key {
        Some(h) => match hex::decode(&h).ok().and_then(|b| b.try_into().ok()) {
            Some(seed) => { println!("{}", serde_json::to_string_pretty(&registry.sign(&acp_core::sign::Ed25519Signer::from_seed(&seed))).unwrap_or_default()); ExitCode::SUCCESS }
            None => { eprintln!("acp: --key must be 32-byte hex"); ExitCode::from(2) }
        },
        None => { println!("{}", serde_yaml::to_string(registry).unwrap_or_default()); ExitCode::SUCCESS }
    }
}

/// Work an EU AI Act conformity checklist: seed it from an assessment, mark controls, and report.
///   acp conformity init <out.json> <system> [--employment|--biometric|--interacts|...]
///   acp conformity set <file.json> <control-id> <satisfied|partial|gap> [--evidence <id>]... [--owner <who>]
///   acp conformity report <file.json>
fn cmd_conformity(rest: &[String]) -> ExitCode {
    use acp_core::assessment::{assess, Screening};
    use acp_core::conformity::ConformityAssessment;
    use acp_core::grc::Status;
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let load = |f: &str| -> Option<ConformityAssessment> { std::fs::read_to_string(f).ok().and_then(|s| serde_json::from_str(&s).ok()) };
    let save = |f: &str, c: &ConformityAssessment| std::fs::write(f, serde_json::to_string_pretty(c).unwrap_or_default()).is_ok();
    match rest.first().map(String::as_str).unwrap_or("") {
        "init" => {
            let (Some(out), Some(system)) = (rest.get(1), rest.get(2)) else { return usage("acp conformity init <out.json> <system> [assess flags]"); };
            let has = |x: &str| rest.iter().any(|a| a == x);
            let screening = Screening {
                prohibited_practice: has("--prohibited"), safety_component: has("--safety-component"),
                biometric_identification: has("--biometric"), critical_infrastructure: has("--critical-infra"),
                employment_or_education: has("--employment"), essential_services: has("--essential-services"),
                law_enforcement: has("--law-enforcement"), interacts_with_humans: has("--interacts"), generates_content: has("--generates"),
            };
            let a = assess(system, &screening, now_ms);
            let c = ConformityAssessment::from_assessment(&a, now_ms);
            if !save(out, &c) { eprintln!("acp: cannot write {out}"); return ExitCode::from(1); }
            let (s,tot,pct)=c.completeness();
            eprintln!("seeded conformity for {system} ({}): {tot} control(s), {s}/{tot} satisfied ({pct}%)", c.tier);
            ExitCode::SUCCESS
        }
        "set" => {
            let (Some(f), Some(cid), Some(st)) = (rest.get(1), rest.get(2), rest.get(3)) else { return usage("acp conformity set <file.json> <control-id> <satisfied|partial|gap> [--evidence <id>] [--owner <who>]"); };
            let status = match st.as_str() { "satisfied"=>Status::Satisfied, "partial"=>Status::Partial, "gap"=>Status::Gap, o=>{eprintln!("acp: unknown status '{o}'"); return ExitCode::from(2);} };
            let mut evidence=Vec::new(); let mut it=rest.iter();
            while let Some(a)=it.next() { if a=="--evidence" { if let Some(v)=it.next(){evidence.push(v.clone());} } }
            let owner = flag_value(rest, "--owner").unwrap_or_default();
            let Some(mut c)=load(f) else { eprintln!("acp: cannot read {f}"); return ExitCode::from(1); };
            if !c.set_status(cid, status, evidence, &owner, now_ms) { eprintln!("acp: no such control '{cid}'"); return ExitCode::from(1); }
            if !save(f,&c) { return ExitCode::from(1); }
            let (s,tot,pct)=c.completeness();
            eprintln!("{cid} -> {st}; {s}/{tot} satisfied ({pct}%)"); ExitCode::SUCCESS
        }
        "report" => {
            let Some(f)=rest.get(1) else { return usage("acp conformity report <file.json>"); };
            let Some(c)=load(f) else { eprintln!("acp: cannot read {f}"); return ExitCode::from(1); };
            let (s,tot,pct)=c.completeness();
            println!("Conformity: {} ({}) -- {s}/{tot} satisfied ({pct}%){}", c.system, c.tier, if c.is_conformant(){"  [CONFORMANT]"}else{""});
            for i in &c.items {
                println!("  [{:9}] {:6} {}  evidence: {}", format!("{:?}", i.status).to_lowercase(), i.control_id, i.title, i.evidence.join(","));
            }
            ExitCode::SUCCESS
        }
        _ => usage("acp conformity <init|set|report> ..."),
    }
}

/// Maintain model cards (a core GRC artifact).
///   acp modelcard add <reg.json> --id X --name N --provider P --version V --intended-use "..." --limitations "..." --eval "..." --owner O [--risk-tier <t>] [--usecase <id>]
///   acp modelcard list <reg.json>
fn cmd_modelcard(rest: &[String]) -> ExitCode {
    use acp_core::modelcard::{ModelCard, ModelCardRegistry};
    let load = |f: &str| -> ModelCardRegistry { std::fs::read_to_string(f).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default() };
    match rest.first().map(String::as_str).unwrap_or("") {
        "add" => {
            let Some(f)=rest.get(1) else { return usage("acp modelcard add <reg.json> --id X --name N ..."); };
            let id=match flag_value(rest,"--id"){Some(v)=>v,None=>return usage("acp modelcard add ... --id <id>")};
            let card = ModelCard {
                id: id.clone(),
                name: flag_value(rest,"--name").unwrap_or_default(),
                provider: flag_value(rest,"--provider").unwrap_or_default(),
                version: flag_value(rest,"--version").unwrap_or_default(),
                intended_use: flag_value(rest,"--intended-use").unwrap_or_default(),
                limitations: flag_value(rest,"--limitations").unwrap_or_default(),
                training_data: flag_value(rest,"--training-data").unwrap_or_default(),
                eval_summary: flag_value(rest,"--eval").unwrap_or_default(),
                owner: flag_value(rest,"--owner").unwrap_or_default(),
                risk_tier: flag_value(rest,"--risk-tier"),
                linked_usecase: flag_value(rest,"--usecase"),
            };
            let mut r=load(f); r.upsert(card);
            if std::fs::write(f, serde_json::to_string_pretty(&r).unwrap_or_default()).is_err(){eprintln!("acp: cannot write {f}");return ExitCode::from(1);}
            eprintln!("model card '{id}' saved; {} card(s), {} incomplete", r.cards.len(), r.incomplete().len());
            ExitCode::SUCCESS
        }
        "list" => {
            let Some(f)=rest.get(1) else { return usage("acp modelcard list <reg.json>"); };
            for c in load(f).cards {
                let flag = if c.intended_use.is_empty()||c.limitations.is_empty()||c.eval_summary.is_empty()||c.owner.is_empty() {"INCOMPLETE"} else {"ok"};
                println!("{:8} [{:10}] {} v{} ({}) tier={} {}", c.id, flag, c.name, c.version, c.provider, c.risk_tier.unwrap_or_else(||"-".into()), c.owner);
            }
            ExitCode::SUCCESS
        }
        _ => usage("acp modelcard <add|list> ..."),
    }
}

/// Evaluate a trained content model against a labelled dataset (the CI gate for ML models).
///   acp content-eval <model.json> <dataset.json> [--min-recall <r>] [--min-precision <p>]
/// dataset.json is an array of {"text": "...", "label": 0|1}. Exits 3 if below either threshold.
fn cmd_content_eval(rest: &[String]) -> ExitCode {
    use acp_core::content::{eval_injection, LinearScorer};
    let pos: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(model_path), Some(ds_path)) = (pos.first(), pos.get(1)) else {
        return usage("acp content-eval <model.json> <dataset.json> [--min-recall <r>] [--min-precision <p>]");
    };
    let scorer = match std::fs::read_to_string(model_path.as_str()).ok().and_then(|s| LinearScorer::from_json(&s).ok()) {
        Some(s) => s, None => { eprintln!("acp: cannot load model {model_path}"); return ExitCode::from(1); }
    };
    let items: Vec<Value> = match std::fs::read_to_string(ds_path.as_str()).ok().and_then(|s| serde_json::from_str(&s).ok()) {
        Some(Value::Array(a)) => a, _ => { eprintln!("acp: {ds_path} must be a JSON array of {{text,label}}"); return ExitCode::from(2); }
    };
    let samples: Vec<(String, bool)> = items.iter()
        .filter_map(|v| Some((v.get("text")?.as_str()?.to_string(), v.get("label")?.as_i64()? == 1)))
        .collect();
    if samples.is_empty() { eprintln!("acp: no samples in {ds_path}"); return ExitCode::from(2); }
    let m = eval_injection(&scorer, &samples);
    let min_recall: f32 = flag_value(rest, "--min-recall").and_then(|s| s.parse().ok()).unwrap_or(0.8);
    let min_precision: f32 = flag_value(rest, "--min-precision").and_then(|s| s.parse().ok()).unwrap_or(0.8);
    println!("content-eval: n={} precision={:.3} recall={:.3} fpr={:.3} accuracy={:.3}", m.n, m.precision, m.recall, m.fpr, m.accuracy);
    if m.recall < min_recall || m.precision < min_precision {
        eprintln!("GATE FAILED: recall {:.3} (min {:.3}) precision {:.3} (min {:.3})", m.recall, min_recall, m.precision, min_precision);
        return ExitCode::from(3);
    }
    eprintln!("gate passed (min recall {min_recall}, min precision {min_precision})");
    ExitCode::SUCCESS
}

/// Continuous adversarial testing: run the built-in obfuscation corpus through the content engine.
///   acp redteam [model.json] [--min-catch <r>]
/// With a model, uses signatures + ML; without, signatures only. Exits 3 below the catch threshold
/// or on any false positive.
fn cmd_redteam(rest: &[String]) -> ExitCode {
    use acp_core::content::{ContentPolicy, LinearScorer};
    use acp_core::redteam::{corpus, run};
    let model = rest.iter().find(|a| !a.starts_with("--"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| LinearScorer::from_json(&s).ok());
    let min_catch: f32 = flag_value(rest, "--min-catch").and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let cases = corpus();
    let r = run(&ContentPolicy::default(), model.as_ref(), &cases);
    println!("redteam: {}/{} attacks caught ({:.1}%), {} false positive(s) on {} benign",
        r.caught, r.attacks, r.catch_rate * 100.0, r.false_positives, r.benign);
    for (name, caught, n) in &r.per_transform {
        println!("  {:12} {}/{}", name, caught, n);
    }
    for m in &r.missed {
        println!("  MISSED {m}");
    }
    if r.catch_rate < min_catch || r.false_positives > 0 {
        eprintln!("GATE FAILED: catch-rate {:.3} (min {:.3}), false positives {}", r.catch_rate, min_catch, r.false_positives);
        return ExitCode::from(3);
    }
    eprintln!("gate passed (min catch {min_catch}, zero false positives)");
    ExitCode::SUCCESS
}

/// Check an answer's groundedness against a source context (baseline lexical detector).
///   acp groundedness <answer-or-@file> <context-or-@file> [--block-below <r>] [--claim-threshold <r>]
/// Prints the score and unsupported claims; exits 3 when the score is below --block-below.
fn cmd_groundedness(rest: &[String]) -> ExitCode {
    use acp_core::groundedness::groundedness;
    let pos: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (Some(a), Some(c)) = (pos.first(), pos.get(1)) else {
        return usage("acp groundedness <answer-or-@file> <context-or-@file> [--block-below <r>] [--claim-threshold <r>]");
    };
    let read = |s: &str| -> String { s.strip_prefix('@').map(|p| std::fs::read_to_string(p).unwrap_or_default()).unwrap_or_else(|| s.to_string()) };
    let answer = read(a);
    let context = read(c);
    let block_below: f32 = flag_value(rest, "--block-below").and_then(|s| s.parse().ok()).unwrap_or(0.6);
    let claim_threshold: f32 = flag_value(rest, "--claim-threshold").and_then(|s| s.parse().ok()).unwrap_or(0.5);
    let r = groundedness(&answer, &context, claim_threshold);
    println!("groundedness: {:.2} ({} claim(s), {} unsupported)", r.score, r.claims.len(), r.ungrounded.len());
    for u in &r.ungrounded {
        println!("  UNSUPPORTED  {}", u.chars().take(90).collect::<String>());
    }
    if r.score < block_below {
        eprintln!("BELOW THRESHOLD: {:.2} < {:.2}", r.score, block_below);
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// Compile one ACP policy into a coding agent's native managed-settings (phase D):
///   acp native-compile <policy.yaml> <claude|copilot|gemini>
/// Prints the native settings JSON to stdout and a coverage report (what mapped, what is routed to
/// the proxy) to stderr.
fn cmd_native_compile(rest: &[String]) -> ExitCode {
    use acp_nativecompile::{compile_with_gateway, Vendor};
    let positionals: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (file, vendor_s) = match (positionals.first(), positionals.get(1)) {
        (Some(f), Some(v)) => (*f, *v),
        _ => return usage("acp native-compile <policy.yaml> <claude|copilot|gemini> [--gateway <url>]"),
    };
    let gateway = flag_value(rest, "--gateway");
    let Some(vendor) = Vendor::parse(vendor_s) else {
        eprintln!("acp: unknown vendor '{vendor_s}' (claude|copilot|gemini)");
        return ExitCode::from(2);
    };
    let src = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => { eprintln!("acp: cannot read {file}: {e}"); return ExitCode::from(1); }
    };
    let policy = match acp_policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => { eprintln!("acp: invalid policy: {e}"); return ExitCode::from(1); }
    };
    let c = compile_with_gateway(&policy, vendor, gateway.as_deref());
    println!("{}", serde_json::to_string_pretty(&c.settings).unwrap());
    eprintln!("coverage: {} rule(s) mapped natively [{}]", c.covered.len(), c.covered.join(", "));
    if !c.uncovered.is_empty() {
        eprintln!(
            "routed to proxy ({} rule(s) this agent cannot express natively): {}",
            c.uncovered.len(),
            c.uncovered.join(", ")
        );
    }
    ExitCode::SUCCESS
}

/// F2 channel: write (or clear) the break-glass grant file the proxy watches.
///   acp break-glass engage <file> <mode> <reason> <actor> <ttl_ms> [--scope <scope>]
///   scope: global | agent:<id> | resource:<class> | tool:<name>  (default global)
///   acp break-glass clear  <file>
/// Modes: lockdown_all | disable_enforce | emergency_bypass. Prints a meta-audit line to record.
fn cmd_break_glass(rest: &[String]) -> ExitCode {
    use acp_core::breakglass::{GrantFile, Mode, Scope};
    match rest.first().map(String::as_str) {
        Some("clear") => {
            let Some(file) = rest.get(1) else { return usage("acp break-glass clear <file>"); };
            match std::fs::remove_file(file) {
                Ok(_) | Err(_) => {
                    println!("break-glass cleared ({file}); the proxy reverts to normal on next decision");
                    ExitCode::SUCCESS
                }
            }
        }
        Some("engage") => {
            let (file, mode_s, reason, actor, ttl_s) =
                match (rest.get(1), rest.get(2), rest.get(3), rest.get(4), rest.get(5)) {
                    (Some(f), Some(m), Some(r), Some(a), Some(t)) => (f, m, r, a, t),
                    _ => return usage("acp break-glass engage <file> <mode> <reason> <actor> <ttl_ms>"),
                };
            let Some(mode) = Mode::parse(mode_s) else {
                eprintln!("acp: unknown mode '{mode_s}' (lockdown_all|disable_enforce|emergency_bypass)");
                return ExitCode::from(2);
            };
            let ttl_ms: u64 = match ttl_s.parse() {
                Ok(n) if n > 0 => n,
                _ => { eprintln!("acp: ttl_ms must be a positive number"); return ExitCode::from(2); }
            };
            // A fixed engaged_ms of 0 is not used; stamp wall-clock so the TTL is meaningful.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if reason.trim().is_empty() {
                eprintln!("acp: break-glass requires a reason");
                return ExitCode::from(2);
            }
            // Optional flags: --scope aims the grant; --key <32-byte hex seed> signs it so a proxy
            // that pins the corresponding public key will accept it (and reject forgeries).
            let mut scope = Scope::Global;
            let mut key_hex: Option<String> = None;
            let mut i = 6;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--scope" => {
                        if let Some(v) = rest.get(i + 1) {
                            scope = Scope::parse(v);
                        }
                        i += 2;
                    }
                    "--key" => {
                        key_hex = rest.get(i + 1).cloned();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            let scope_s = scope.as_str();
            let mut grant = GrantFile::new_scoped(mode, scope, reason, actor, now, ttl_ms);
            if let Some(kh) = key_hex {
                match hex::decode(&kh) {
                    Ok(b) if b.len() == 32 => {
                        let mut seed = [0u8; 32];
                        seed.copy_from_slice(&b);
                        let signer = acp_core::sign::Ed25519Signer::from_seed(&seed);
                        grant.sign(&signer);
                        println!("signed; pin on the proxy with --break-glass-key {}", grant.pubkey);
                    }
                    _ => {
                        eprintln!("acp: --key must be a 32-byte hex seed");
                        return ExitCode::from(2);
                    }
                }
            }
            let json = serde_json::to_string_pretty(&grant).unwrap();
            if std::fs::write(file, json).is_err() {
                eprintln!("acp: cannot write {file}");
                return ExitCode::from(1);
            }
            println!("break-glass ENGAGED: mode={mode_s} scope={scope_s} actor={actor} ttl_ms={ttl_ms} -> {file}");
            // Meta-audit line the operator/server should append to the tamper-evident log.
            println!("META-AUDIT: {{\"kind\":\"break_glass_engage\",\"actor\":\"{actor}\",\"reason\":\"{reason}\",\"after\":\"{mode_s}\"}}");
            ExitCode::SUCCESS
        }
        _ => usage("acp break-glass <engage|clear> ..."),
    }
}


fn cmd_app(rest: &[String]) -> ExitCode {
    match (rest.first().map(String::as_str), rest.get(1), rest.get(2), rest.get(3)) {
        (Some("register"), Some(file), Some(name), owner) => {
            let mut reg = match acp_registry::Registry::load(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            let app = reg.register_app(name, owner.map(String::as_str).unwrap_or(""));
            if reg.save(file).is_err() { eprintln!("acp: cannot write {file}"); return ExitCode::from(1); }
            println!("registered app: id={} name={}", app.id, app.name);
            ExitCode::SUCCESS
        }
        _ => usage("acp app register <registry.json> <name> [owner]"),
    }
}

fn cmd_agent(rest: &[String]) -> ExitCode {
    let reg_of = |file: &str| acp_registry::Registry::load(file);
    match (rest.first().map(String::as_str), rest.get(1), rest.get(2), rest.get(3)) {
        (Some("register"), Some(file), Some(app_id), Some(name)) => {
            let mut reg = match reg_of(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            match reg.register_agent(app_id, name) {
                Ok((agent, token)) => {
                    if reg.save(file).is_err() { eprintln!("acp: cannot write {file}"); return ExitCode::from(1); }
                    println!("registered agent: id={} app={}", agent.id, agent.app_id);
                    println!("TOKEN (shown once, give it to the agent): {token}");
                    ExitCode::SUCCESS
                }
                Err(e) => { eprintln!("acp: {e}"); ExitCode::from(1) }
            }
        }
        (Some("revoke"), Some(file), Some(agent_id), _) => {
            let mut reg = match reg_of(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            if reg.deactivate_agent(agent_id) {
                let _ = reg.save(file);
                println!("revoked agent {agent_id}");
                ExitCode::SUCCESS
            } else { eprintln!("acp: no such agent {agent_id}"); ExitCode::from(1) }
        }
        _ => usage("acp agent <register <registry.json> <app_id> <name> | revoke <registry.json> <agent_id>>"),
    }
}

fn cmd_registry(rest: &[String]) -> ExitCode {
    match (rest.first().map(String::as_str), rest.get(1)) {
        (Some("list"), Some(file)) => {
            let reg = match acp_registry::Registry::load(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            println!("apps:");
            for a in reg.apps() { println!("  {} ({}) owner={}", a.id, a.name, a.owner); }
            println!("agents:");
            for a in reg.agents() { println!("  {} ({}) app={} active={}", a.id, a.name, a.app_id, a.active); }
            ExitCode::SUCCESS
        }
        _ => usage("acp registry list <registry.json>"),
    }
}


/// Signed, versioned policy deployment.
///   acp policy deploy  <policy.yaml> <store-dir> <keyfile>
///   acp policy current <store-dir>
fn cmd_policy(rest: &[String]) -> ExitCode {
    use acp_core::sign::Ed25519Signer;
    match rest.first().map(String::as_str) {
        Some("deploy") => {
            let (pol, store, keyf) = match (rest.get(1), rest.get(2), rest.get(3)) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => return usage("acp policy deploy <policy.yaml> <store-dir> <keyfile>"),
            };
            let src = match std::fs::read_to_string(pol) {
                Ok(s) => s,
                Err(e) => { eprintln!("acp: cannot read {pol}: {e}"); return ExitCode::from(1); }
            };
            let signer = match std::fs::read(keyf) {
                Ok(b) if b.len() == 32 => { let mut s=[0u8;32]; s.copy_from_slice(&b); Ed25519Signer::from_seed(&s) }
                _ => { let s = Ed25519Signer::generate(); if acp_core::secret::write_key_secure(keyf, &s.seed()).is_err() { eprintln!("acp: cannot write key {keyf}"); return ExitCode::from(1); } s }
            };
            match acp_policy::store::deploy(&src, store, &signer, "cli") {
                Ok(d) => { println!("deployed policy v{} (hash {}...) to {store}", d.version, &d.hash[..12.min(d.hash.len())]); ExitCode::SUCCESS }
                Err(e) => { eprintln!("acp: deploy rejected: {e}"); ExitCode::from(1) }
            }
        }
        Some("current") => {
            let Some(store) = rest.get(1) else { return usage("acp policy current <store-dir>"); };
            match acp_policy::store::current_info(store) {
                Ok(v) => { println!("{}", serde_json::to_string_pretty(&v).unwrap()); ExitCode::SUCCESS }
                Err(e) => { eprintln!("acp: {e}"); ExitCode::from(1) }
            }
        }
        _ => usage("acp policy <deploy|current> ..."),
    }
}
