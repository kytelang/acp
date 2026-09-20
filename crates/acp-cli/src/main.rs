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
        "grc-report" => cmd_grc_report(&args[2..]),
        "ledger-backup" => cmd_ledger_backup(&args[2..]),
        "verify-enforcement" => cmd_verify_enforcement(&args[2..]),
        "registry" => cmd_registry(&args[2..]),
        "policy" => cmd_policy(&args[2..]),
        _ => usage("acp [init|verify|verify-pack|export|policy-compile|policy-test|approve|deny|approvals|canary|learn|replay|purge|classify-eval]"),
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("usage: {msg}");
    ExitCode::from(2)
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
    let governed: BTreeSet<String> = positionals
        .get(1)
        .map(|f| read_lines(f).into_iter().collect())
        .unwrap_or_default();

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

/// Compile one ACP policy into a coding agent's native managed-settings (phase D):
///   acp native-compile <policy.yaml> <claude|copilot|gemini>
/// Prints the native settings JSON to stdout and a coverage report (what mapped, what is routed to
/// the proxy) to stderr.
fn cmd_native_compile(rest: &[String]) -> ExitCode {
    use acp_nativecompile::{compile, Vendor};
    let (file, vendor_s) = match (rest.first(), rest.get(1)) {
        (Some(f), Some(v)) => (f, v),
        _ => return usage("acp native-compile <policy.yaml> <claude|copilot|gemini>"),
    };
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
    let c = compile(&policy, vendor);
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
