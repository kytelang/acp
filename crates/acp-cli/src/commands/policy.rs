//! acp CLI commands: policy.
use crate::common::*;
use serde_json::Value;
use std::process::ExitCode;

pub(crate) fn policy_compile(path: &str) -> ExitCode {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match acp_core::policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: invalid policy {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = acp_core::policy::validate(&policy) {
        eprintln!("acp: invalid policy {path}: {e}");
        return ExitCode::from(1);
    }
    print!("{}", acp_core::policy::compile_to_cedar(&policy));
    ExitCode::SUCCESS
}

/// `acp policy-test <policy.yaml> <calls.jsonl>`            -> verdict per call
/// `acp policy-test --diff <old.yaml> <new.yaml> <calls.jsonl>` -> only the calls whose verdict flips
pub(crate) fn run_policy_test(rest: &[String]) -> ExitCode {
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


/// `acp posture <ledger.db> [--required <0..1>]`: read real decisions and report whether the tenant
/// is ready to switch the policy default from allow to deny (E6 staged path). Coverage is the
/// fraction of decisions that matched a named rule; the would-block set is the distinct tools whose
/// decisions matched no rule (they would newly deny under default-deny). Wires acp_core::posture.
pub(crate) fn cmd_posture(rest: &[String]) -> ExitCode {
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
    let pack = match acp_core::ledger::export_file(path) {
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

pub(crate) fn cmd_learn(rest: &[String]) -> ExitCode {
    let least_privilege = rest.iter().any(|a| a == "--least-privilege" || a == "--strict");
    let ledger = match rest.iter().find(|a| !a.starts_with("--")) {
        Some(l) => l.as_str(),
        None => return usage("acp learn <ledger.db> [--least-privilege]"),
    };
    // G2: least-privilege mode emits the smallest default-deny allow-list from observed traffic.
    if least_privilege {
        match acp_core::ledger::observed_actions(ledger) {
            Ok(actions) => {
                if actions.is_empty() {
                    eprintln!("acp: no decision records observed in {ledger}; run the proxy in --shadow first");
                    return ExitCode::from(1);
                }
                print!("{}", acp_core::policy::synth::synthesize_least_privilege(&actions));
                return ExitCode::SUCCESS;
            }
            Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); }
        }
    }
    let tools = match acp_core::ledger::observed_tools(ledger) {
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

/// Compute a coverage attestation: cross-reference observed AI endpoints against the governed
/// (enrolled) set, list ungoverned or leaky paths, and optionally sign the report.
///   acp coverage <observed.txt> <governed.txt> [--fail-open] [--leaky <msg>]... [--key <hex>] [--require-full]
/// Prints the (signed) report JSON to stdout and a summary to stderr. With --require-full, exits 3
/// when the estate is not fully contained (useful as a CI/rollout gate).
pub(crate) fn cmd_coverage(rest: &[String]) -> ExitCode {
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

/// Signed, versioned policy deployment.
///   acp policy deploy  <policy.yaml> <store-dir> <keyfile>
///   acp policy current <store-dir>
pub(crate) fn cmd_policy(rest: &[String]) -> ExitCode {
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
            match acp_core::policy::store::deploy(&src, store, &signer, "cli") {
                Ok(d) => { println!("deployed policy v{} (hash {}...) to {store}", d.version, &d.hash[..12.min(d.hash.len())]); ExitCode::SUCCESS }
                Err(e) => { eprintln!("acp: deploy rejected: {e}"); ExitCode::from(1) }
            }
        }
        Some("current") => {
            let Some(store) = rest.get(1) else { return usage("acp policy current <store-dir>"); };
            match acp_core::policy::store::current_info(store) {
                Ok(v) => { println!("{}", serde_json::to_string_pretty(&v).unwrap()); ExitCode::SUCCESS }
                Err(e) => { eprintln!("acp: {e}"); ExitCode::from(1) }
            }
        }
        _ => usage("acp policy <deploy|current> ..."),
    }
}
