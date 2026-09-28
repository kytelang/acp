//! acp CLI commands: evidence.
use crate::common::*;
use acp_core::policy::build_context;
use serde_json::Value;
use std::process::ExitCode;

pub(crate) fn cmd_verify(path: &str) -> ExitCode {
    match acp_core::ledger::verify_file(path) {
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

pub(crate) fn cmd_verify_pack(path: &str) -> ExitCode {
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
    // Two pack shapes verify offline with the public key alone:
    //  - Merkle evidence packs from `acp export` ({public_key, records, sth}); and
    //  - detached-signature packs ({body, pubkey_hex, sig_hex}) as produced by the signed audit pack
    //    (GET /audit/pack) and the framework compliance pack (GET /report/framework/:name/pack),
    //    a plain Ed25519 signature over the canonical bytes of `body`.
    if pack.get("sig_hex").is_some() {
        return match acp_core::sign::verify_detached_pack(&pack) {
            Ok(()) => {
                println!("OK: signed pack verifies (detached Ed25519 over the canonical body)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("FAIL: {e}");
                ExitCode::from(1)
            }
        };
    }
    match acp_core::ledger::verify_pack(&pack) {
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

pub(crate) fn cmd_export(path: &str) -> ExitCode {
    match acp_core::ledger::export_file(path) {
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

pub(crate) fn cmd_purge(rest: &[String]) -> ExitCode {
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
    match acp_core::ledger::purge_args_file(&rest[0], before) {
        Ok(n) => {
            println!("purged {n} argument payloads older than {days} days");
            match acp_core::ledger::verify_file(&rest[0]) {
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

pub(crate) fn cmd_replay(rest: &[String]) -> ExitCode {
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
    let (record, args) = match acp_core::ledger::read_record(&rest[0], seq) {
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

/// H2.1: load-run tooling. Append N decision records to a fresh ledger and time append + verify, so
/// the large-ledger cost model can be measured on real hardware (the 100M run is the same command
/// with a bigger N on a load box).
pub(crate) fn cmd_bench_ledger(rest: &[String]) -> ExitCode {
    use acp_core::sign::Ed25519Signer;
    use acp_core::ledger::Ledger;
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

/// Backup the evidence ledger and verify the copy (P1 #8). Copies the db plus its WAL/SHM so the
/// snapshot is consistent, then runs the standalone verify on the destination and fails if it does
/// not check out. Quiesce writers for a fully consistent snapshot; for a live hot backup use the
/// sqlite backup API (future).
///   acp ledger-backup <src.db> <dst.db>
pub(crate) fn cmd_ledger_backup(rest: &[String]) -> ExitCode {
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
    match acp_core::ledger::verify_file(dst) {
        Ok(()) => { println!("backup OK: {dst} copied and verifies"); ExitCode::SUCCESS }
        Err(e) => { eprintln!("acp: backup {dst} does NOT verify: {e}"); ExitCode::from(1) }
    }
}

/// Render a ledger's governed decisions to a SIEM line format for forwarding.
///   acp siem <ledger.db> --format <cef|ocsf|syslog>
pub(crate) fn cmd_siem(rest: &[String]) -> ExitCode {
    use acp_core::siem::{to_cef, to_ocsf, to_syslog, DecisionEvent};
    let Some(db) = rest.iter().find(|a| !a.starts_with("--")) else {
        return usage("acp siem <ledger.db> --format <cef|ocsf|syslog>");
    };
    let format = flag_value(rest, "--format").unwrap_or_else(|| "cef".into());
    let pack = match acp_core::ledger::export_file(db) {
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
