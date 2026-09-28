//! acp CLI commands: registry.
use crate::common::*;
use std::process::ExitCode;

#[allow(dead_code)]
pub(crate) fn cmd_resolve(rest: &[String], approve: bool) -> ExitCode {
    if rest.len() < 2 {
        return usage("acp approve|deny <approvals.db> <id> [approver]");
    }
    let store = match acp_core::approvals::ApprovalStore::open(&rest[0]) {
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

#[allow(dead_code)]
pub(crate) fn cmd_list_approvals(path: &str) -> ExitCode {
    let store = match acp_core::approvals::ApprovalStore::open(path) {
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

/// Manage shadow-AI dispositions (enroll / quarantine / accept-risk), feeding the coverage report
/// and the MDM/CASB allow+block export.
///   acp enroll record <log.json> <endpoint> <enroll|quarantine|accept-risk> [--kind K] [--operator O] [--reason R] [--expires-ms N] --key <hex>
///   acp enroll governed <log.json>        (enrolled endpoints, one per line; feed to `acp coverage`)
///   acp enroll export-mdm <log.json>      (allow/block JSON for MDM/CASB)
#[allow(dead_code)]
pub(crate) fn cmd_enroll(rest: &[String]) -> ExitCode {
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

/// F2 channel: write (or clear) the break-glass grant file the proxy watches.
///   acp break-glass engage <file> <mode> <reason> <actor> <ttl_ms> [--scope <scope>]
///   scope: global | agent:<id> | resource:<class> | tool:<name>  (default global)
///   acp break-glass clear  <file>
/// Modes: lockdown_all | disable_enforce | emergency_bypass. Prints a meta-audit line to record.
#[allow(dead_code)]
pub(crate) fn cmd_break_glass(rest: &[String]) -> ExitCode {
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

#[allow(dead_code)]
pub(crate) fn cmd_app(rest: &[String]) -> ExitCode {
    match (rest.first().map(String::as_str), rest.get(1), rest.get(2), rest.get(3)) {
        (Some("register"), Some(file), Some(name), owner) => {
            let mut reg = match acp_core::registry::Registry::load(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            let app = reg.register_app(name, owner.map(String::as_str).unwrap_or(""));
            if reg.save(file).is_err() { eprintln!("acp: cannot write {file}"); return ExitCode::from(1); }
            println!("registered app: id={} name={}", app.id, app.name);
            ExitCode::SUCCESS
        }
        _ => usage("acp app register <registry.json> <name> [owner]"),
    }
}

#[allow(dead_code)]
pub(crate) fn cmd_agent(rest: &[String]) -> ExitCode {
    let reg_of = |file: &str| acp_core::registry::Registry::load(file);
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

#[allow(dead_code)]
pub(crate) fn cmd_registry(rest: &[String]) -> ExitCode {
    match (rest.first().map(String::as_str), rest.get(1)) {
        (Some("list"), Some(file)) => {
            let reg = match acp_core::registry::Registry::load(file) { Ok(r) => r, Err(e) => { eprintln!("acp: {e}"); return ExitCode::from(1); } };
            println!("apps:");
            for a in reg.apps() { println!("  {} ({}) owner={}", a.id, a.name, a.owner); }
            println!("agents:");
            for a in reg.agents() { println!("  {} ({}) app={} active={}", a.id, a.name, a.app_id, a.active); }
            ExitCode::SUCCESS
        }
        _ => usage("acp registry list <registry.json>"),
    }
}
