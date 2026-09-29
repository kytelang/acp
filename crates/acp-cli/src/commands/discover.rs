//! acp CLI commands: discover.
use crate::common::*;
use acp_core::policy::build_context;
use std::process::ExitCode;

/// B2: canary / synthetic decisions prove the gate is actually live.
/// `acp canary <policy.yaml> <canaries.json>` evaluates a set of probe calls, each declaring the
/// verdict it must produce. Any mismatch exits non-zero so a scheduler pages: a mis-loaded policy
/// that lets a must-deny probe through is caught within one probe interval.
pub(crate) fn cmd_canary(rest: &[String]) -> ExitCode {
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
pub(crate) fn cmd_diagnose(rest: &[String]) -> ExitCode {
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
    let (record, _args) = match acp_core::ledger::read_record(ledger, seq) {
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

/// Verify an ACP enforcement attestation (P2 #14): the primitive a tool-server guard / sidecar uses
/// to reject un-proxied calls. Checks the x-acp-enforcement token against the pinned proxy pubkey and
/// a freshness bound. Exit 0 = valid, 1 = reject.
///   acp verify-enforcement <proxy-pubkey-hex> <token> [max-age-ms]
pub(crate) fn cmd_verify_enforcement(rest: &[String]) -> ExitCode {
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

/// Live discovery: poll an egress-log file and print each newly-seen shadow-AI endpoint. Runs until
/// interrupted. A weak but useful telemetry ingestion path; production feeds a sensor/eBPF stream.
pub(crate) fn discover_watch(file: &str) -> ExitCode {
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

/// Discovery plane (phase E): read observed egress endpoints (one per line) and report shadow AI,
/// classified by provider. Optional second file lists already-governed endpoints to exclude.
///   acp discover <observed.txt> [governed.txt]
pub(crate) fn cmd_discover(rest: &[String]) -> ExitCode {
    use acp_core::discovery::{find_shadow_ai, parse_access_log, AiKind};
    let positionals: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let Some(obs_file) = positionals.first().copied() else {
        return usage("acp discover <observed-or-log-file> [governed.txt] [--from squid|csv|jsonl|purview|zscaler|netskope|hosts]");
    };
    // B6: a connector reads a real-world egress/proxy/audit log format into observed hosts.
    let from_fmt: Option<String> = rest.iter().position(|a| a == "--from").and_then(|i| rest.get(i + 1)).cloned();
    let read_lines = |f: &str| -> Vec<String> {
        let content = std::fs::read_to_string(f).unwrap_or_default();
        if let Some(fmt) = &from_fmt {
            return parse_access_log(&content, fmt);
        }
        content
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
    let governed = positionals.get(1).map(|f| read_lines(f)).unwrap_or_default();
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

/// Egress canary: attempt a DIRECT (un-proxied) TCP connection to each governed model/tool host and
/// assert it is refused. The network allowlist should make direct access impossible, so a reachable
/// host is a containment breach. Exits 3 if any breach is found.
///   acp canary-egress <targets.txt> [--timeout-ms <n>]
/// targets.txt: one "host:port [kind]" per line (the hosts that must NOT be directly reachable).
pub(crate) fn cmd_canary_egress(rest: &[String]) -> ExitCode {
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

/// Endpoint interception registry: validate, sign, or test how a destination would be handled.
///   acp intercept validate <rules.yaml>
///   acp intercept sign <rules.yaml> --key <hex>
///   acp intercept match <rules.yaml> <host> [path] [port]
pub(crate) fn cmd_intercept(rest: &[String]) -> ExitCode {
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

/// Mint a signed egress-identity header (audit F2 client side). The workstation agent uses this to
/// assert who is behind an outbound call so the egress proxy can attribute the flow to a real
/// principal instead of an IP.
///   acp egress-identity --key <32-byte-hex-seed> --agent <id> --principal <id> [--group <g> ...]
/// Prints the x-acp-identity header value and the signer public key (pin it on the proxy with
/// --identity-pubkey).
pub(crate) fn cmd_egress_identity(rest: &[String]) -> std::process::ExitCode {
    use std::process::ExitCode;
    let flag = |name: &str| -> Option<String> {
        rest.iter().position(|a| a == name).and_then(|i| rest.get(i + 1).cloned())
    };
    let groups: Vec<String> = rest.iter().enumerate().filter(|(_, a)| a.as_str() == "--group")
        .filter_map(|(i, _)| rest.get(i + 1).cloned()).collect();
    let (Some(key), Some(agent), Some(principal)) = (flag("--key"), flag("--agent"), flag("--principal")) else {
        eprintln!("usage: acp egress-identity --key <32-byte-hex-seed> --agent <id> --principal <id> [--group <g> ...]");
        return ExitCode::from(2);
    };
    let seed = match hex::decode(&key) { Ok(b) if b.len() == 32 => { let mut s = [0u8; 32]; s.copy_from_slice(&b); s }, _ => { eprintln!("--key must be a 32-byte hex seed"); return ExitCode::from(2); } };
    let signer = acp_core::sign::Ed25519Signer::from_seed(&seed);
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let id = acp_core::egress::issue_identity(&signer, &agent, &principal, &groups, now_ms);
    println!("x-acp-identity: acp {}", id.encode());
    println!("# signer pubkey (pin on the proxy): --identity-pubkey {}", id.pubkey_hex);
    ExitCode::SUCCESS
}
