//! acp CLI commands: grc.
use crate::common::*;
use serde_json::Value;
use std::process::ExitCode;

/// GRC projection (phase F): read the tamper-evident ledger and print an evidence-backed compliance
/// report mapping the signed decisions to the canonical catalogue controls (EU AI Act, NIST AI RMF,
/// ISO 42001, SOC 2 and more; see `acp_core::controls`).
///   acp grc-report <ledger.db>
pub(crate) fn cmd_grc_report(rest: &[String]) -> ExitCode {
    use acp_core::grc::{report, EvidenceSummary};
    let Some(ledger) = rest.first() else {
        return usage("acp grc-report <ledger.db>");
    };
    let pack = match acp_core::ledger::export_file(ledger) {
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
    let mut fw = String::new();
    for c in report(&s) {
        if c.framework != fw { println!("[{}]", c.framework); fw = c.framework.clone(); }
        let mark = match c.status.as_str() { "satisfied" => "PASS", "partial" => "PART", _ => "GAP " };
        println!("  {mark}  {:11} {:32} {}", c.control_id, c.title, c.rationale);
    }
    ExitCode::SUCCESS
}

/// Emit a signed AI bill of materials (CycloneDX) from an artifacts file, running each artifact
/// through the supply-chain admission gate.
///   acp aibom <artifacts.json> [--require-scan] [--key <hex>] [--strict]
/// artifacts.json: an array of objects {kind,name,digest,source,publisher,signature?,scan?,
/// high_impact?,pin?,policy?} where scan is "clean" | "unscanned" | {"findings":[..]}.
/// Prints the (signed) CycloneDX doc to stdout, a summary to stderr; --strict exits 3 if any
/// artifact is denied admission.
#[allow(dead_code)]
pub(crate) fn cmd_aibom(rest: &[String]) -> ExitCode {
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
        entries.push(BomEntry::new(
            artifact,
            scan,
            admission,
            it.get("pin").and_then(|v| v.as_str()).map(String::from),
            it.get("policy").and_then(|v| v.as_str()).map(String::from),
        ));
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

/// Maintain the AI risk register (evidence-linked; the full GRC lifecycle stays with the GRC platform).
///   acp risk add <register.json> --id X --title T --owner O --likelihood <low|medium|high> --impact <low|medium|high> --treatment <mitigate|accept|transfer|avoid> [--status <open|mitigating|accepted|closed>] [--control C]... [--decision D]... [--note N] [--key <hex>]
///   acp risk list <register.json>
///   acp risk report <register.json>
#[allow(dead_code)]
pub(crate) fn cmd_risk(rest: &[String]) -> ExitCode {
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

/// List the built-in control library (all frameworks, or one).
///   acp controls [<framework-slug>]   e.g. eu-ai-act, nist-ai-rmf, iso-42001, iso-27001, soc-2, gdpr
#[allow(dead_code)]
pub(crate) fn cmd_controls(rest: &[String]) -> ExitCode {
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
#[allow(dead_code)]
pub(crate) fn cmd_assess(rest: &[String]) -> ExitCode {
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
#[allow(dead_code)]
pub(crate) fn cmd_attest(rest: &[String]) -> ExitCode {
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
#[allow(dead_code)]
pub(crate) fn cmd_usecase(rest: &[String]) -> ExitCode {
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

/// Work an EU AI Act conformity checklist: seed it from an assessment, mark controls, and report.
///   acp conformity init <out.json> <system> [--employment|--biometric|--interacts|...]
///   acp conformity set <file.json> <control-id> <satisfied|partial|gap> [--evidence <id>]... [--owner <who>]
///   acp conformity report <file.json>
#[allow(dead_code)]
pub(crate) fn cmd_conformity(rest: &[String]) -> ExitCode {
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
#[allow(dead_code)]
pub(crate) fn cmd_modelcard(rest: &[String]) -> ExitCode {
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
