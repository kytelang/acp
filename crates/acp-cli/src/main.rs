//! acp: the single CLI (init, verify, export, policy-compile, policy-test).

use std::process::ExitCode;


mod nativecompile;
mod common;
mod commands;
use common::*;
use commands::policy::*;
use commands::evidence::*;
use commands::content::*;
use commands::discover::*;
use commands::supplychain::*;
use commands::grc::*;
use commands::init::*;

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
        "approve" => retired("approve", "Resolve holds from the console Approvals inbox, or POST /approvals/:id/approve."),
        "deny" => retired("deny", "Resolve holds from the console Approvals inbox, or POST /approvals/:id/deny."),
        "approvals" => retired("approvals", "See the console Approvals inbox, or GET /approvals/pending."),
        "init" => cmd_init(args.get(2).map(String::as_str).unwrap_or("acp-demo")),
        "replay" => cmd_replay(&args[2..]),
        "purge" => cmd_purge(&args[2..]),
        "learn" => cmd_learn(&args[2..]),
        "classify-eval" => cmd_classify_eval(args.get(2).map(String::as_str)),
        "canary" => cmd_canary(&args[2..]),
        "diagnose" => cmd_diagnose(&args[2..]),
        "sign-artifact" => cmd_sign_artifact(&args[2..]),
        "verify-artifact" => cmd_verify_artifact(&args[2..]),
        "bench-ledger" => cmd_bench_ledger(&args[2..]),
        "break-glass" => retired("break-glass", "Operate the kill-switch from the console, or POST /break-glass/engage and /clear."),
        "app" => retired("app", "Register teams from the console Teams page, or POST /apps."),
        "agent" => retired("agent", "Register agents from the console Agents page, or POST /agents."),
        "native-compile" => cmd_native_compile(&args[2..]),
        "discover" => cmd_discover(&args[2..]),
        "coverage" => cmd_coverage(&args[2..]),
        "canary-egress" => cmd_canary_egress(&args[2..]),
        "aibom" => retired("aibom", "Create an AI-BOM record from the console Governance page, or POST /grc."),
        "enroll" => retired("enroll", "Register AI endpoints from the console AI Endpoints page, or POST /endpoints/register."),
        "siem" => cmd_siem(&args[2..]),
        "risk" => retired("risk", "Manage the risk register from the console Governance page, or POST /grc."),
        "content-scan" => cmd_content_scan(&args[2..]),
        "content-eval" => cmd_content_eval(&args[2..]),
        "redteam" => cmd_redteam(&args[2..]),
        "groundedness" => cmd_groundedness(&args[2..]),
        "controls" => retired("controls", "The control library is served by the control plane; see the console Governance page."),
        "assess" => retired("assess", "Create an assessment from the console Governance page, or POST /grc."),
        "attest" => retired("attest", "Create an attestation from the console Governance page, or POST /grc."),
        "usecase" => retired("usecase", "Manage the use-case lifecycle from the console Governance page, or POST /grc and /grc/:id/status."),
        "conformity" => retired("conformity", "Manage the conformity checklist from the console Governance page, or POST /grc."),
        "modelcard" => retired("modelcard", "Manage model cards from the console Governance page, or POST /grc."),
        "intercept" => cmd_intercept(&args[2..]),
        "grc-report" => cmd_grc_report(&args[2..]),
        "ledger-backup" => cmd_ledger_backup(&args[2..]),
        "verify-enforcement" => cmd_verify_enforcement(&args[2..]),
        "registry" => retired("registry", "Inspect teams and agents from the console, or GET /apps and /agents."),
        "policy" => cmd_policy(&args[2..]),
        "posture" => cmd_posture(&args[2..]),
        "help" | "--help" | "-h" | "version" | "--version" | "-V" => print_help(),
        _ => usage("acp [init|verify|verify-pack|export|policy-compile|policy-test|approve|deny|approvals|canary|learn|replay|purge|classify-eval]"),
    }
}


fn print_help() -> ExitCode {
    println!("Varman, the Agent Control Plane (ACP)");
    println!("Vendor-neutral, on-premises runtime authorization and verifiable evidence for AI actions.");
    println!();
    println!("Commands (offline / CI / pipeline tools):");
    println!("  verify | export | verify-pack     evidence: verify a ledger, export a signed pack");
    println!("  verify-enforcement | diagnose     confirm a PEP is enforcing; redacted support bundle");
    println!("  policy-compile | policy-test      author and test policy in CI");
    println!("  coverage | canary-egress | posture   unavoidability and default-deny readiness");
    println!("  redteam | content-scan | content-eval | groundedness   content firewall + adversarial gate");
    println!("  discover | intercept              shadow-AI discovery and traffic-interception rules");
    println!("  grc-report | siem                 framework report and SIEM projection from a ledger");
    println!("  native-compile | sign-artifact | verify-artifact   coding-agent settings, artifact signing");
    println!("  ledger-backup | purge | replay | init | learn      evidence maintenance and scaffolding");
    println!();
    println!("Managed from the console or the control-plane API (retired from the CLI):");
    println!("  teams/agents (POST /apps, /agents), AI endpoints (/endpoints/register), approvals");
    println!("  (/approvals/:id/approve|deny), policy deploy (/policy-store/deploy), the kill-switch");
    println!("  (/break-glass/engage|clear), and GRC records assessment|conformity|risk|model-card|");
    println!("  use-case|attestation|aibom (POST /grc). Run a retired command to see its console pointer.");
    println!();
    println!("Run a command with no arguments to see its usage.");
    ExitCode::SUCCESS
}
