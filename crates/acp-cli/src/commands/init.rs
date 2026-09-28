//! acp CLI commands: init.
use std::process::ExitCode;

pub(crate) const SAMPLE_POLICY: &str = "\
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

pub(crate) fn cmd_init(dir: &str) -> ExitCode {
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
