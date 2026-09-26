//! acp-guard binary: thin wrapper over the shared workstation agent (guard capability).
//! Prefer `acp-agent guard`; kept for compatibility.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_guard::agent::run(std::env::args().collect()).await
}
