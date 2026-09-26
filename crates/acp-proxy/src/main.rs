//! acp-proxy binary: thin wrapper over the shared workstation agent (mcp capability).
//! Prefer `acp-agent mcp`; kept for compatibility.
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    acp_proxy::agent::run(std::env::args().collect()).await
}
