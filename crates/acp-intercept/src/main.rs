//! acp-intercept binary: a thin wrapper over the shared workstation agent (firewall capability).
//! Prefer the unified `acp-agent firewall` service; this binary is kept for compatibility.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_intercept::agent::run(std::env::args().collect()).await
}
