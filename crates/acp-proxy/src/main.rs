//! acp-proxy: sits between an MCP client and the tool server(s), decides on every
//! `tools/call`, and (from M3) streams a signed evidence record for each decision.
//!
//! M1: the transparent stdio shim. `acp-proxy stdio -- <mcp-server-cmd> [args...]`.

mod intercept;
mod limits;
mod stdio;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("stdio") => {
            let rest: Vec<String> = args.iter().skip(2).cloned().collect();
            let cmd_args: Vec<String> = match rest.iter().position(|a| a == "--") {
                Some(i) => rest[i + 1..].to_vec(),
                None => rest,
            };
            if cmd_args.is_empty() {
                eprintln!("usage: acp-proxy stdio -- <mcp-server-cmd> [args...]");
                return ExitCode::from(2);
            }
            match stdio::run(&cmd_args[0], &cmd_args[1..]).await {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    eprintln!("acp-proxy: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("usage: acp-proxy stdio -- <mcp-server-cmd> [args...]");
            ExitCode::SUCCESS
        }
    }
}
