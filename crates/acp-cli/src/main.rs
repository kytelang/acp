//! acp: the single CLI (init, verify, export, policy-compile, policy-test).
//! `policy-compile` is implemented against acp-policy; `verify`/`export` land in M3.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    match cmd {
        "policy-compile" => match args.get(2) {
            Some(path) => policy_compile(path),
            None => {
                eprintln!("usage: acp policy-compile <policy.yaml>");
                ExitCode::from(2)
            }
        },
        "policy-test" => {
            eprintln!("acp policy-test (skeleton) - evaluates compiled policy vs fixtures in M2");
            ExitCode::SUCCESS
        }
        "verify" => {
            eprintln!("acp verify (skeleton) - Merkle + STH + consistency via acp_core in M3");
            ExitCode::SUCCESS
        }
        "export" => {
            eprintln!("acp export (skeleton) - M3");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: acp [init|verify|export|policy-compile|policy-test]");
            ExitCode::SUCCESS
        }
    }
}

fn policy_compile(path: &str) -> ExitCode {
    let src = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("acp: cannot read {path}: {e}");
            return ExitCode::from(1);
        }
    };
    let policy = match acp_policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acp: invalid policy {path}: {e}");
            return ExitCode::from(1);
        }
    };
    print!("{}", acp_policy::compile_to_cedar(&policy));
    ExitCode::SUCCESS
}
