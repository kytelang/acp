//! acp-verify: independent, offline verification of ACP evidence.
//!
//! This is the one local tool the design keeps. An auditor runs it on their own machine, with only
//! the public key inside the ledger or pack, so verification never depends on trusting the server
//! that produced the evidence. It is deliberately tiny: it verifies, and nothing else.

use std::process::ExitCode;

fn help() {
    println!(
        "acp-verify: independent, offline evidence verification.\n\n\
         Usage:\n\
         \x20 acp-verify <ledger.db>          verify a ledger file (public key only)\n\
         \x20 acp-verify --pack <pack.json>   verify a standalone export pack\n\n\
         Exit 0 if the evidence verifies, non-zero if it was tampered with or is invalid.\n\
         Verification uses only the public key embedded in the ledger or pack; it never contacts\n\
         or trusts the server that produced the evidence."
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => {
            help();
            ExitCode::from(2)
        }
        Some("--help") | Some("-h") | Some("help") => {
            help();
            ExitCode::SUCCESS
        }
        Some("--pack") => {
            let path = match args.get(2) {
                Some(p) => p,
                None => {
                    eprintln!("acp-verify: usage: acp-verify --pack <pack.json>");
                    return ExitCode::from(2);
                }
            };
            let txt = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("acp-verify: cannot read {path}: {e}");
                    return ExitCode::from(1);
                }
            };
            let v: serde_json::Value = match serde_json::from_str(&txt) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("acp-verify: {path} is not valid JSON: {e}");
                    return ExitCode::from(1);
                }
            };
            match acp_ledger::verify_pack(&v) {
                Ok(()) => {
                    println!("OK: {path} verifies (public key only)");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("acp-verify: FAILED: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some(path) => match acp_ledger::verify_file(path) {
            Ok(()) => {
                println!("OK: {path} verifies (public key only)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("acp-verify: FAILED: {e}");
                ExitCode::from(1)
            }
        },
    }
}
