//! acp CLI commands: supplychain.
use crate::common::*;
use std::process::ExitCode;

/// H0.9: sign a release artifact (SBOM, binary, manifest) with an Ed25519 key. Writes <file>.sig
/// (hex signature) and <keyfile>.pub (hex public key). Generates the key if it does not exist.
pub(crate) fn cmd_sign_artifact(rest: &[String]) -> ExitCode {
    use acp_core::sign::{Ed25519Signer, Signer};
    let (file, keyfile) = match (rest.first(), rest.get(1)) {
        (Some(f), Some(k)) => (f, k),
        _ => return usage("acp sign-artifact <file> <keyfile>"),
    };
    let signer = match std::fs::read(keyfile) {
        Ok(b) if b.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&b);
            Ed25519Signer::from_seed(&s)
        }
        _ => {
            let s = Ed25519Signer::generate();
            if acp_core::secret::write_key_secure(keyfile, &s.seed()).is_err() {
                eprintln!("acp: cannot write key {keyfile}");
                return ExitCode::from(1);
            }
            s
        }
    };
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("acp: cannot read {file}: {e}");
            return ExitCode::from(1);
        }
    };
    let sig = signer.sign(&data);
    let _ = std::fs::write(format!("{file}.sig"), hex::encode(&sig));
    let _ = std::fs::write(format!("{keyfile}.pub"), hex::encode(signer.public_key()));
    println!("signed {file} -> {file}.sig (public key {keyfile}.pub)");
    ExitCode::SUCCESS
}

/// H0.9: verify a release artifact's signature under a public key.
pub(crate) fn cmd_verify_artifact(rest: &[String]) -> ExitCode {
    use acp_core::sign::verify_ed25519;
    let (file, pubfile, sigfile) = match (rest.first(), rest.get(1), rest.get(2)) {
        (Some(f), Some(p), Some(s)) => (f, p, s),
        _ => return usage("acp verify-artifact <file> <keyfile.pub> <file.sig>"),
    };
    let read_hex = |path: &str| -> Option<Vec<u8>> {
        std::fs::read_to_string(path).ok().and_then(|s| hex::decode(s.trim()).ok())
    };
    let (pk, sig, data) = match (read_hex(pubfile), read_hex(sigfile), std::fs::read(file).ok()) {
        (Some(p), Some(s), Some(d)) => (p, s, d),
        _ => {
            eprintln!("acp: cannot read inputs");
            return ExitCode::from(1);
        }
    };
    if verify_ed25519(&pk, &data, &sig) {
        println!("VERIFIED: {file} signature is valid");
        ExitCode::SUCCESS
    } else {
        println!("INVALID: {file} signature does not verify");
        ExitCode::from(1)
    }
}

/// Compile one ACP policy into a coding agent's native managed-settings (phase D):
///   acp native-compile <policy.yaml> <claude|copilot|gemini>
/// Prints the native settings JSON to stdout and a coverage report (what mapped, what is routed to
/// the proxy) to stderr.
pub(crate) fn cmd_native_compile(rest: &[String]) -> ExitCode {
    use crate::nativecompile::{compile_with_gateway, Vendor};
    let positionals: Vec<&String> = rest.iter().filter(|a| !a.starts_with("--")).collect();
    let (file, vendor_s) = match (positionals.first(), positionals.get(1)) {
        (Some(f), Some(v)) => (*f, *v),
        _ => return usage("acp native-compile <policy.yaml> <claude|copilot|gemini> [--gateway <url>]"),
    };
    let gateway = flag_value(rest, "--gateway");
    let Some(vendor) = Vendor::parse(vendor_s) else {
        eprintln!("acp: unknown vendor '{vendor_s}' (claude|copilot|gemini)");
        return ExitCode::from(2);
    };
    let src = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => { eprintln!("acp: cannot read {file}: {e}"); return ExitCode::from(1); }
    };
    let policy = match acp_core::policy::parse_str(&src) {
        Ok(p) => p,
        Err(e) => { eprintln!("acp: invalid policy: {e}"); return ExitCode::from(1); }
    };
    let c = compile_with_gateway(&policy, vendor, gateway.as_deref());
    println!("{}", serde_json::to_string_pretty(&c.settings).unwrap());
    eprintln!("coverage: {} rule(s) mapped natively [{}]", c.covered.len(), c.covered.join(", "));
    if !c.uncovered.is_empty() {
        eprintln!(
            "routed to proxy ({} rule(s) this agent cannot express natively): {}",
            c.uncovered.len(),
            c.uncovered.join(", ")
        );
    }
    ExitCode::SUCCESS
}
