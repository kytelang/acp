//! Entra / OIDC identity-cutover preflight: verify the RBAC setup without starting the server.
use crate::common::{load_jwks, now_ms};

/// Verify the identity configuration, then exit: resolve the issuer/audience/JWKS, fetch and parse
/// the JWKS, and (when a sample token is given) run full verification, printing each claim check and
/// the effective capabilities. Always exits the process: 0 on success, 1 on any failure.
pub(crate) async fn run(
    entra_tenant: &Option<String>,
    entra_audience: &Option<String>,
    oidc_jwks: &Option<String>,
    oidc_issuer: &Option<String>,
    oidc_audience: &Option<String>,
    entra_test_token: &Option<String>,
) -> ! {
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        let (issuer, audience, source) = match resolved {
            Some(t) => t,
            None => {
                eprintln!("preflight: need --entra-tenant + --entra-audience (or the --oidc-* flags)");
                std::process::exit(1);
            }
        };
        println!("entra preflight");
        println!("  issuer:   {issuer}");
        println!("  audience: {audience}");
        println!("  jwks:     {source}");
        let jwks = match load_jwks(&source).await {
            Ok(j) => { println!("  [ok] JWKS fetched: {} key(s)", j.key_count()); j }
            Err(e) => { println!("  [FAIL] JWKS load: {e}"); std::process::exit(1); }
        };
        if let Some(tok) = &entra_test_token {
            let cfg = acp_core::auth::EntraConfig { issuer, audience };
            match acp_core::auth::verify(tok, &jwks, &cfg, now_ms()) {
                Ok(p) => {
                    println!("  [ok] token verified");
                    println!("       oid={} user={} tid={}", p.oid, p.username, p.tenant);
                    println!("       roles: {}", if p.roles.is_empty() { "(none)".to_string() } else { p.roles.join(", ") });
                    let caps: Vec<String> = p.capabilities().into_iter().map(|c| format!("{c:?}")).collect();
                    println!("       capabilities: {}", if caps.is_empty() { "(none, fail-closed)".to_string() } else { caps.join(", ") });
                    if p.roles.is_empty() {
                        println!("  [warn] token carries no app roles; the principal can do nothing. Assign app roles in Entra.");
                    }
                }
                Err(e) => { println!("  [FAIL] token verification: {e:?}"); std::process::exit(1); }
            }
        } else {
            println!("  [note] no --entra-test-token given; JWKS reachability only. Pass a real token to verify iss/aud/nbf/exp/signature/roles end to end.");
        }
        println!("preflight OK");
        std::process::exit(0);
}
