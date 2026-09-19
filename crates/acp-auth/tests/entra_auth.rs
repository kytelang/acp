//! H0.8 auth: the Entra ID verify-and-authorise path, exercised against a mock IdP.

use acp_auth::{verify, AuthError, Capability, MockEntra};

const NOW: u64 = 1_700_000_000_000; // fixed clock

fn idp() -> MockEntra {
    MockEntra::new("contoso-tenant", "acp-app-client-id")
}

#[test]
fn a_valid_token_authenticates_with_roles_and_capabilities() {
    let idp = idp();
    let tok = idp.issue(
        "oid-123",
        "alice@contoso.com",
        "contoso-tenant",
        &["Approver", "Auditor"],
        NOW,
        3600,
    );
    let p = verify(&tok, &idp.jwks(), &idp.config(), NOW + 1000).expect("valid");
    assert_eq!(p.oid, "oid-123");
    assert_eq!(p.tenant, "contoso-tenant");
    assert!(p.can(Capability::Approve));
    assert!(p.can(Capability::Export));
    // Roles not granted must not confer capabilities (fail-closed RBAC).
    assert!(!p.can(Capability::SeeArgs));
    assert!(!p.can(Capability::EditPolicy));
}

#[test]
fn an_expired_token_is_rejected() {
    let idp = idp();
    let tok = idp.issue("oid-1", "u", "contoso-tenant", &[], NOW, 60);
    // Well past exp + the 60s clock-skew leeway.
    let err = verify(&tok, &idp.jwks(), &idp.config(), NOW + 121_000).unwrap_err();
    assert_eq!(err, AuthError::Expired);
}

#[test]
fn a_not_yet_valid_token_is_rejected() {
    let idp = idp();
    // Issued "in the future" relative to the verify clock.
    let tok = idp.issue("oid-1", "u", "contoso-tenant", &[], NOW + 121_000, 3600);
    let err = verify(&tok, &idp.jwks(), &idp.config(), NOW).unwrap_err();
    assert_eq!(err, AuthError::NotYetValid);
}

#[test]
fn a_wrong_audience_is_rejected() {
    let idp = idp();
    let other = MockEntra::new("contoso-tenant", "some-other-app");
    // Token minted for a different audience, but we present our own JWKS/config.
    let tok = other.issue("oid-1", "u", "contoso-tenant", &[], NOW, 3600);
    // Use the attacker's key so the signature is valid but the audience is wrong.
    let err = verify(&tok, &other.jwks(), &idp.config(), NOW).unwrap_err();
    assert_eq!(err, AuthError::WrongAudience);
}

#[test]
fn a_wrong_issuer_is_rejected() {
    let idp = idp();
    let other = MockEntra::new("evil-tenant", "acp-app-client-id");
    let tok = other.issue("oid-1", "u", "evil-tenant", &[], NOW, 3600);
    let err = verify(&tok, &other.jwks(), &idp.config(), NOW).unwrap_err();
    assert_eq!(err, AuthError::WrongIssuer);
}

#[test]
fn a_tampered_payload_fails_signature() {
    let idp = idp();
    let tok = idp.issue("oid-1", "u", "contoso-tenant", &["Approver"], NOW, 3600);
    // Flip a byte in the payload segment.
    let mut parts: Vec<String> = tok.split('.').map(str::to_string).collect();
    parts[1].push('x');
    let tampered = parts.join(".");
    let err = verify(&tampered, &idp.jwks(), &idp.config(), NOW).unwrap_err();
    assert!(matches!(
        err,
        AuthError::BadSignature | AuthError::Malformed
    ));
}

#[test]
fn an_unknown_kid_is_rejected() {
    let idp = idp();
    let stranger = MockEntra::new("contoso-tenant", "acp-app-client-id");
    let tok = idp.issue("oid-1", "u", "contoso-tenant", &[], NOW, 3600);
    // Verify against a JWKS that does not contain the signing kid.
    let err = verify(&tok, &stranger.jwks(), &idp.config(), NOW).unwrap_err();
    // Different mock has a different key under the same kid -> signature fails; if kids differed it
    // would be UnknownKey. Either way it must not authenticate.
    assert!(matches!(
        err,
        AuthError::BadSignature | AuthError::UnknownKey
    ));
}

#[test]
fn a_policy_admin_can_edit_policy_only() {
    let idp = idp();
    let tok = idp.issue(
        "oid-9",
        "admin",
        "contoso-tenant",
        &["PolicyAdmin"],
        NOW,
        3600,
    );
    let p = verify(&tok, &idp.jwks(), &idp.config(), NOW).unwrap();
    assert!(p.can(Capability::EditPolicy));
    assert!(!p.can(Capability::Approve));
    assert!(!p.can(Capability::SeeArgs));
}

#[test]
fn an_auditor_has_scoped_read_only_access() {
    // v1.2.3: a non-operator auditor can export evidence but cannot edit policy, approve, or see
    // raw args. Access is scoped by the Entra role, and revoking the role (a token without it)
    // removes it.
    let idp = idp();
    let tok = idp.issue(
        "oid-aud",
        "auditor@contoso.com",
        "contoso-tenant",
        &["Auditor"],
        NOW,
        3600,
    );
    let p = verify(&tok, &idp.jwks(), &idp.config(), NOW).unwrap();
    assert!(p.can(Capability::Export), "auditor can export evidence");
    assert!(!p.can(Capability::EditPolicy), "auditor is non-operator");
    assert!(!p.can(Capability::Approve));
    assert!(!p.can(Capability::SeeArgs), "auditor cannot see raw args");

    // Revocation: a token issued without the role confers nothing.
    let revoked = idp.issue(
        "oid-aud",
        "auditor@contoso.com",
        "contoso-tenant",
        &[],
        NOW,
        3600,
    );
    let p2 = verify(&revoked, &idp.jwks(), &idp.config(), NOW).unwrap();
    assert!(!p2.can(Capability::Export), "revoked auditor loses access");
}
