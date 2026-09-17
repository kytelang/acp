use acp_core::classify::classify;

#[test]
fn detects_pii_and_secret() {
    assert_eq!(
        classify("contact me at jane.doe@example.com please"),
        Some("pii")
    );
    assert_eq!(classify("token=sk_live_abcdefgh12345678"), Some("secret"));
    assert_eq!(classify("hello world"), None);
}

#[test]
fn linear_time_on_pathological_input() {
    // Rust's regex crate is linear-time; a long adversarial string must not stall.
    let s = "a".repeat(200_000);
    let start = std::time::Instant::now();
    let _ = classify(&s);
    assert!(
        start.elapsed().as_millis() < 200,
        "classifier must stay within budget"
    );
}
