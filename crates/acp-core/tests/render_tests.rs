use acp_core::render::csv_safe;

#[test]
fn csv_formula_injection_is_neutralised() {
    assert_eq!(csv_safe("=SUM(A1:A2)"), "'=SUM(A1:A2)");
    assert_eq!(csv_safe("+1"), "'+1");
    assert_eq!(csv_safe("@cmd"), "'@cmd");
    assert_eq!(csv_safe("normal text"), "normal text");
}
