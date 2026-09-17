use acp_core::blast_radius::score;
use acp_core::BlastRadius;
use serde_json::json;

#[test]
fn read_is_low() {
    assert_eq!(score("db.query", &json!({"operation": "read"})), BlastRadius::Low);
}

#[test]
fn big_charge_is_high() {
    let r = score("payments.charge", &json!({"amount_cents": 90000, "recipient": "x@y.z"}));
    assert_eq!(r, BlastRadius::High);
}

#[test]
fn prod_delete_is_at_least_medium() {
    let r = score("db.delete", &json!({"operation": "delete"}));
    assert!(matches!(r, BlastRadius::Medium | BlastRadius::High));
}
