use acp_core::impact::ImpactTaxonomy;
use acp_core::types::BlastRadius;
use serde_json::json;

#[test]
fn default_taxonomy_matches_heuristic() {
    let t = ImpactTaxonomy::default();
    assert_eq!(
        t.score("db.query", &json!({"operation":"read"})),
        BlastRadius::Low
    );
    assert_eq!(
        t.score(
            "payments.charge",
            &json!({"amount_cents":90000,"recipient":"x@y.z"})
        ),
        BlastRadius::High
    );
    assert!(t.version.starts_with("impact@"));
}

#[test]
fn per_tenant_taxonomy_scores_differently() {
    // a healthcare-style taxonomy: any external recipient is High on its own
    let src = "version: impact@health-1\nexternal_keys: [to, patient_id]\nmedium_at: 1\nhigh_at: 2\namount_keys: []\ndestructive_ops: []\ndestructive_tool_substrings: []\namount_high_threshold: 0\n";
    let t = ImpactTaxonomy::from_yaml(src).unwrap();
    // same call the default taxonomy would score Low is High here
    assert_eq!(
        t.score("records.export", &json!({"patient_id":"p1"})),
        BlastRadius::High
    );
    assert_eq!(t.version, "impact@health-1");
}
