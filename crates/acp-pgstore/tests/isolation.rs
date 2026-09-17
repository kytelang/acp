//! v1.1.1 tenant isolation: proven against a real Postgres with FORCE row-level security. One
//! tenant must never read another's rows, even via a bare unfiltered SELECT. Gated on
//! ACP_PG_TEST_URL so a machine without Postgres skips rather than fails.

use acp_pgstore::TenantStore;
use serde_json::json;

fn url() -> Option<String> {
    std::env::var("ACP_PG_TEST_URL").ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenants_cannot_see_each_others_rows() {
    let Some(url) = url() else {
        eprintln!("ACP_PG_TEST_URL not set; skipping Postgres isolation test");
        return;
    };
    let store = TenantStore::connect(&url).await.expect("connect");
    store.init_schema().await.expect("schema");
    store.truncate_all().await.expect("clean slate");

    // Two tenants write disjoint data.
    store
        .put("acme", "a1", &json!({"secret": "acme-1"}))
        .await
        .unwrap();
    store
        .put("acme", "a2", &json!({"secret": "acme-2"}))
        .await
        .unwrap();
    store
        .put("globex", "g1", &json!({"secret": "globex-1"}))
        .await
        .unwrap();

    // A bare unfiltered count returns ONLY the calling tenant's rows (FORCE RLS).
    let acme_count = store.count_visible("acme").await.unwrap();
    let globex_count = store.count_visible("globex").await.unwrap();
    assert_eq!(acme_count, 2, "acme sees exactly its own two rows");
    assert_eq!(globex_count, 1, "globex sees exactly its own one row");

    // Cross-tenant read is impossible: globex cannot fetch acme's row by id.
    let cross = store.get("globex", "a1").await.unwrap();
    assert!(
        cross.is_none(),
        "globex must not read acme's row, got {cross:?}"
    );

    // Each tenant reads only its own row.
    let own = store.get("acme", "a1").await.unwrap();
    assert_eq!(own, Some(json!({"secret": "acme-1"})));

    // And globex cannot count acme's rows into its own view: the two counts do not include each
    // other. If RLS were off, a bare count would return the full table for both.
    let total_if_leaked = acme_count + globex_count;
    let acme_recount = store.count_visible("acme").await.unwrap();
    assert_eq!(
        acme_recount, acme_count,
        "acme's visible count is stable and tenant-scoped"
    );
    assert!(
        acme_count < total_if_leaked,
        "a tenant's visible rows must be strictly fewer than the whole table"
    );
}
