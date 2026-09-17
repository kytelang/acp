use acp_approvals::ApprovalStore;
use serde_json::json;

fn tmp(name: &str) -> String {
    format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"))
}
fn store(name: &str) -> ApprovalStore {
    let p = tmp(name);
    let _ = std::fs::remove_file(&p);
    ApprovalStore::open(&p).unwrap()
}
fn presented() -> serde_json::Value {
    json!({"tool":"payments.charge","impact":"high"})
}

#[test]
fn request_is_idempotent() {
    let s = store("a1.db");
    assert!(s
        .request(
            "id1",
            "sess",
            "alice",
            "payments.charge",
            "h1",
            &presented(),
            900_000
        )
        .unwrap());
    // a re-issue while pending does not create a second approval
    assert!(!s
        .request(
            "id1",
            "sess",
            "alice",
            "payments.charge",
            "h1",
            &presented(),
            900_000
        )
        .unwrap());
}

#[test]
fn single_use_consume() {
    let s = store("a2.db");
    s.request("id", "sess", "alice", "t", "h1", &presented(), 900_000)
        .unwrap();
    s.resolve("id", true, "approver@x", "cli").unwrap();
    // first consume succeeds and records approver
    let v = s.consume("id", "sess", "alice", "h1").unwrap();
    assert_eq!(v.state, "consumed");
    assert_eq!(v.approver.as_deref(), Some("approver@x"));
    // second consume fails (already used)
    assert!(s.consume("id", "sess", "alice", "h1").is_err());
}

#[test]
fn caller_and_canonical_binding() {
    let s = store("a3.db");
    s.request("id", "sess", "alice", "t", "h1", &presented(), 900_000)
        .unwrap();
    s.resolve("id", true, "boss", "cli").unwrap();
    // wrong session, wrong principal, wrong arg_hash each fail (approval stays approved, unused)
    assert!(s.consume("id", "OTHER", "alice", "h1").is_err());
    assert!(s.consume("id", "sess", "mallory", "h1").is_err());
    assert!(s.consume("id", "sess", "alice", "DIFFERENT").is_err());
    // the correct caller + args still works afterwards (nothing was consumed by the failures)
    assert!(s.consume("id", "sess", "alice", "h1").is_ok());
}

#[test]
fn ttl_expiry_denies() {
    let s = store("a4.db");
    s.request("id", "sess", "alice", "t", "h1", &presented(), 0)
        .unwrap(); // already expired
                   // resolve is refused on an expired approval
    assert!(s.resolve("id", true, "boss", "cli").is_err());
    assert!(s.consume("id", "sess", "alice", "h1").is_err());
}

#[test]
fn resolve_is_one_terminal_transition() {
    let s = store("a5.db");
    s.request("id", "sess", "alice", "t", "h1", &presented(), 900_000)
        .unwrap();
    s.resolve("id", true, "boss", "cli").unwrap();
    // cannot resolve again (already approved)
    assert!(s.resolve("id", false, "boss", "cli").is_err());
}

#[test]
fn concurrent_consume_only_one_wins() {
    let path = tmp("a6.db");
    let _ = std::fs::remove_file(&path);
    let s = ApprovalStore::open(&path).unwrap();
    s.request("id", "sess", "alice", "t", "h1", &presented(), 900_000)
        .unwrap();
    s.resolve("id", true, "boss", "cli").unwrap();
    drop(s);

    // Two independent connections race to consume the one approval.
    let p1 = path.clone();
    let p2 = path.clone();
    let h1 = std::thread::spawn(move || {
        ApprovalStore::open(&p1)
            .unwrap()
            .consume("id", "sess", "alice", "h1")
            .is_ok()
    });
    let h2 = std::thread::spawn(move || {
        ApprovalStore::open(&p2)
            .unwrap()
            .consume("id", "sess", "alice", "h1")
            .is_ok()
    });
    let (a, b) = (h1.join().unwrap(), h2.join().unwrap());
    assert!(
        a ^ b,
        "exactly one concurrent consume must succeed (a={a}, b={b})"
    );
}
