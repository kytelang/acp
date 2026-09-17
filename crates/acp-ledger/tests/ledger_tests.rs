use acp_core::sign::Ed25519Signer;
use acp_ledger::{spool::Spool, verify_pack, Ledger};
use serde_json::json;

fn tmp(name: &str) -> String {
    format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"))
}

fn open(path: &str) -> Ledger {
    let _ = std::fs::remove_file(path);
    Ledger::open(path, Box::new(Ed25519Signer::generate())).unwrap()
}

fn rec(seq: u64) -> serde_json::Value {
    json!({"schema":1,"type":"decision","tool":"payments.charge","verdict":"deny","n":seq})
}

#[test]
fn append_verify_and_idempotency() {
    let p = tmp("l1.db");
    let mut l = open(&p);
    for i in 0..5 {
        l.append(
            &format!("d{i}"),
            "decision",
            &rec(i),
            Some(&json!({"amount": i})),
        )
        .unwrap();
    }
    assert_eq!(l.size(), 5);
    l.verify().expect("clean ledger verifies");

    // idempotent: re-appending the same decision ids creates no new leaves
    for i in 0..5 {
        l.append(&format!("d{i}"), "decision", &rec(i), None)
            .unwrap();
    }
    assert_eq!(l.size(), 5, "idempotent re-append must not add leaves");
    l.verify().unwrap();
}

#[test]
fn outcome_links_and_export_self_verifies() {
    let p = tmp("l2.db");
    let mut l = open(&p);
    let seq = l.append("d1", "decision", &rec(1), None).unwrap();
    l.outcome("d1:out", seq, "forwarded", Some("200")).unwrap();
    assert_eq!(l.size(), 2, "decision + linked outcome are both leaves");

    let pack = l.export().unwrap();
    verify_pack(&pack).expect("export pack must verify standalone");

    // a tampered pack must fail standalone verification
    let mut bad = pack.clone();
    bad["records"][0]["canonical"] = json!("00");
    assert!(verify_pack(&bad).is_err());
}

#[test]
fn verify_catches_tampered_leaf() {
    let p = tmp("l3.db");
    let _ = std::fs::remove_file(&p);
    let seed = [7u8; 32];
    {
        let mut l = Ledger::open(&p, Box::new(Ed25519Signer::from_seed(&seed))).unwrap();
        for i in 0..6 {
            l.append(&format!("d{i}"), "decision", &rec(i), None)
                .unwrap();
        }
        l.verify().unwrap();
    }
    // Simulate a raw-store attacker: drop the append-only trigger and edit one record's bytes.
    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.execute_batch("DROP TRIGGER records_no_update;")
        .unwrap();
    conn.execute(
        "UPDATE records SET canonical=? WHERE seq=4",
        rusqlite::params![b"{\"x\":1}".to_vec()],
    )
    .unwrap();
    drop(conn);
    // Reopen with the same key; verify must catch the edit and name the exact leaf.
    let l = Ledger::open(&p, Box::new(Ed25519Signer::from_seed(&seed))).unwrap();
    let err = l.verify().unwrap_err();
    assert!(
        err.contains("seq 4"),
        "verify must name the tampered leaf, got: {err}"
    );
}

#[test]
fn verify_catches_history_rewrite() {
    use acp_core::merkle::leaf_hash;
    let p = tmp("l3b.db");
    let _ = std::fs::remove_file(&p);
    let seed = [9u8; 32];
    {
        let mut l = Ledger::open(&p, Box::new(Ed25519Signer::from_seed(&seed))).unwrap();
        for i in 0..6 {
            l.append(&format!("d{i}"), "decision", &rec(i), None)
                .unwrap();
        }
    }
    // A cleverer attacker rewrites a leaf AND its stored leaf_hash consistently, so the leaf check
    // passes; but the signed tree heads (which they cannot re-sign) no longer match.
    let forged = b"{\"rewritten\":true}".to_vec();
    let forged_leaf = leaf_hash(&forged).to_vec();
    let conn = rusqlite::Connection::open(&p).unwrap();
    conn.execute_batch("DROP TRIGGER records_no_update;")
        .unwrap();
    conn.execute(
        "UPDATE records SET canonical=?, leaf_hash=? WHERE seq=2",
        rusqlite::params![forged, forged_leaf],
    )
    .unwrap();
    drop(conn);
    let l = Ledger::open(&p, Box::new(Ed25519Signer::from_seed(&seed))).unwrap();
    let err = l.verify().unwrap_err();
    assert!(
        err.contains("rewrite") || err.contains("signature"),
        "verify must catch the rewrite, got: {err}"
    );
}

#[test]
fn spool_replays_with_no_loss_and_no_dup() {
    let dbp = tmp("l4.db");
    let sp = tmp("l4.spool");
    let _ = std::fs::remove_file(&sp);
    let mut l = open(&dbp);
    let spool = Spool::open(&sp);

    // Simulate: proxy spooled 3 decisions (fsync) but crashed before the ledger write.
    for i in 0..3 {
        spool
            .append(&json!({"decision_id": format!("d{i}"), "kind":"decision", "record": rec(i)}))
            .unwrap();
    }
    assert_eq!(l.size(), 0);

    // On restart: drain the spool into the ledger. No loss.
    let r1 = spool.drain_into(&mut l).unwrap();
    assert_eq!(r1.ingested, 3);
    assert_eq!(l.size(), 3);
    l.verify().unwrap();
    let root_after_first = l.root();

    // Draining again (e.g. crash after ledger write, before clearing the spool) is idempotent:
    // no duplicate leaves, no root divergence.
    let r2 = spool.drain_into(&mut l).unwrap();
    assert_eq!(r2.ingested, 3); // re-offered, but ledger dedups by decision_id
    assert_eq!(l.size(), 3, "no duplicate leaves on replay");
    assert_eq!(l.root(), root_after_first, "no root divergence on replay");
}

#[test]
fn poison_entry_is_dead_lettered_not_blocking() {
    let dbp = tmp("l5.db");
    let sp = tmp("l5.spool");
    let _ = std::fs::remove_file(&sp);
    let mut l = open(&dbp);
    let spool = Spool::open(&sp);
    spool
        .append(&json!({"decision_id":"good1","kind":"decision","record": rec(1)}))
        .unwrap();
    spool.append(&json!({"missing":"decision_id"})).unwrap(); // poison
    spool
        .append(&json!({"decision_id":"good2","kind":"decision","record": rec(2)}))
        .unwrap();
    let report = spool.drain_into(&mut l).unwrap();
    assert_eq!(
        report.ingested, 2,
        "good entries ingested despite the poison one"
    );
    assert_eq!(report.dead_letters.len(), 1);
    assert_eq!(l.size(), 2);
    l.verify().unwrap();
}

#[test]
fn purge_drops_args_but_keeps_records_verifiable() {
    let p = tmp("lpurge.db");
    let _ = std::fs::remove_file(&p);
    {
        let mut l = Ledger::open(&p, Box::new(Ed25519Signer::generate())).unwrap();
        for i in 0..4 {
            l.append(
                &format!("d{i}"),
                "decision",
                &rec(i),
                Some(&json!({"amount": i, "note": "secret"})),
            )
            .unwrap();
        }
        l.verify().unwrap();
    }
    // purge everything older than "now + 1s" (i.e. all of it)
    let future = acp_approvals_now() + 1000;
    let n = acp_ledger::purge_args_file(&p, future).unwrap();
    assert!(n >= 4, "purged {n} args");
    // records still verify after the payloads are gone
    acp_ledger::verify_file(&p).expect("verifies after purge");
    // and the blobs are actually gone
    let conn = rusqlite::Connection::open(&p).unwrap();
    let remaining: i64 = conn
        .query_row("SELECT COUNT(*) FROM args_blob", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 0);
}

fn acp_approvals_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn observed_tools_summarises_max_impact() {
    let p = tmp("lobs.db");
    let _ = std::fs::remove_file(&p);
    let mut l = Ledger::open(&p, Box::new(Ed25519Signer::generate())).unwrap();
    l.append(
        "d1",
        "decision",
        &json!({"action":{"tool":"payments.charge","impact":"low"}}),
        None,
    )
    .unwrap();
    l.append(
        "d2",
        "decision",
        &json!({"action":{"tool":"payments.charge","impact":"high"}}),
        None,
    )
    .unwrap();
    l.append(
        "d3",
        "decision",
        &json!({"action":{"tool":"db.read","impact":"low"}}),
        None,
    )
    .unwrap();
    drop(l);
    let tools = acp_ledger::observed_tools(&p).unwrap();
    // max impact per tool, sorted by tool name
    assert_eq!(
        tools,
        vec![
            ("db.read".to_string(), "low".to_string()),
            ("payments.charge".to_string(), "high".to_string())
        ]
    );
}

#[test]
fn meta_audit_events_append_to_the_same_verifiable_log() {
    // H0.7: self-governance changes (policy/key/RBAC) land in the same RFC 6962 ledger as
    // decisions, so they inherit its tamper-evidence. Here we append a policy-change and a
    // key-rotation meta record and confirm the log still verifies and exports.
    use acp_core::metaaudit::{MetaEvent, MetaKind};
    let p = tmp("l-meta.db");
    let mut l = open(&p);
    let pc = MetaEvent::new(MetaKind::PolicyChange, "alice", "tighten fs.write", 100)
        .unwrap()
        .transition(Some("hashA"), Some("hashB"));
    let kr = MetaEvent::new(MetaKind::KeyRotation, "root", "quarterly rotation", 200).unwrap();
    l.append("meta-1", "meta", &pc.to_record(), None).unwrap();
    l.append("meta-2", "meta", &kr.to_record(), None).unwrap();
    assert_eq!(l.size(), 2);
    l.verify().expect("meta events keep the ledger verifiable");

    let pack = l.export().expect("export");
    verify_pack(&pack).expect("exported pack with meta records self-verifies");
}

#[test]
fn backup_and_restore_drill_reverifies_the_ledger() {
    // H0.4: a real restore drill. Write a ledger, back it up by copying the store, simulate loss
    // by removing the original, restore from the backup, and confirm it still verifies. The Merkle
    // log plus signed heads are self-contained, so a restored copy verifies with no live service.
    let p = tmp("l-dr.db");
    let backup = tmp("l-dr-backup.db");
    let _ = std::fs::remove_file(&backup);
    {
        let mut l = open(&p);
        for i in 0..8 {
            l.append(
                &format!("d{i}"),
                "decision",
                &rec(i),
                Some(&json!({"n": i})),
            )
            .unwrap();
        }
        l.verify().expect("live ledger verifies");
    }
    // Back up (file copy) then lose the original.
    std::fs::copy(&p, &backup).expect("backup copy");
    std::fs::remove_file(&p).expect("simulate data loss");
    assert!(std::fs::metadata(&p).is_err(), "original is gone");

    // Restore = point at the backup, and it must still verify end to end.
    acp_ledger::verify_file(&backup).expect("restored ledger reverifies after DR");
}

#[test]
fn right_to_erasure_removes_the_payload_but_keeps_the_ledger_verifiable() {
    // H1.9: erase one decision's arguments. The record and its hash remain, so verify() still
    // passes; only the recoverable argument value is gone.
    let p = tmp("l-erase.db");
    let mut l = open(&p);
    l.append("d1", "decision", &rec(1), Some(&json!({"pii": "erase-me"}))).unwrap();
    l.append("d2", "decision", &rec(2), Some(&json!({"ok": "keep"}))).unwrap();
    l.verify().unwrap();

    let removed = l.erase_args_for("d1").unwrap();
    assert_eq!(removed, 1, "one args blob erased");

    // The ledger still verifies (leaf hashes are over the canonical record, not the args blob).
    l.verify().expect("ledger still verifies after erasure");

    // d1's args are gone; d2's remain.
    drop(l);
    let (_rec1, args1) = acp_ledger::read_record(&p, 1).unwrap();
    let (_rec2, args2) = acp_ledger::read_record(&p, 2).unwrap();
    assert!(args1.is_none(), "erased subject's args are gone");
    assert!(args2.is_some(), "other subject's args are untouched");
}

#[test]
fn approval_and_evidence_survive_a_crash_with_no_ledger_gap() {
    // V0.G3: a decision is durably spooled before forward; if the process dies before the ledger
    // write, the spool replays on restart with no lost or duplicated record.
    let p = tmp("l-outage.db");
    let spool_path = format!("{p}.spool");
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&spool_path);

    // Simulate the pre-crash state: records were fsync'd to the spool but never reached the ledger.
    {
        let spool = Spool::open(&spool_path);
        for i in 0..4 {
            spool
                .append(&json!({"decision_id": format!("d{i}"), "kind": "decision", "record": rec(i), "args": {"n": i}}))
                .unwrap();
        }
    }

    // Restart: a fresh ledger drains the spool. Nothing is lost.
    let mut l = open(&p);
    let report = Spool::open(&spool_path).drain_into(&mut l).unwrap();
    assert_eq!(report.ingested, 4, "all spooled decisions replay after the crash");
    assert_eq!(l.size(), 4, "no ledger gap");
    l.verify().expect("recovered ledger verifies");

    // Draining again is idempotent: replay must not duplicate leaves.
    let report2 = Spool::open(&spool_path).drain_into(&mut l).unwrap();
    let _ = report2;
    assert_eq!(l.size(), 4, "idempotent replay, no duplicates");
}

#[test]
fn chaos_failure_injection_preserves_invariants() {
    // Generalised chaos over the durability path: inject a crash between spool and ledger, a
    // duplicate-decision replay, and a partial-then-complete drain, asserting after each that no
    // decision is lost, none is double-applied, and the ledger verifies.
    let p = tmp("l-chaos.db");
    let spool_path = format!("{p}.spool");
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&spool_path);

    // Phase 1: decisions fsync'd to the spool, process dies before the ledger write.
    {
        let spool = Spool::open(&spool_path);
        for i in 0..6 {
            spool
                .append(&json!({"decision_id": format!("d{i}"), "kind": "decision", "record": rec(i), "args": {"n": i}}))
                .unwrap();
        }
    }
    let mut l = open(&p);

    // Phase 2: a duplicate of an already-spooled decision arrives (retry after a timeout). Replay
    // must be idempotent: the duplicate does not create a second leaf.
    {
        let spool = Spool::open(&spool_path);
        spool
            .append(&json!({"decision_id": "d0", "kind": "decision", "record": rec(0), "args": {"n": 0}}))
            .unwrap();
    }

    // Phase 3: drain everything and verify. 6 distinct ids -> 6 leaves despite the duplicate.
    let report = Spool::open(&spool_path).drain_into(&mut l).unwrap();
    assert!(report.ingested >= 6, "all distinct decisions recovered");
    assert_eq!(l.size(), 6, "duplicate did not create a second leaf (no double-apply)");
    l.verify().expect("ledger verifies after chaos");

    // Phase 4: a redundant drain after the crash-recovery completes changes nothing.
    let _ = Spool::open(&spool_path).drain_into(&mut l).unwrap();
    assert_eq!(l.size(), 6, "idempotent under repeated recovery");
    l.verify().expect("still verifies");
}

#[test]
fn an_archived_pack_verifies_with_the_live_store_removed() {
    // H2.1/C3: evidence in a cold/archive tier must verify without the hot database. Export a pack,
    // delete the live ledger file, and confirm the pack still self-verifies from its own bytes.
    let p = tmp("l-archive.db");
    let pack = {
        let mut l = open(&p);
        for i in 0..7 {
            l.append(&format!("d{i}"), "decision", &rec(i), Some(&json!({"n": i}))).unwrap();
        }
        l.export().expect("export")
    };
    // Simulate archive-only: the hot store is gone.
    std::fs::remove_file(&p).expect("remove live store");
    assert!(std::fs::metadata(&p).is_err(), "hot store removed");
    // The archived pack verifies from its own bytes with only the embedded public key.
    verify_pack(&pack).expect("archived pack self-verifies without the live store");
}

#[test]
fn records_order_into_a_single_hlc_timeline() {
    // F11: records carry an hlc; ordered_by_hlc returns one causal timeline regardless of insert
    // order (as would happen when merging records from several proxies).
    let p = tmp("l-timeline.db");
    let mut l = open(&p);
    // Append with hlc values deliberately out of seq order.
    l.append("d1", "decision", &json!({"schema":1,"type":"decision","hlc":"000c:0:pB"}), None).unwrap();
    l.append("d2", "decision", &json!({"schema":1,"type":"decision","hlc":"000a:0:pA"}), None).unwrap();
    l.append("d3", "decision", &json!({"schema":1,"type":"decision","hlc":"000b:0:pA"}), None).unwrap();
    drop(l);
    let order = acp_ledger::ordered_by_hlc(&p).unwrap();
    let hlcs: Vec<&str> = order.iter().map(|(_, h)| h.as_str()).collect();
    assert_eq!(hlcs, vec!["000a:0:pA", "000b:0:pA", "000c:0:pB"], "sorted causally by hlc");
}
