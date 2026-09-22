//! The evidence ledger (decisions D3/D6/D7/D11): a durable, append-only, RFC 6962-verifiable log.
//!
//! Records are leaves in a Merkle tree; the head is signed with Ed25519 (never per-record). The
//! SQLite store enforces append-only on `records` and `tree_heads` via triggers; `args_blob` is
//! separately purgeable so payloads can be dropped while the signed decisions stay verifiable.
//! `append` is idempotent by `decision_id` (retried batches never create duplicate leaves), and
//! `verify` catches both an edited leaf (named by seq) and a history rewrite (unsigned root).

pub mod spool;

pub mod migrate;

use acp_core::canonical::{canonical_bytes, sha256_hex};
use acp_core::merkle::{leaf_hash, Hash, MerkleLog};
use acp_core::sign::{sign_sth, verify_sth, SignedTreeHead, Signer};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS records (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  decision_id TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL,
  canonical   BLOB NOT NULL,
  leaf_hash   BLOB NOT NULL,
  args_hash   TEXT,
  created_ms  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS args_blob ( args_hash TEXT PRIMARY KEY, blob BLOB NOT NULL );
CREATE TABLE IF NOT EXISTS tree_heads ( size INTEGER PRIMARY KEY, root BLOB NOT NULL, ts_ms INTEGER NOT NULL, sig BLOB NOT NULL );
CREATE TABLE IF NOT EXISTS meta ( k TEXT PRIMARY KEY, v TEXT NOT NULL );
CREATE TRIGGER IF NOT EXISTS records_no_update BEFORE UPDATE ON records
  BEGIN SELECT RAISE(ABORT,'records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS records_no_delete BEFORE DELETE ON records
  BEGIN SELECT RAISE(ABORT,'records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS heads_no_update BEFORE UPDATE ON tree_heads
  BEGIN SELECT RAISE(ABORT,'tree heads are append-only'); END;
"#;

pub struct Ledger {
    conn: Connection,
    merkle: MerkleLog,
    signer: Box<dyn Signer + Send>,
    public_key: Vec<u8>,
    algorithm: String,
    /// Optional key-encryption key for at-rest encryption of argument blobs (P0-1). `None` keeps the
    /// legacy plaintext behaviour and reads existing plaintext ledgers unchanged.
    kek: Option<[u8; 32]>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Read the ledger key-encryption key from `ACP_LEDGER_KEK` (64 hex chars = 32 bytes). Absent or
/// malformed means no at-rest encryption, which is backward compatible with existing plaintext
/// ledgers. The KEK is never written to the database.
pub fn kek_from_env() -> Option<[u8; 32]> {
    let hexk = std::env::var("ACP_LEDGER_KEK").ok()?;
    let bytes = hex::decode(hexk.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Some(k)
}

/// Decode a stored args blob. A leading 0x01 byte marks an encrypted envelope (JSON after the tag);
/// any other first byte is legacy plaintext JSON (JSON text never begins with 0x01). Returns `None`
/// when an encrypted blob cannot be opened (no KEK, wrong KEK, or tamper), so a caller without the
/// key simply sees no recoverable arguments rather than an error.
fn decode_blob(blob: &[u8], args_hash: &str, kek: Option<[u8; 32]>) -> Option<Vec<u8>> {
    if blob.first() == Some(&0x01u8) {
        let kek = kek?;
        let env: acp_encrypt::Envelope = serde_json::from_slice(&blob[1..]).ok()?;
        acp_encrypt::decrypt(&kek, &env, args_hash.as_bytes()).ok()
    } else {
        Some(blob.to_vec())
    }
}

impl Ledger {
    /// Open (or create) a ledger at `path`, signing tree heads with `signer`. Exclusive locking
    /// gives the single-writer guarantee (D6): a second writer on the same file cannot extend it.
    /// Argument-blob encryption at rest is enabled when `ACP_LEDGER_KEK` is set (see `open_with_kek`).
    pub fn open(path: &str, signer: Box<dyn Signer + Send>) -> Result<Ledger, String> {
        Self::open_with_kek(path, signer, kek_from_env())
    }

    /// Open (or create) a ledger, encrypting argument blobs at rest under `kek` when `Some` (P0-1,
    /// decision H0.5). The KEK never touches the database, and verification is unaffected: the Merkle
    /// leaves commit to the canonical record, not to the (auxiliary, purgeable) argument blob.
    pub fn open_with_kek(
        path: &str,
        signer: Box<dyn Signer + Send>,
        kek: Option<[u8; 32]>,
    ) -> Result<Ledger, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE").ok();
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;

        let public_key = signer.public_key();
        let algorithm = signer.algorithm().to_string();
        // Pin the public key + algorithm on first open; refuse a mismatched key thereafter.
        let stored_pk: Option<String> = conn
            .query_row("SELECT v FROM meta WHERE k='public_key'", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        match stored_pk {
            None => {
                conn.execute(
                    "INSERT INTO meta(k,v) VALUES('public_key',?)",
                    params![hex::encode(&public_key)],
                )
                .map_err(|e| e.to_string())?;
                conn.execute(
                    "INSERT INTO meta(k,v) VALUES('algorithm',?)",
                    params![algorithm],
                )
                .map_err(|e| e.to_string())?;
            }
            Some(pk) if pk != hex::encode(&public_key) => {
                return Err("ledger public key does not match the provided signer".into());
            }
            _ => {}
        }

        // Rebuild the Merkle tree from stored leaves (persisted state, R4).
        let mut merkle = MerkleLog::new();
        {
            let mut stmt = conn
                .prepare("SELECT canonical FROM records ORDER BY seq")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))
                .map_err(|e| e.to_string())?;
            for row in rows {
                merkle.append(&row.map_err(|e| e.to_string())?);
            }
        }
        Ok(Ledger {
            conn,
            merkle,
            signer,
            public_key,
            algorithm,
            kek,
        })
    }

    fn existing(&self, decision_id: &str) -> Result<Option<u64>, String> {
        self.conn
            .query_row(
                "SELECT seq FROM records WHERE decision_id=?",
                params![decision_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map(|o| o.map(|v| v as u64))
            .map_err(|e| e.to_string())
    }

    /// Append a record. Idempotent by `decision_id`: a repeat returns the existing seq and does
    /// NOT extend the log (no duplicate leaves, D11). Extends the Merkle head and signs a new STH.
    pub fn append(
        &mut self,
        decision_id: &str,
        kind: &str,
        record: &Value,
        args: Option<&Value>,
    ) -> Result<u64, String> {
        if let Some(seq) = self.existing(decision_id)? {
            return Ok(seq);
        }
        // Wrap the 2-3 inserts (args_blob, records, tree_heads) plus the Merkle mutation in ONE
        // transaction: one WAL commit instead of three (perf) and atomicity (a crash never leaves a
        // record without its signed tree head). On a commit failure the DB rolls back but the
        // in-memory Merkle has the extra leaf, so we rebuild it from the persisted rows (rare path).
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| e.to_string())?;
        match self.append_txn(decision_id, kind, record, args) {
            Ok(seq) => match self.conn.execute_batch("COMMIT") {
                Ok(_) => Ok(seq),
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    self.rebuild_merkle()?;
                    Err(e.to_string())
                }
            },
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                self.rebuild_merkle()?;
                Err(e)
            }
        }
    }

    /// Encode an args blob for storage: encrypt under the KEK when configured (tag byte 0x01 followed
    /// by the envelope JSON), else store legacy plaintext. Fails closed (returns `Err`) rather than
    /// silently storing plaintext if encryption was requested but the primitive failed.
    fn encode_blob(&self, args_hash: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        match self.kek {
            Some(kek) => {
                let env = acp_encrypt::encrypt(&kek, plaintext, args_hash.as_bytes())?;
                let mut out = Vec::with_capacity(plaintext.len() + 160);
                out.push(0x01u8);
                out.extend_from_slice(&serde_json::to_vec(&env).map_err(|e| e.to_string())?);
                Ok(out)
            }
            None => Ok(plaintext.to_vec()),
        }
    }

    /// The transactional body of `append`; assumes a transaction is open.
    fn append_txn(
        &mut self,
        decision_id: &str,
        kind: &str,
        record: &Value,
        args: Option<&Value>,
    ) -> Result<u64, String> {
        let canonical = canonical_bytes(record);
        let leaf = leaf_hash(&canonical);
        let args_hash = args.map(sha256_hex);
        if let (Some(a), Some(h)) = (args, &args_hash) {
            let plaintext = serde_json::to_vec(a).map_err(|e| e.to_string())?;
            let blob = self.encode_blob(h, &plaintext)?;
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO args_blob(args_hash,blob) VALUES(?,?)",
                    params![h, blob],
                )
                .map_err(|e| e.to_string())?;
        }
        let ts = now_ms();
        self.conn
            .execute(
                "INSERT INTO records(decision_id,kind,canonical,leaf_hash,args_hash,created_ms) VALUES(?,?,?,?,?,?)",
                params![decision_id, kind, canonical, leaf.to_vec(), args_hash, ts as i64],
            )
            .map_err(|e| e.to_string())?;
        let seq = self.conn.last_insert_rowid() as u64;

        self.merkle.append(&canonical);
        let sth = SignedTreeHead {
            tree_size: self.merkle.size() as u64,
            root_hash: self.merkle.root(),
            timestamp_ms: ts,
        };
        let sig = sign_sth(&*self.signer, &sth);
        self.conn
            .execute(
                "INSERT INTO tree_heads(size,root,ts_ms,sig) VALUES(?,?,?,?)",
                params![sth.tree_size as i64, sth.root_hash.to_vec(), ts as i64, sig],
            )
            .map_err(|e| e.to_string())?;
        Ok(seq)
    }

    /// Rebuild the in-memory Merkle tree from the persisted leaves (used after a rolled-back append).
    fn rebuild_merkle(&mut self) -> Result<(), String> {
        let mut merkle = MerkleLog::new();
        let mut stmt = self
            .conn
            .prepare("SELECT canonical FROM records ORDER BY seq")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|e| e.to_string())?;
        for row in rows {
            merkle.append(&row.map_err(|e| e.to_string())?);
        }
        self.merkle = merkle;
        Ok(())
    }

    /// Append a linked outcome record for an earlier decision (D11): forwarded / not_executed /
    /// eval_error, so the ledger never implies an action happened.
    pub fn outcome(
        &mut self,
        outcome_id: &str,
        ref_seq: u64,
        kind: &str,
        detail: Option<&str>,
    ) -> Result<u64, String> {
        let rec = json!({ "schema": 1, "type": "outcome", "ref_seq": ref_seq, "kind": kind, "detail": detail });
        self.append(outcome_id, "outcome", &rec, None)
    }

    pub fn size(&self) -> usize {
        self.merkle.size()
    }

    pub fn root(&self) -> Hash {
        self.merkle.root()
    }

    /// Verify the whole ledger. Returns the first problem, or Ok. Catches an edited leaf (named by
    /// seq) and a rewrite (a stored head whose root no longer matches the current leaves, which the
    /// attacker cannot re-sign without the key).
    pub fn verify(&self) -> Result<(), String> {
        let mut merkle = MerkleLog::new();
        let mut stmt = self
            .conn
            .prepare("SELECT seq,canonical,leaf_hash FROM records ORDER BY seq")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (seq, canonical, stored_leaf) = row.map_err(|e| e.to_string())?;
            let leaf = leaf_hash(&canonical);
            if leaf.to_vec() != stored_leaf {
                return Err(format!("evidence tampered: leaf mismatch at seq {seq}"));
            }
            merkle.append(&canonical);
        }
        // Every stored head must match the current leaves at its size and carry a valid signature.
        let mut hs = self
            .conn
            .prepare("SELECT size,root,ts_ms,sig FROM tree_heads ORDER BY size")
            .map_err(|e| e.to_string())?;
        let heads = hs
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        // Verify each stored head incrementally: advance an O(log n) tree to the head's size and
        // compare its root. Heads are in ascending size order, so each leaf is folded exactly once,
        // making the whole head check O(n log n) instead of O(n^2).
        let mut any = false;
        let mut inc = MerkleLog::new();
        let mut next_leaf = 0usize;
        for head in heads {
            any = true;
            let (size, root, ts, sig) = head.map_err(|e| e.to_string())?;
            let size = size as usize;
            if size > merkle.size() {
                return Err(format!(
                    "tree head size {size} exceeds record count {}",
                    merkle.size()
                ));
            }
            while next_leaf < size {
                inc.append_hash(merkle.leaf(next_leaf).unwrap());
                next_leaf += 1;
            }
            let recomputed = inc.root();
            if recomputed.to_vec() != root {
                return Err(format!(
                    "history rewrite: root at size {size} does not match signed head"
                ));
            }
            let sth = SignedTreeHead {
                tree_size: size as u64,
                root_hash: recomputed,
                timestamp_ms: ts as u64,
            };
            if !verify_sth(&self.public_key, &sth, &sig) {
                return Err(format!("invalid signature on tree head at size {size}"));
            }
        }
        if !any && merkle.size() > 0 {
            return Err("records exist but no signed tree head".into());
        }
        Ok(())
    }

    /// Retention purge: drop argument payloads older than `before_ms`. The signed decisions stay
    /// verifiable because the leaf commits to the record (which holds only the args hash).
    /// Right-to-erasure for a single decision (H1.9): remove the argument payload for one record
    /// without touching the leaf. The leaf hash is over the canonical record (not the args blob),
    /// so the ledger still verifies after erasure; only the recoverable value is gone.
    pub fn erase_args_for(&self, decision_id: &str) -> Result<usize, String> {
        self.conn
            .execute(
                "DELETE FROM args_blob WHERE args_hash IN (SELECT args_hash FROM records WHERE decision_id = ? AND args_hash IS NOT NULL)",
                params![decision_id],
            )
            .map_err(|e| e.to_string())
    }

    pub fn purge_args(&self, before_ms: u64) -> Result<usize, String> {
        self.conn
            .execute(
                "DELETE FROM args_blob WHERE args_hash IN (SELECT args_hash FROM records WHERE created_ms < ? AND args_hash IS NOT NULL)",
                params![before_ms as i64],
            )
            .map_err(|e| e.to_string())
    }

    /// Build a signed, self-verifying export pack (D3/M3.7). Verifiable on a clean machine with
    /// only the public key inside the pack.
    pub fn export(&self) -> Result<Value, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq,decision_id,kind,canonical FROM records ORDER BY seq")
            .map_err(|e| e.to_string())?;
        let recs: Vec<Value> = stmt
            .query_map([], |r| {
                Ok(json!({
                    "seq": r.get::<_, i64>(0)?,
                    "decision_id": r.get::<_, String>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "canonical": hex::encode(r.get::<_, Vec<u8>>(3)?),
                }))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        let (size, root, ts, sig): (i64, Vec<u8>, i64, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT size,root,ts_ms,sig FROM tree_heads ORDER BY size DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "algorithm": self.algorithm,
            "public_key": hex::encode(&self.public_key),
            "sth": { "tree_size": size, "root": hex::encode(&root), "timestamp_ms": ts, "sig": hex::encode(&sig) },
            "records": recs,
        }))
    }
}

/// Verify an export pack standalone, using only the public key inside it (no database, M3.7).
pub fn verify_pack(pack: &Value) -> Result<(), String> {
    let public_key = hex::decode(pack["public_key"].as_str().ok_or("missing public_key")?)
        .map_err(|e| e.to_string())?;
    let mut merkle = MerkleLog::new();
    for r in pack["records"].as_array().ok_or("missing records")? {
        let canonical = hex::decode(r["canonical"].as_str().ok_or("missing canonical")?)
            .map_err(|e| e.to_string())?;
        merkle.append(&canonical);
    }
    let size = pack["sth"]["tree_size"]
        .as_i64()
        .ok_or("missing tree_size")? as usize;
    let root = hex::decode(pack["sth"]["root"].as_str().ok_or("missing root")?)
        .map_err(|e| e.to_string())?;
    let sig = hex::decode(pack["sth"]["sig"].as_str().ok_or("missing sig")?)
        .map_err(|e| e.to_string())?;
    let ts = pack["sth"]["timestamp_ms"]
        .as_i64()
        .ok_or("missing timestamp")? as u64;
    if merkle.size() != size {
        return Err(format!(
            "record count {} does not match tree size {size}",
            merkle.size()
        ));
    }
    if merkle.root().to_vec() != root {
        return Err("recomputed root does not match the signed tree head".into());
    }
    let sth = SignedTreeHead {
        tree_size: size as u64,
        root_hash: merkle.root(),
        timestamp_ms: ts,
    };
    if !verify_sth(&public_key, &sth, &sig) {
        return Err("tree head signature invalid".into());
    }
    Ok(())
}

/// Verify a ledger file read-only, using only the public key stored inside it (no private key,
/// no write access). This is what `acp verify` runs.
pub fn verify_file(path: &str) -> Result<(), String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let pk_hex: String = conn
        .query_row("SELECT v FROM meta WHERE k='public_key'", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let public_key = hex::decode(&pk_hex).map_err(|e| e.to_string())?;

    let mut merkle = MerkleLog::new();
    let mut stmt = conn
        .prepare("SELECT seq,canonical,leaf_hash FROM records ORDER BY seq")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for row in rows {
        let (seq, canonical, stored_leaf) = row.map_err(|e| e.to_string())?;
        if leaf_hash(&canonical).to_vec() != stored_leaf {
            return Err(format!("evidence tampered: leaf mismatch at seq {seq}"));
        }
        merkle.append(&canonical);
    }
    let mut hs = conn
        .prepare("SELECT size,root,ts_ms,sig FROM tree_heads ORDER BY size")
        .map_err(|e| e.to_string())?;
    let heads = hs
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for head in heads {
        let (size, root, ts, sig) = head.map_err(|e| e.to_string())?;
        let size = size as usize;
        if size > merkle.size() {
            return Err(format!(
                "tree head size {size} exceeds record count {}",
                merkle.size()
            ));
        }
        let recomputed = acp_core::merkle::root_of(
            &(0..size)
                .map(|i| merkle.leaf(i).unwrap())
                .collect::<Vec<_>>(),
        );
        if recomputed.to_vec() != root {
            return Err(format!(
                "history rewrite: root at size {size} does not match signed head"
            ));
        }
        let sth = SignedTreeHead {
            tree_size: size as u64,
            root_hash: recomputed,
            timestamp_ms: ts as u64,
        };
        if !verify_sth(&public_key, &sth, &sig) {
            return Err(format!("invalid signature on tree head at size {size}"));
        }
    }
    Ok(())
}

/// Build an export pack from a ledger file read-only. This is what `acp export` runs.
pub fn export_file(path: &str) -> Result<Value, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let public_key: String = conn
        .query_row("SELECT v FROM meta WHERE k='public_key'", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let algorithm: String = conn
        .query_row("SELECT v FROM meta WHERE k='algorithm'", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT seq,decision_id,kind,canonical FROM records ORDER BY seq")
        .map_err(|e| e.to_string())?;
    let recs: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "seq": r.get::<_, i64>(0)?,
                "decision_id": r.get::<_, String>(1)?,
                "kind": r.get::<_, String>(2)?,
                "canonical": hex::encode(r.get::<_, Vec<u8>>(3)?),
            }))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let (size, root, ts, sig): (i64, Vec<u8>, i64, Vec<u8>) = conn
        .query_row(
            "SELECT size,root,ts_ms,sig FROM tree_heads ORDER BY size DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "algorithm": algorithm,
        "public_key": public_key,
        "sth": {"tree_size": size, "root": hex::encode(&root), "timestamp_ms": ts, "sig": hex::encode(&sig)},
        "records": recs,
    }))
}

/// Read a single record (and its args, if not purged) by seq, read-only. Used by `acp replay`.
/// F11: read all records and return (seq, hlc) ordered by the hybrid logical clock, giving a single
/// causally-ordered timeline across proxies (records carry an `hlc` field). Records without an hlc
/// sort first (empty string).
pub fn ordered_by_hlc(path: &str) -> Result<Vec<(u64, String)>, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT seq, canonical FROM records")
        .map_err(|e| e.to_string())?;
    let mut rows: Vec<(u64, String)> = stmt
        .query_map([], |r| {
            let seq: i64 = r.get(0)?;
            let canonical: Vec<u8> = r.get(1)?;
            let hlc = serde_json::from_slice::<Value>(&canonical)
                .ok()
                .and_then(|v| v.get("hlc").and_then(|h| h.as_str().map(str::to_string)))
                .unwrap_or_default();
            Ok((seq as u64, hlc))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    rows.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(rows)
}

pub fn read_record(path: &str, seq: u64) -> Result<(Value, Option<Value>), String> {
    read_record_with_kek(path, seq, kek_from_env())
}

/// Read a single record and its args by seq, read-only, decrypting the args blob with `kek` when the
/// blob is encrypted. `read_record` supplies the KEK from `ACP_LEDGER_KEK`.
pub fn read_record_with_kek(
    path: &str,
    seq: u64,
    kek: Option<[u8; 32]>,
) -> Result<(Value, Option<Value>), String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let (canonical, args_hash): (Vec<u8>, Option<String>) = conn
        .query_row(
            "SELECT canonical,args_hash FROM records WHERE seq=?",
            params![seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| e.to_string())?;
    let record: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    let args = match args_hash {
        Some(h) => {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT blob FROM args_blob WHERE args_hash=?",
                    params![h],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            blob.and_then(|b| decode_blob(&b, &h, kek))
                .and_then(|plain| serde_json::from_slice(&plain).ok())
        }
        None => None,
    };
    Ok((record, args))
}

/// Retention purge of a ledger file (read-write): drop argument payloads older than `before_ms`.
/// No signing key is needed -- only `args_blob` rows are removed; signed decisions stay verifiable.
pub fn purge_args_file(path: &str, before_ms: u64) -> Result<usize, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM args_blob WHERE args_hash IN (SELECT args_hash FROM records WHERE created_ms < ? AND args_hash IS NOT NULL)",
        params![before_ms as i64],
    )
    .map_err(|e| e.to_string())
}

/// Summarise the distinct tools observed in decision records and the highest impact seen for
/// each (read-only). Used by `acp learn` to propose a starter policy (E5).
pub fn observed_tools(path: &str) -> Result<Vec<(String, String)>, String> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT canonical FROM records WHERE kind='decision'")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(|e| e.to_string())?;
    let rank = |s: &str| match s {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    let mut best: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for row in rows {
        let canonical = row.map_err(|e| e.to_string())?;
        if let Ok(v) = serde_json::from_slice::<Value>(&canonical) {
            let tool = v["action"]["tool"].as_str().unwrap_or("").to_string();
            let impact = v["action"]["impact"].as_str().unwrap_or("low").to_string();
            if tool.is_empty() {
                continue;
            }
            let cur = best.entry(tool).or_insert_with(|| "low".to_string());
            if rank(&impact) > rank(cur) {
                *cur = impact;
            }
        }
    }
    Ok(best.into_iter().collect())
}
