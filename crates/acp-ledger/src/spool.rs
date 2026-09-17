//! The durable, disk-backed evidence spool (decision D5).
//!
//! The proxy appends a decision to this spool (fsync) before/at forwarding, so a crash after
//! forwarding but before the ledger write loses nothing: on restart the spool is drained into the
//! ledger idempotently. A malformed entry is dead-lettered, not allowed to head-of-line-block the
//! rest of the replay (D11).

use crate::Ledger;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

pub struct Spool {
    path: String,
}

/// The result of draining the spool into a ledger.
pub struct DrainReport {
    pub ingested: usize,
    pub dead_letters: Vec<String>,
}

impl Spool {
    pub fn open(path: &str) -> Self {
        Spool {
            path: path.to_string(),
        }
    }

    /// Append one entry `{decision_id, kind, record, args?}` and fsync before returning.
    pub fn append(&self, entry: &Value) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?; // durability: the record survives a crash
        Ok(())
    }

    /// Read all spooled entries (skipping blank lines).
    pub fn entries(&self) -> std::io::Result<Vec<Value>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                out.push(v);
            }
        }
        Ok(out)
    }

    /// Drain every spooled entry into the ledger, idempotently. Malformed entries are dead-lettered
    /// and do not block the rest of the replay.
    pub fn drain_into(&self, ledger: &mut Ledger) -> std::io::Result<DrainReport> {
        let mut ingested = 0;
        let mut dead_letters = Vec::new();
        for entry in self.entries()? {
            match ingest_one(&entry, ledger) {
                Ok(()) => ingested += 1,
                Err(e) => dead_letters.push(format!("{e}: {entry}")),
            }
        }
        Ok(DrainReport {
            ingested,
            dead_letters,
        })
    }

    /// Truncate the spool (after a successful, verified drain).
    pub fn clear(&self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn ingest_one(entry: &Value, ledger: &mut Ledger) -> Result<(), String> {
    let decision_id = entry
        .get("decision_id")
        .and_then(Value::as_str)
        .ok_or("missing decision_id")?;
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("missing kind")?;
    let record = entry.get("record").ok_or("missing record")?;
    let args = entry.get("args");
    ledger.append(decision_id, kind, record, args)?;
    Ok(())
}
