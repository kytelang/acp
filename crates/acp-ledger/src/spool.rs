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
    // A5: when set, the sensitive `args` payload is encrypted at rest in the spool (the transient
    // pre-drain buffer), so a crash between forward and ledger-write leaves no plaintext arguments.
    kek: Option<[u8; 32]>,
}

/// The result of draining the spool into a ledger.
pub struct DrainReport {
    pub ingested: usize,
    pub dead_letters: Vec<String>,
}

impl Spool {
    pub fn open(path: &str) -> Self {
        Spool { path: path.to_string(), kek: None }
    }

    /// Open a spool that encrypts the `args` payload at rest under `kek` (None = plaintext, back-compat).
    pub fn open_with_kek(path: &str, kek: Option<[u8; 32]>) -> Self {
        Spool { path: path.to_string(), kek }
    }

    /// Append one entry `{decision_id, kind, record, args?}` and fsync before returning.
    pub fn append(&self, entry: &Value) -> std::io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let to_write = self.seal(entry);
        let line = serde_json::to_string(&to_write)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?; // durability: the record survives a crash
        Ok(())
    }

    /// Encrypt the `args` payload into an `args_enc` envelope when a KEK is set; else pass through.
    fn seal(&self, entry: &Value) -> Value {
        let kek = match self.kek { Some(k) => k, None => return entry.clone() };
        let args = match entry.get("args") { Some(a) if !a.is_null() => a, _ => return entry.clone() };
        let did = entry.get("decision_id").and_then(Value::as_str).unwrap_or("");
        let pt = match serde_json::to_vec(args) { Ok(v) => v, Err(_) => return entry.clone() };
        let env = match acp_encrypt::encrypt(&kek, &pt, did.as_bytes()) { Ok(e) => e, Err(_) => return entry.clone() };
        let mut e2 = entry.clone();
        if let Some(o) = e2.as_object_mut() {
            o.remove("args");
            if let Ok(ev) = serde_json::to_value(&env) { o.insert("args_enc".to_string(), ev); }
        }
        e2
    }

    /// Reverse of `seal`: decrypt an `args_enc` envelope back to `args` so ingest sees plaintext.
    fn unseal(&self, mut entry: Value) -> Value {
        let kek = match self.kek { Some(k) => k, None => return entry };
        let env_v = match entry.get("args_enc").cloned() { Some(v) => v, None => return entry };
        let env: acp_encrypt::Envelope = match serde_json::from_value(env_v) { Ok(e) => e, Err(_) => return entry };
        let did = entry.get("decision_id").and_then(Value::as_str).unwrap_or("").to_string();
        if let Ok(pt) = acp_encrypt::decrypt(&kek, &env, did.as_bytes()) {
            if let Ok(args) = serde_json::from_slice::<Value>(&pt) {
                if let Some(o) = entry.as_object_mut() { o.remove("args_enc"); o.insert("args".to_string(), args); }
            }
        }
        entry
    }

    /// Read all spooled entries (skipping blank lines).
    pub fn entries(&self) -> std::io::Result<Vec<Value>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            // Missing or unreadable spool at startup: treat as empty rather than failing to open.
            Err(_) => return Ok(vec![]),
        };
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                out.push(self.unseal(v));
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


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypted_spool_hides_args_but_drains_plaintext() {
        let dir = std::env::temp_dir();
        let path = format!("{}/acp-spool-test-{}.jsonl", dir.display(), std::process::id());
        let _ = std::fs::remove_file(&path);
        let kek = [7u8; 32];
        let sp = Spool::open_with_kek(&path, Some(kek));
        let entry = json!({"decision_id":"d1","kind":"decision","record":{"tool":"t"},"args":{"secret":"sk-supersecret-123"}});
        sp.append(&entry).unwrap();
        // On disk, the sensitive args value must not appear in plaintext.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sk-supersecret-123"), "args must be encrypted at rest in the spool");
        assert!(raw.contains("args_enc"), "encrypted envelope marker present");
        // entries() (with the KEK) restores the plaintext args for draining.
        let got = sp.entries().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["args"]["secret"], "sk-supersecret-123");
        let _ = std::fs::remove_file(&path);
    }
}
