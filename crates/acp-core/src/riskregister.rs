//! AI risk register (gap-closure, section 5: closing the GRC-lifecycle gap on ACP's side).
//!
//! `grc.rs` projects ledger decisions into control-evidence and framework status, but has no risk
//! register (risk items, owners, likelihood/impact, treatment and lifecycle). The full GRC lifecycle
//! stays with the GRC platform (positioning), but ACP keeps a lightweight, evidence-linked register
//! so a risk can point at the real ledger decisions and controls that bear on it. Pure and signable.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    fn score(self) -> u8 {
        match self {
            Level::Low => 1,
            Level::Medium => 2,
            Level::High => 3,
        }
    }
    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Level::Low),
            "medium" | "med" => Some(Level::Medium),
            "high" => Some(Level::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Treatment {
    Mitigate,
    Accept,
    Transfer,
    Avoid,
}

impl Treatment {
    pub fn parse(s: &str) -> Option<Treatment> {
        match s.to_ascii_lowercase().as_str() {
            "mitigate" => Some(Treatment::Mitigate),
            "accept" => Some(Treatment::Accept),
            "transfer" => Some(Treatment::Transfer),
            "avoid" => Some(Treatment::Avoid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskStatus {
    Open,
    Mitigating,
    Accepted,
    Closed,
}

impl RiskStatus {
    pub fn parse(s: &str) -> Option<RiskStatus> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Some(RiskStatus::Open),
            "mitigating" => Some(RiskStatus::Mitigating),
            "accepted" => Some(RiskStatus::Accepted),
            "closed" => Some(RiskStatus::Closed),
            _ => None,
        }
    }
}

/// One risk in the register, optionally linked to the controls and ledger decisions bearing on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskItem {
    pub id: String,
    pub title: String,
    pub owner: String,
    pub likelihood: Level,
    pub impact: Level,
    pub treatment: Treatment,
    pub status: RiskStatus,
    #[serde(default)]
    pub linked_controls: Vec<String>,
    #[serde(default)]
    pub linked_decisions: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

impl RiskItem {
    /// Inherent risk score: likelihood x impact, in 1..=9.
    pub fn score(&self) -> u8 {
        self.likelihood.score() * self.impact.score()
    }
    /// Severity band derived from the score.
    pub fn band(&self) -> &'static str {
        match self.score() {
            1..=2 => "low",
            3..=4 => "medium",
            6 => "high",
            _ => "critical", // 9
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskRegister {
    pub items: Vec<RiskItem>,
}

/// A signed register snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRegister {
    pub register: RiskRegisterView,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

/// A serialisable view of the register plus its computed heatmap, for signing/export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskRegisterView {
    pub items: Vec<RiskItem>,
    pub open: usize,
    pub critical: usize,
    pub high: usize,
}

impl RiskRegister {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a risk item by id.
    pub fn upsert(&mut self, item: RiskItem) {
        if let Some(existing) = self.items.iter_mut().find(|i| i.id == item.id) {
            *existing = item;
        } else {
            self.items.push(item);
        }
    }

    pub fn get(&self, id: &str) -> Option<&RiskItem> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn by_status(&self, status: RiskStatus) -> Vec<&RiskItem> {
        self.items.iter().filter(|i| i.status == status).collect()
    }

    /// A signable view with the heatmap counts (open, critical, high) computed.
    pub fn view(&self) -> RiskRegisterView {
        let mut items = self.items.clone();
        items.sort_by(|a, b| b.score().cmp(&a.score()).then(a.id.cmp(&b.id)));
        let open = items.iter().filter(|i| i.status == RiskStatus::Open).count();
        let critical = items.iter().filter(|i| i.band() == "critical").count();
        let high = items.iter().filter(|i| i.band() == "high").count();
        RiskRegisterView { items, open, critical, high }
    }

    /// Sign the register view.
    pub fn sign(&self, signer: &dyn Signer) -> SignedRegister {
        let register = self.view();
        let bytes = crate::canonical::canonical_bytes(&register);
        let sig = signer.sign(&bytes);
        SignedRegister {
            register,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Verify a signed register. Fail-closed on decode error.
pub fn verify(signed: &SignedRegister) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = crate::canonical::canonical_bytes(&signed.register);
    verify_ed25519(&pk, &bytes, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn item(id: &str, l: Level, i: Level, s: RiskStatus) -> RiskItem {
        RiskItem {
            id: id.into(),
            title: "t".into(),
            owner: "o".into(),
            likelihood: l,
            impact: i,
            treatment: Treatment::Mitigate,
            status: s,
            linked_controls: vec!["eu-ai-act-art-14".into()],
            linked_decisions: vec!["dec-1".into()],
            notes: String::new(),
        }
    }

    #[test]
    fn score_and_band() {
        assert_eq!(item("r", Level::High, Level::High, RiskStatus::Open).score(), 9);
        assert_eq!(item("r", Level::High, Level::High, RiskStatus::Open).band(), "critical");
        assert_eq!(item("r", Level::Low, Level::Low, RiskStatus::Open).band(), "low");
        assert_eq!(item("r", Level::Medium, Level::High, RiskStatus::Open).band(), "high");
    }

    #[test]
    fn upsert_replaces_by_id_and_view_sorts_by_score() {
        let mut reg = RiskRegister::new();
        reg.upsert(item("a", Level::Low, Level::Low, RiskStatus::Open));
        reg.upsert(item("b", Level::High, Level::High, RiskStatus::Open));
        reg.upsert(item("a", Level::High, Level::Medium, RiskStatus::Closed)); // replace a
        let v = reg.view();
        assert_eq!(reg.items.len(), 2);
        assert_eq!(v.items[0].id, "b"); // highest score first
        assert_eq!(v.open, 1);
        assert_eq!(v.critical, 1);
    }

    #[test]
    fn signed_register_verifies_and_tamper_caught() {
        let mut reg = RiskRegister::new();
        reg.upsert(item("a", Level::High, Level::High, RiskStatus::Open));
        let signed = reg.sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.register.open = 999;
        assert!(!verify(&bad));
    }
}
