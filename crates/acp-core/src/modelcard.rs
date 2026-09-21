//! Model cards (pending.md P1 #2: GRC depth).
//!
//! A model card is the documented record of an AI model or system: what it is for, its limitations,
//! how it was evaluated, who owns it, and the use case and risk tier it is bound to. It is a core
//! GRC artifact (the thing an auditor reads). Pure and signable; links to the use-case registry and
//! the risk assessment by id so the record is joined, not free-floating.

use crate::sign::{verify_ed25519, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCard {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub version: String,
    pub intended_use: String,
    pub limitations: String,
    pub training_data: String,
    pub eval_summary: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_usecase: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelCardRegistry {
    pub cards: Vec<ModelCard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedModelCards {
    pub registry_cards: Vec<ModelCard>,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

impl ModelCardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a card by id.
    pub fn upsert(&mut self, card: ModelCard) {
        if let Some(e) = self.cards.iter_mut().find(|c| c.id == card.id) {
            *e = card;
        } else {
            self.cards.push(card);
        }
    }

    pub fn get(&self, id: &str) -> Option<&ModelCard> {
        self.cards.iter().find(|c| c.id == id)
    }

    /// Cards missing any field an auditor needs (a completeness check for the GRC gate).
    pub fn incomplete(&self) -> Vec<&ModelCard> {
        self.cards
            .iter()
            .filter(|c| {
                c.intended_use.is_empty()
                    || c.limitations.is_empty()
                    || c.eval_summary.is_empty()
                    || c.owner.is_empty()
            })
            .collect()
    }

    pub fn sign(&self, signer: &dyn Signer) -> SignedModelCards {
        let mut cards = self.cards.clone();
        cards.sort_by(|a, b| a.id.cmp(&b.id));
        let bytes = crate::canonical::canonical_bytes(&cards);
        let sig = signer.sign(&bytes);
        SignedModelCards {
            registry_cards: cards,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

pub fn verify(signed: &SignedModelCards) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&pk, &crate::canonical::canonical_bytes(&signed.registry_cards), &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;

    fn card(id: &str, complete: bool) -> ModelCard {
        ModelCard {
            id: id.into(),
            name: "Hiring screener".into(),
            provider: "acme".into(),
            version: "1.0".into(),
            intended_use: if complete { "screen CVs".into() } else { String::new() },
            limitations: if complete { "no protected-attribute use".into() } else { String::new() },
            training_data: "internal HR set".into(),
            eval_summary: if complete { "bias tested".into() } else { String::new() },
            owner: if complete { "hr-lead".into() } else { String::new() },
            risk_tier: Some("high".into()),
            linked_usecase: Some("uc-hire".into()),
        }
    }

    #[test]
    fn upsert_and_get() {
        let mut r = ModelCardRegistry::new();
        r.upsert(card("m1", true));
        r.upsert(card("m1", true)); // replace, not duplicate
        assert_eq!(r.cards.len(), 1);
        assert_eq!(r.get("m1").unwrap().name, "Hiring screener");
    }

    #[test]
    fn incomplete_flags_missing_fields() {
        let mut r = ModelCardRegistry::new();
        r.upsert(card("done", true));
        r.upsert(card("wip", false));
        let inc = r.incomplete();
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].id, "wip");
    }

    #[test]
    fn signed_cards_verify_and_tamper_caught() {
        let mut r = ModelCardRegistry::new();
        r.upsert(card("m1", true));
        let signed = r.sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.registry_cards[0].owner = "someone-else".into();
        assert!(!verify(&bad));
    }
}
