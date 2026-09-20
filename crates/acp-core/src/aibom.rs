//! AI bill of materials (gap-closure, section 3).
//!
//! The registry emits a signed AI-BOM: every agent, MCP server, tool and model-class in the estate,
//! with its provenance, admission verdict, current integrity pin and the policy in force over it.
//! CycloneDX is the emitted format so it drops into tools the enterprise already has. Because it is
//! signed and cross-references the ledger, it answers "what AI is in the estate, where did each piece
//! come from, and is it governed" with evidence rather than a spreadsheet.

use crate::sign::{verify_ed25519, Signer};
use crate::supplychain::{Admission, Artifact, ScanVerdict};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One entry in the AI-BOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BomEntry {
    pub artifact: Artifact,
    pub scan: ScanVerdict,
    pub admission: Admission,
    /// The runtime integrity pin (tool fingerprint) if one is held.
    pub integrity_pin: Option<String>,
    /// The policy hash in force over this artifact, if known.
    pub policy_in_force: Option<String>,
}

/// The whole bill of materials at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBom {
    pub generated_ms: u64,
    pub entries: Vec<BomEntry>,
}

/// A signed AI-BOM: the CycloneDX document plus a signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBom {
    pub bom: Value,
    pub algo: String,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

impl AiBom {
    /// The artifacts denied admission (the ones NOT allowed into the estate).
    pub fn denied(&self) -> Vec<&BomEntry> {
        self.entries.iter().filter(|e| !e.admission.admitted()).collect()
    }

    /// Emit a CycloneDX 1.5 JSON document. Each artifact becomes a component with its provenance and
    /// ACP-specific properties (admission, scan, integrity pin, policy in force).
    pub fn cyclonedx(&self) -> Value {
        let components: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                let scan = match &e.scan {
                    ScanVerdict::Clean => "clean".to_string(),
                    ScanVerdict::Unscanned => "unscanned".to_string(),
                    ScanVerdict::Findings { issues } => format!("findings:{}", issues.join("|")),
                };
                let mut props = vec![
                    json!({"name": "acp:admission", "value": e.admission.reason()}),
                    json!({"name": "acp:scan", "value": scan}),
                    json!({"name": "acp:kind", "value": e.artifact.kind}),
                    json!({"name": "acp:source", "value": e.artifact.source}),
                ];
                if let Some(p) = &e.integrity_pin {
                    props.push(json!({"name": "acp:integrity_pin", "value": p}));
                }
                if let Some(p) = &e.policy_in_force {
                    props.push(json!({"name": "acp:policy_in_force", "value": p}));
                }
                json!({
                    "type": "machine-learning-model",
                    "name": e.artifact.name,
                    "publisher": e.artifact.publisher,
                    "hashes": [{"alg": "SHA-256", "content": e.artifact.digest}],
                    "properties": props,
                })
            })
            .collect();
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp_ms": self.generated_ms,
                "tools": [{"vendor": "ACP", "name": "acp aibom"}],
            },
            "components": components,
        })
    }

    /// Emit the CycloneDX document and sign it (canonical bytes + Ed25519).
    pub fn sign(&self, signer: &dyn Signer) -> SignedBom {
        let bom = self.cyclonedx();
        let bytes = crate::canonical::canonical_bytes(&bom);
        let sig = signer.sign(&bytes);
        SignedBom {
            bom,
            algo: signer.algorithm().to_string(),
            pubkey_hex: hex::encode(signer.public_key()),
            sig_hex: hex::encode(sig),
        }
    }
}

/// Verify a signed AI-BOM against its embedded public key. Fail-closed on any decode error.
pub fn verify(signed: &SignedBom) -> bool {
    let pk = match hex::decode(&signed.pubkey_hex) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match hex::decode(&signed.sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = crate::canonical::canonical_bytes(&signed.bom);
    verify_ed25519(&pk, &bytes, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Ed25519Signer;
    use crate::supplychain::admit;

    fn entry(name: &str, digest: &str, scan: ScanVerdict, high: bool) -> BomEntry {
        let artifact = Artifact {
            kind: "model-class".into(),
            name: name.into(),
            digest: digest.into(),
            source: "https://example".into(),
            publisher: "acme".into(),
            signature: None,
        };
        let admission = admit(&artifact, &scan, true, high);
        BomEntry { artifact, scan, admission, integrity_pin: None, policy_in_force: Some("ph-1".into()) }
    }

    #[test]
    fn cyclonedx_lists_components_and_flags_denied() {
        let bom = AiBom {
            generated_ms: 1000,
            entries: vec![
                entry("frontier/ok", "d1", ScanVerdict::Clean, true),
                entry("frontier/bad", "", ScanVerdict::Clean, true), // no digest -> denied
            ],
        };
        assert_eq!(bom.denied().len(), 1);
        let doc = bom.cyclonedx();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["components"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_signed_bom_verifies_and_tamper_is_caught() {
        let bom = AiBom { generated_ms: 1000, entries: vec![entry("frontier/ok", "d1", ScanVerdict::Clean, false)] };
        let signed = bom.sign(&Ed25519Signer::generate());
        assert!(verify(&signed));
        let mut bad = signed.clone();
        bad.bom["version"] = json!(999);
        assert!(!verify(&bad));
    }
}
