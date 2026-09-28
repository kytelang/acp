//! Permission-aware retrieval (gap G7).
//!
//! When an agent retrieves documents for RAG, it must only receive documents the human it acts for is
//! allowed to see, so an AI assistant cannot become a way around document ACLs (oversharing). This is
//! the pure access decision: given the acting principal, their groups, and a candidate document's ACL,
//! decide whether the document may be returned. The PEP calls this per candidate before the documents
//! reach the model, and records the filtering.

use serde::{Deserialize, Serialize};

/// A candidate document's access control: the principals and groups allowed to see it. Empty `allow`
/// lists mean "not readable" (fail-closed), never "public".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocAcl {
    pub doc_id: String,
    #[serde(default)]
    pub allow_principals: Vec<String>,
    #[serde(default)]
    pub allow_groups: Vec<String>,
}

/// May `principal` (a member of `groups`) see `doc`? Fail-closed: an unattributed principal, or a doc
/// whose ACL names neither the principal nor any of their groups, is denied.
pub fn may_read(principal: &str, groups: &[String], doc: &DocAcl) -> bool {
    if principal.is_empty() || principal == "unattributed" {
        return false;
    }
    if doc.allow_principals.iter().any(|p| p == principal) {
        return true;
    }
    doc.allow_groups.iter().any(|g| groups.iter().any(|pg| pg == g))
}

/// Filter candidates to those the principal may read; returns (visible, filtered_out_ids).
pub fn filter<'a>(principal: &str, groups: &[String], candidates: &'a [DocAcl]) -> (Vec<&'a DocAcl>, Vec<String>) {
    let mut visible = Vec::new();
    let mut filtered = Vec::new();
    for d in candidates {
        if may_read(principal, groups, d) {
            visible.push(d);
        } else {
            filtered.push(d.doc_id.clone());
        }
    }
    (visible, filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn doc(id: &str, ps: &[&str], gs: &[&str]) -> DocAcl {
        DocAcl { doc_id: id.into(), allow_principals: ps.iter().map(|s| s.to_string()).collect(), allow_groups: gs.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn returns_only_documents_the_principal_may_see() {
        let cands = vec![doc("d1", &["alice"], &[]), doc("d2", &[], &["hr"]), doc("d3", &["bob"], &["legal"])];
        let (vis, filt) = filter("alice", &vec!["hr".into()], &cands);
        let ids: Vec<&str> = vis.iter().map(|d| d.doc_id.as_str()).collect();
        assert!(ids.contains(&"d1")); // named principal
        assert!(ids.contains(&"d2")); // via group hr
        assert!(!ids.contains(&"d3")); // neither
        assert_eq!(filt, vec!["d3".to_string()]);
    }

    #[test]
    fn unattributed_sees_nothing() {
        let cands = vec![doc("d1", &[], &["public"])];
        let (vis, _) = filter("unattributed", &vec!["public".into()], &cands);
        assert!(vis.is_empty(), "an unverified principal is fail-closed");
    }
}
