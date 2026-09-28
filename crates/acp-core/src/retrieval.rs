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

/// A real connector: parse a documents-with-ACL export into DocAcls. Handles the common shapes a
/// content system exports: a top-level `documents` (or `items`/`value`) array, each entry carrying an
/// id (`doc_id`/`id`/`name`) and an ACL under `acl`/`permissions`/`sharing` with `principals`/`users`
/// and `groups`. This is what a SharePoint, Confluence or Drive export looks like once flattened, so an
/// operator points the retrieval PEP at the export their DLP or content platform already produces.
pub fn from_export(v: &serde_json::Value) -> Vec<DocAcl> {
    let arr = v.get("documents").or_else(|| v.get("items")).or_else(|| v.get("value"))
        .and_then(|x| x.as_array()).cloned()
        .unwrap_or_else(|| v.as_array().cloned().unwrap_or_default());
    let strs = |node: Option<&serde_json::Value>| -> Vec<String> {
        node.and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    arr.iter().filter_map(|d| {
        let doc_id = d.get("doc_id").or_else(|| d.get("id")).or_else(|| d.get("name")).and_then(|x| x.as_str())?.to_string();
        let acl = d.get("acl").or_else(|| d.get("permissions")).or_else(|| d.get("sharing")).unwrap_or(d);
        let allow_principals = {
            let mut p = strs(acl.get("allow_principals"));
            p.extend(strs(acl.get("principals"))); p.extend(strs(acl.get("users"))); p
        };
        let allow_groups = {
            let mut g = strs(acl.get("allow_groups"));
            g.extend(strs(acl.get("groups"))); g
        };
        Some(DocAcl { doc_id, allow_principals, allow_groups })
    }).collect()
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
    fn connector_parses_a_sharepoint_style_export() {
        let export = serde_json::json!({"documents": [
            {"id": "doc-1", "permissions": {"users": ["alice"], "groups": ["hr"]}},
            {"name": "doc-2", "acl": {"allow_groups": ["legal"]}}
        ]});
        let docs = from_export(&export);
        assert_eq!(docs.len(), 2);
        let (vis, _) = filter("alice", &vec![], &docs);
        assert_eq!(vis.len(), 1, "alice sees doc-1 via her principal, not doc-2 (legal only)");
    }

    #[test]
    fn unattributed_sees_nothing() {
        let cands = vec![doc("d1", &[], &["public"])];
        let (vis, _) = filter("unattributed", &vec!["public".into()], &cands);
        assert!(vis.is_empty(), "an unverified principal is fail-closed");
    }
}
