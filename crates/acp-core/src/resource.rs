//! Tool to (resource, operation) classification taxonomy (model v2, decisions D2 and D3).
//!
//! The object of an ACP policy rule is a *resource* (the class of protected system a tool touches:
//! database, filesystem, source code, and so on) and an *operation* (read, write, delete, ...).
//! Neither is asserted by the agent. Both are derived here, by the proxy, from the tool name, which
//! is the actual MCP method being invoked and therefore trusted. Arguments are never consulted for
//! classification: an agent must not be able to label a delete as a "read" to dodge a policy rule.
//! A tool whose real operation cannot be narrowed from its name is classified at its most privileged
//! operation, so ambiguity fails safe (towards more governance, not less).
//!
//! The taxonomy is declarative, versioned, and per-tenant, exactly like the impact taxonomy beside
//! it. Its version is stamped into evidence so a historical decision stays reproducible.

use serde::Deserialize;

/// The class of protected system a tool acts upon. The vocabulary is small and extensible; unknown
/// tools fall to `Other` so nothing is silently ungoverned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Resource {
    Database,
    Filesystem,
    SourceCode,
    Network,
    Secrets,
    Payments,
    Messaging,
    Compute,
    Identity,
    Other,
}

impl Resource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::Database => "database",
            Resource::Filesystem => "filesystem",
            Resource::SourceCode => "source-code",
            Resource::Network => "network",
            Resource::Secrets => "secrets",
            Resource::Payments => "payments",
            Resource::Messaging => "messaging",
            Resource::Compute => "compute",
            Resource::Identity => "identity",
            Resource::Other => "other",
        }
    }
}

/// The operation a tool performs on its resource. Derived from the tool name only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Read,
    Write,
    Delete,
    Execute,
    Egress,
    Admin,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Delete => "delete",
            Operation::Execute => "execute",
            Operation::Egress => "egress",
            Operation::Admin => "admin",
        }
    }
}

/// One classification rule: a tool-name pattern mapping to a (resource, operation).
/// `match_glob` supports `*` wildcards and `|` alternation, matched case-insensitively.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceRule {
    #[serde(rename = "match")]
    pub match_glob: String,
    pub resource: Resource,
    pub operation: Operation,
}

/// The taxonomy: ordered rules (first match wins) plus a default for unmatched tools.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceTaxonomy {
    pub version: String,
    #[serde(default)]
    pub rules: Vec<ResourceRule>,
    #[serde(default = "default_resource")]
    pub default_resource: Resource,
    #[serde(default = "default_operation")]
    pub default_operation: Operation,
}

fn default_resource() -> Resource {
    Resource::Other
}
fn default_operation() -> Operation {
    Operation::Execute
}

/// Case-insensitive wildcard match for a single pattern (supports `*` and `?`).
fn wildcard(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[i]) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            mark = i;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// True if `tool` matches `pattern`, where the pattern may contain `|`-separated alternatives.
fn pattern_matches(pattern: &str, tool: &str) -> bool {
    let t = tool.to_ascii_lowercase();
    pattern
        .split('|')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .any(|alt| wildcard(alt.to_ascii_lowercase().as_bytes(), t.as_bytes()))
}

impl ResourceTaxonomy {
    pub fn from_yaml(src: &str) -> Result<Self, String> {
        serde_yaml::from_str(src).map_err(|e| e.to_string())
    }

    /// Classify a tool into (resource, operation), first matching rule wins, else the default.
    pub fn classify(&self, tool: &str) -> (Resource, Operation) {
        for r in &self.rules {
            if pattern_matches(&r.match_glob, tool) {
                return (r.resource, r.operation);
            }
        }
        (self.default_resource, self.default_operation)
    }
}

impl Default for ResourceTaxonomy {
    fn default() -> Self {
        // Ordered specific to general: destructive and write patterns precede the general read
        // patterns for the same resource, so first-match-wins classifies at the right operation.
        let rules = [
            ("db.delete*|db.drop*|sql.delete*|sql.drop*|*.truncate*", Resource::Database, Operation::Delete),
            ("db.exec*|db.write*|db.insert*|db.update*|sql.insert*|sql.update*|sql.exec*", Resource::Database, Operation::Write),
            ("db.*|sql.*|query*|select*", Resource::Database, Operation::Read),
            ("delete_file|remove_file|rm|unlink*", Resource::Filesystem, Operation::Delete),
            ("write_file|edit_file|create_file|append_file|mkdir*", Resource::Filesystem, Operation::Write),
            ("read_file|list_dir|ls|stat|glob|grep|cat", Resource::Filesystem, Operation::Read),
            ("git.push*|git.commit*|git.*|repo.*", Resource::SourceCode, Operation::Write),
            ("http.*|https.*|fetch|curl|net.*|request*", Resource::Network, Operation::Egress),
            ("secret.*|vault.*|kms.*|get_secret*", Resource::Secrets, Operation::Read),
            ("charge_*|payment.*|refund*|transfer*|invoice.*", Resource::Payments, Operation::Execute),
            ("send_*|email.*|mail.*|slack.*|message.*|notify.*", Resource::Messaging, Operation::Execute),
            ("iam.*|role.*|grant*|revoke*|user.create*", Resource::Identity, Operation::Admin),
        ]
        .iter()
        .map(|(m, r, o)| ResourceRule {
            match_glob: (*m).to_string(),
            resource: *r,
            operation: *o,
        })
        .collect();
        ResourceTaxonomy {
            version: "resource@default-1".into(),
            rules,
            default_resource: Resource::Other,
            default_operation: Operation::Execute,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_tools() {
        let t = ResourceTaxonomy::default();
        assert_eq!(t.classify("db.query"), (Resource::Database, Operation::Read));
        assert_eq!(t.classify("db.delete_row"), (Resource::Database, Operation::Delete));
        assert_eq!(t.classify("db.insert"), (Resource::Database, Operation::Write));
        assert_eq!(t.classify("read_file"), (Resource::Filesystem, Operation::Read));
        assert_eq!(t.classify("write_file"), (Resource::Filesystem, Operation::Write));
        assert_eq!(t.classify("git.push"), (Resource::SourceCode, Operation::Write));
        assert_eq!(t.classify("http.get"), (Resource::Network, Operation::Egress));
        assert_eq!(t.classify("get_secret"), (Resource::Secrets, Operation::Read));
        assert_eq!(t.classify("charge_card"), (Resource::Payments, Operation::Execute));
    }

    #[test]
    fn unknown_tool_falls_to_other_execute() {
        let t = ResourceTaxonomy::default();
        assert_eq!(t.classify("some_novel_tool"), (Resource::Other, Operation::Execute));
    }

    #[test]
    fn destructive_pattern_wins_over_general_read() {
        // db.* would match as read, but the delete pattern is ordered first.
        let t = ResourceTaxonomy::default();
        assert_eq!(t.classify("db.drop_table").1, Operation::Delete);
    }

    #[test]
    fn serialises_from_yaml_and_stamps_version() {
        let src = "version: resource@test-1\nrules:\n  - match: \"pay.*\"\n    resource: payments\n    operation: execute\n";
        let t = ResourceTaxonomy::from_yaml(src).unwrap();
        assert_eq!(t.version, "resource@test-1");
        assert_eq!(t.classify("pay.charge"), (Resource::Payments, Operation::Execute));
        // unmatched falls to the default
        assert_eq!(t.classify("db.query"), (Resource::Other, Operation::Execute));
    }
}
