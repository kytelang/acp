//! Tool-server sandbox profile (decision v2.1.2).
//!
//! A launched tool server should run with least privilege. On Linux this is enforced with seccomp /
//! landlock / cgroups; the enforcement is platform-specific, but the *profile* (which syscalls and
//! paths are permitted) is portable data that can be authored and tested anywhere. This is that
//! profile: default-deny, so anything not explicitly allowed is blocked.

use std::collections::BTreeSet;

#[derive(Debug, Default, Clone)]
pub struct SandboxProfile {
    syscalls: BTreeSet<String>,
    read_paths: BTreeSet<String>,
}

impl SandboxProfile {
    /// A conservative baseline: the syscalls a typical stdio tool server needs, nothing more.
    pub fn baseline() -> Self {
        let mut p = SandboxProfile::default();
        for s in [
            "read",
            "write",
            "close",
            "fstat",
            "mmap",
            "munmap",
            "brk",
            "exit_group",
            "rt_sigreturn",
        ] {
            p.syscalls.insert(s.to_string());
        }
        p
    }

    pub fn allow_syscall(&mut self, name: &str) {
        self.syscalls.insert(name.to_string());
    }
    pub fn allow_read(&mut self, path: &str) {
        self.read_paths.insert(path.to_string());
    }

    /// Default-deny: a syscall not on the allowlist is blocked.
    pub fn permits_syscall(&self, name: &str) -> bool {
        self.syscalls.contains(name)
    }
    pub fn permits_read(&self, path: &str) -> bool {
        self.read_paths
            .iter()
            .any(|p| path == p || path.starts_with(&format!("{p}/")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_baseline_denies_dangerous_syscalls() {
        let p = SandboxProfile::baseline();
        assert!(p.permits_syscall("read"));
        assert!(!p.permits_syscall("execve"), "no arbitrary process launch");
        assert!(!p.permits_syscall("socket"), "no network by default");
    }

    #[test]
    fn read_paths_are_scoped() {
        let mut p = SandboxProfile::baseline();
        p.allow_read("/etc/tool");
        assert!(p.permits_read("/etc/tool/config.yaml"));
        assert!(!p.permits_read("/etc/shadow"), "outside the allowed prefix");
    }
}
