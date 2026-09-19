//! Secret handling for production (hardening P0): keep secrets off the command line, and write key
//! material with owner-only permissions.

use std::io;

/// Resolve a value that may be a literal, an environment reference (`env:VAR`), or a file (`@path`).
/// So operators pass `env:ACP_UPSTREAM_KEY` or `@/run/secrets/key` instead of a secret in argv
/// (which shows in `ps`). A plain value is returned unchanged for backward compatibility.
pub fn resolve(s: &str) -> String {
    if let Some(var) = s.strip_prefix("env:") {
        std::env::var(var).unwrap_or_default()
    } else if let Some(path) = s.strip_prefix('@') {
        std::fs::read_to_string(path).map(|c| c.trim().to_string()).unwrap_or_default()
    } else {
        s.to_string()
    }
}

/// Write a key/seed file, then restrict it to owner read/write (0600 on unix), so a leaked directory
/// listing does not expose signing material.
pub fn write_key_secure(path: &str, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_reads_env_file_and_literal() {
        std::env::set_var("ACP_TEST_SECRET", "from-env");
        assert_eq!(resolve("env:ACP_TEST_SECRET"), "from-env");
        assert_eq!(resolve("plain-literal"), "plain-literal");
        let dir = std::env::temp_dir().join(format!("acp-sec-{}", std::process::id()));
        let _ = std::fs::write(&dir, "from-file\n");
        assert_eq!(resolve(&format!("@{}", dir.display())), "from-file");
        let _ = std::fs::remove_file(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn written_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("acp-key-{}", std::process::id()));
        let ps = p.to_string_lossy().to_string();
        write_key_secure(&ps, b"0123456789012345678901234567890").unwrap();
        let mode = std::fs::metadata(&ps).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&ps);
    }
}
