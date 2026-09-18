# CLAUDE.md - ACP (Agent Control Plane)

ACP is a transparent MCP proxy that gates AI-agent tool calls, holds high-impact actions for human
approval, and writes a signed, tamper-evident evidence log. The trust surface is **Rust everywhere**
(crates under `crates/`); the web console (`acp-console/`) is **Kyte + datastar** and is deliberately
kept out of the enforcement path (read-only reporting only). The product is **fully local / on-prem
by design**: no cloud dependency, no Kubernetes required. Entra ID is the one accepted external
identity option, and even that is optional (any OIDC works via the JWKS seam; it is mocked in tests).

Docs style: Indian English, British spellings in prose, and no em or en dashes.

## Build and test

```sh
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Gotchas learned the hard way:
- `cargo test --workspace` can be slow to compile (the `tokio-postgres` dep tree). Prefer testing
  per crate when iterating: `cargo test -p acp-core`, `-p acp-ledger`, etc.
- Benchmarks are fsync/compute bound in debug; use `--release` (e.g. `acp-cli bench-ledger`).
- Some tests are env-gated so they skip cleanly without their backend:
  - Postgres (`acp-pgstore`): `ACP_PG_TEST_URL=postgresql://acp_app:acp@localhost:5432/acp_test`
    (the app role must be NOSUPERUSER so FORCE row-level security applies).
  - HSM (`acp-hsm`): `ACP_PKCS11_MODULE`, `ACP_PKCS11_SLOT`, `ACP_PKCS11_PIN`, `ACP_PKCS11_LABEL`,
    with `SOFTHSM2_CONF` for SoftHSM. Run these with `-- --test-threads=1` (PKCS#11 `C_Initialize`
    is once-per-process; parallel test threads segfault the module).
- Scripts (`scripts/pentest.sh`, `scripts/shakedown.sh`, `scripts/run-local.sh`) are bash.

## Testing on Linux (Multipass)

The enforcement core must build and pass on Linux, not just macOS. A local Ubuntu VM via Multipass
is the run-verify:

```sh
multipass launch --name acp-linux 24.04        # or reuse an existing instance
# rustup (the distro cargo is often older than the workspace's rust-version):
multipass exec acp-linux -- bash -lc 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; source ~/.cargo/env; rustup default stable'
# ship a clean source snapshot (tracked files only, no target/):
git archive --format=tar.gz -o /tmp/acp-src.tar.gz HEAD
multipass transfer /tmp/acp-src.tar.gz acp-linux:/home/ubuntu/acp-src.tar.gz
multipass exec acp-linux -- bash -lc 'mkdir -p ~/acp && tar xzf ~/acp-src.tar.gz -C ~/acp && cd ~/acp && source ~/.cargo/env && cargo test --workspace'
# resilience + security drills on Linux:
multipass exec acp-linux -- bash -lc 'cd ~/acp && source ~/.cargo/env && bash scripts/pentest.sh && bash scripts/shakedown.sh'
```

Verified on Linux aarch64 (Multipass, Ubuntu 24.04, rustc 1.98): the trust core and policy engine
build and pass, `acp-core` + `acp-jsonrpc` + `acp-ledger` (15 tests) + `acp-policy` (cedar) all green.
Low-RAM tip: linking the cedar-policy test binary in debug can OOM a small VM (`ld ... signal 9`);
build those with `RUSTFLAGS="-C debuginfo=0"` and `-j 1`, or give the VM >= 6 GB. The CI
ubuntu-latest leg runs the full workspace with normal resources.

To exercise the env-gated backends on Linux too: `apt-get install -y softhsm2 postgresql`, create the
`acp_app` Postgres role, init a SoftHSM token, and export the same env vars as above.

## Testing on Windows

Multipass does not run Windows guests, so use one of these:

1. **CI (the default).** `.github/workflows/ci.yml` runs a target-OS matrix including
   `windows-latest`: it builds the workspace and runs `cargo test --workspace` on Windows on every
   push. This is the routine Windows verification. Check the matrix leg is green before a release.

2. **A local Windows VM** (Parallels / VMware / UTM / Hyper-V) or a cloud Windows box:
   - Install Rust via the rustup-init.exe (MSVC toolchain) and the Visual Studio Build Tools
     (the MSVC linker + Windows SDK). `rustup default stable-msvc`.
   - Copy the source (git clone, or the `git archive` tarball as above) and run
     `cargo build --workspace` then `cargo test --workspace` in PowerShell.
   - `rusqlite` is bundled (no system SQLite needed) and `ring`/`rustls` build on MSVC, so the
     trust core and both transports compile natively.

3. **Cross-compile smoke from any host** (compile-only, does not run):
   `rustup target add x86_64-pc-windows-gnu && cargo build -p acp-cli --target x86_64-pc-windows-gnu`
   (needs the mingw-w64 linker: `brew install mingw-w64`). Use this for a quick portability check;
   real behaviour still needs option 1 or 2.

### Windows-specific notes

- The bash scripts (`pentest.sh`, `shakedown.sh`, `run-local.sh`, `sbom.sh`) need **WSL2** or
  **Git Bash**; they do not run in cmd/PowerShell as-is. The CI Windows leg therefore runs
  `cargo test` only, not the shell drills (those run on the Linux leg).
- `acp-hsm` on Windows needs a Windows PKCS#11 module (`.dll`): a Windows SoftHSM build for testing,
  or the real HSM vendor's Windows driver. Same env vars, pointed at the `.dll`.
- Graceful shutdown: the server drains on Ctrl-C; the Unix `SIGTERM` path is compiled out on Windows
  (`#[cfg(unix)]`), so on Windows drain is Ctrl-C / CTRL_CLOSE only.
- Path separators and the break-glass grant-file path are handled by `std::path`; pass Windows paths
  to `--break-glass-file` and `--ledger` normally.

## Layout

- `crates/` : the Rust workspace (trust surface). Key crates: acp-core (merkle/sign/policy cores),
  acp-ledger (verifiable log), acp-policy (YAML->Cedar), acp-proxy/acp-server/acp-cli, acp-auth
  (Entra OIDC + RBAC), acp-mtls, acp-encrypt (BYOK), acp-hsm (PKCS#11), acp-pgstore (Postgres RLS).
- `acp-console/` : the Kyte + datastar web console (read-only view over acp-server).
- `scripts/` : run-local, pentest, shakedown, sbom, package.
- `docs/` : DESIGN.md, PLAN.md, and the ops/compliance guides.
