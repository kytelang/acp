#!/usr/bin/env bash
# Build a self-contained ACP release: all binaries (release), the console, scripts, docs, an
# installer, and a signed manifest. Produces dist/acp-<version>-<os>-<arch>.tar.gz. Fully local.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${ACP_VERSION:-0.1.0}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
NAME="acp-${VERSION}-${OS}-${ARCH}"
STAGE="dist/${NAME}"
echo "== packaging ${NAME} =="

echo "-- building release binaries --"
cargo build --release -q -p acp-proxy -p acp-server -p acp-cli

rm -rf "$STAGE"; mkdir -p "$STAGE/bin" "$STAGE/scripts" "$STAGE/docs"
cp target/release/acp-proxy target/release/acp-server target/release/acp-cli target/release/mock-mcp-server "$STAGE/bin/"
cp scripts/run-local.sh scripts/pentest.sh scripts/sbom.sh "$STAGE/scripts/" 2>/dev/null || true
cp -r docs/ops docs/compliance "$STAGE/docs/" 2>/dev/null || true

# The Kyte console: ship source (built on the host if the kyte toolchain is present).
if [ -d acp-console ]; then
  mkdir -p "$STAGE/console"
  cp -r acp-console/src acp-console/wwwroot acp-console/project.json acp-console/README.md "$STAGE/console/" 2>/dev/null || true
fi

# Installer: put binaries on PATH under a prefix.
cat > "$STAGE/install.sh" <<'INS'
#!/usr/bin/env bash
set -euo pipefail
PREFIX="${1:-$HOME/.acp}"
cd "$(dirname "$0")"
mkdir -p "$PREFIX/bin"
cp bin/* "$PREFIX/bin/"
echo "installed ACP to $PREFIX/bin"
echo "add to PATH:  export PATH=\"$PREFIX/bin:\$PATH\""
echo "then verify:  acp-cli --help ; and run scripts/run-local.sh for a local demo"
INS
chmod +x "$STAGE/install.sh"

echo "$NAME" > "$STAGE/VERSION"
git rev-parse HEAD > "$STAGE/COMMIT" 2>/dev/null || true

# Signed manifest: sha256 of every file, signed with acp sign-artifact (Ed25519).
( cd "$STAGE" && find . -type f -not -name MANIFEST.txt | sort | while read -r f; do
    shasum -a 256 "$f"; done > MANIFEST.txt )
target/release/acp-cli sign-artifact "$STAGE/MANIFEST.txt" "dist/${NAME}.key" >/dev/null 2>&1 \
  && echo "-- signed MANIFEST.txt (public key dist/${NAME}.key.pub) --" || echo "(sign step skipped)"

tar -czf "dist/${NAME}.tar.gz" -C dist "$NAME"
echo "== wrote dist/${NAME}.tar.gz ($(du -h "dist/${NAME}.tar.gz" | cut -f1)) =="
echo "   contents: $(find "$STAGE" -type f | wc -l | tr -d ' ') files; verify the manifest with acp verify-artifact"
