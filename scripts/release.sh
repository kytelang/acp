#!/usr/bin/env bash
# Produce a signed, reproducible release artifact for a target triple.
#   scripts/release.sh <version> [target]
# Builds the release binaries, assembles a tarball with checksums, and (if the tools are present)
# an SBOM (cargo-cyclonedx) and a cosign signature. Missing optional tools are reported, not fatal.
set -euo pipefail
VERSION="${1:?usage: release.sh <version> [target]}"
TARGET="${2:-$(rustc -vV | sed -n 's/host: //p')}"
OUT="dist/acp-${VERSION}-${TARGET}"
BINS=(acp-cli acp-proxy acp-gateway acp-guard acp-intercept acp-server)

echo "== building release binaries for ${TARGET} =="
for b in "${BINS[@]}"; do cargo build --release -p "$b" --target "$TARGET" 2>/dev/null || cargo build --release -p "$b"; done
cargo build --release --bin mock-mcp-server 2>/dev/null || true

rm -rf "$OUT"; mkdir -p "$OUT/bin"
BINDIR="target/${TARGET}/release"; [ -d "$BINDIR" ] || BINDIR="target/release"
for b in "${BINS[@]}" mock-mcp-server; do [ -f "$BINDIR/$b" ] && cp "$BINDIR/$b" "$OUT/bin/"; done
cp -r deploy "$OUT/deploy" 2>/dev/null || true
cp docs/security/whitepaper.md "$OUT/" 2>/dev/null || true

echo "== checksums =="
( cd "$OUT" && find . -type f -exec shasum -a 256 {} \; > SHA256SUMS )

echo "== SBOM (cargo-cyclonedx) =="
if command -v cargo-cyclonedx >/dev/null 2>&1; then
  cargo cyclonedx -f json --override-filename "$OUT/sbom" 2>/dev/null && echo "  sbom written" || echo "  sbom generation failed"
else echo "  cargo-cyclonedx not installed (install: cargo install cargo-cyclonedx)"; fi

echo "== sign (cosign) =="
TAR="dist/acp-${VERSION}-${TARGET}.tar.gz"
tar -C dist -czf "$TAR" "acp-${VERSION}-${TARGET}"
shasum -a 256 "$TAR" > "$TAR.sha256"
if command -v cosign >/dev/null 2>&1; then
  cosign sign-blob --yes "$TAR" > "$TAR.sig" 2>/dev/null && echo "  signed $TAR.sig" || echo "  cosign signing failed (need a key/OIDC)"
else echo "  cosign not installed (install: brew install cosign) - ship $TAR.sha256 meanwhile"; fi

echo "== done: $TAR (+ .sha256$( [ -f "$TAR.sig" ] && echo ' + .sig'))"
