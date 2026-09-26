#!/bin/sh
# Varman (ACP) workstation installer for macOS and Linux.
#
#   curl -fsSL https://acpdocs.web.app/install.sh | sh
#
# It downloads the release that matches your OS and CPU and installs the client tools into
# ~/.acp/bin: `acp` (the CLI), `acp-proxy` (the MCP proxy you run in front of a tool server),
# `acp-intercept` (the forward proxy), and `acp-guard`. These are run on demand, not as services;
# to run the control plane and gateway as system services on a server, use install-server.sh.
#
# Environment overrides:
#   ACP_VERSION          a release tag such as v0.1.0 (default: the latest release)
#   ACP_REPO             owner/name of the GitHub repo (default: kytelang/acp)
#   ACP_HOME             install location (default: $HOME/.acp)
#   ACP_NO_MODIFY_PATH   set to 1 to skip editing your shell profile
set -eu

REPO="${ACP_REPO:-kytelang/acp}"
ACP_HOME="${ACP_HOME:-$HOME/.acp}"

say() { printf '%s\n' "$*"; }
err() { printf 'acp-install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "this installer needs '$1' on your PATH"; }

need uname; need tar; need mkdir
if command -v curl >/dev/null 2>&1; then DL="curl"; elif command -v wget >/dev/null 2>&1; then DL="wget"; else
  err "this installer needs either 'curl' or 'wget'"; fi

fetch() { if [ "$DL" = "curl" ]; then curl -fSL --proto '=https' --tlsv1.2 -o "$2" "$1"; else wget -q -O "$2" "$1"; fi; }
fetch_stdout() { if [ "$DL" = "curl" ]; then curl -fsSL --proto '=https' --tlsv1.2 "$1" 2>/dev/null || true; else wget -q -O - "$1" 2>/dev/null || true; fi; }

# This installs into your OWN home and edits your shell profile; do not run under sudo.
if [ -n "${SUDO_USER:-}" ] && [ "${ACP_ALLOW_ROOT:-0}" != "1" ]; then
  err "do not run the workstation installer with sudo. For a server with system services, use install-server.sh."
fi

os_raw=$(uname -s)
case "$os_raw" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux" ;;
  *) err "unsupported OS '$os_raw' (macOS and Linux here; on Windows use install.ps1)" ;;
esac
arch_raw=$(uname -m)
case "$arch_raw" in
  arm64|aarch64) ARCH="aarch64" ;;
  x86_64|amd64)  ARCH="x86_64" ;;
  *) err "unsupported CPU architecture '$arch_raw'" ;;
esac

VERSION="${ACP_VERSION:-}"
if [ -z "$VERSION" ]; then
  say "Looking up the latest Varman (ACP) release..."
  body=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest")
  VERSION=$(printf '%s' "$body" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || err "could not determine the latest release tag; set ACP_VERSION=vX.Y.Z and retry"
fi

ASSET="acp-$VERSION-$OS-$ARCH.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
say "Installing Varman (ACP) $VERSION ($OS-$ARCH) into $ACP_HOME"

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t acp-install)
trap 'rm -rf "$TMP"' EXIT INT TERM

say "Downloading $ASSET ..."
fetch "$BASE/$ASSET" "$TMP/$ASSET" || err "download failed: $BASE/$ASSET"

sums=$(fetch_stdout "$BASE/$ASSET.sha256")
if [ -n "$sums" ]; then
  say "Verifying checksum ..."
  printf '%s\n' "$sums" > "$TMP/$ASSET.sha256"
  ( cd "$TMP" && { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$ASSET.sha256"; else shasum -a 256 -c "$ASSET.sha256"; fi; } >/dev/null 2>&1 ) \
    || err "checksum verification failed for $ASSET"
else
  say "No checksum published for this asset; skipping verification."
fi

say "Extracting ..."
tar -xzf "$TMP/$ASSET" -C "$TMP"
SRC="$TMP/acp-$VERSION-$OS-$ARCH"
[ -d "$SRC/bin" ] || err "unexpected archive layout: $SRC/bin not found"

mkdir -p "$ACP_HOME/bin"
cp -R "$SRC/bin/." "$ACP_HOME/bin/"
[ -f "$SRC/VERSION" ] && cp "$SRC/VERSION" "$ACP_HOME/VERSION"
chmod +x "$ACP_HOME/bin/"* 2>/dev/null || true

BIN="$ACP_HOME/bin"
added_profile=""
if [ "${ACP_NO_MODIFY_PATH:-0}" != "1" ]; then
  line="export PATH=\"$BIN:\$PATH\""
  case "${SHELL:-}" in
    */zsh) profile="$HOME/.zshrc" ;;
    */bash) if [ -f "$HOME/.bashrc" ]; then profile="$HOME/.bashrc"; else profile="$HOME/.bash_profile"; fi ;;
    *) profile="$HOME/.profile" ;;
  esac
  if [ -n "${profile:-}" ] && ! grep -qs "# added by acp installer" "$profile" 2>/dev/null; then
    if printf '\n# added by acp installer\n%s\n' "$line" >> "$profile" 2>/dev/null; then added_profile="$profile"; fi
  fi
fi

say ""
say "Varman (ACP) $VERSION is installed in $ACP_HOME."
if [ -n "$added_profile" ]; then
  say "Added $BIN to your PATH in $added_profile. Open a new terminal, or run: export PATH=\"$BIN:\$PATH\""
else
  say "Add $BIN to your PATH:  export PATH=\"$BIN:\$PATH\""
fi
say "Check it with:  acp version"
say "Get started:   acp init acp-demo   (then read https://acpdocs.web.app/guide/16-setup)"
