#!/bin/sh
# Varman (ACP) workstation installer for macOS and Linux.
#
#   curl -fsSL https://acpdocs.web.app/install.sh | sh
#
# It downloads the workstation archive for your OS and CPU and installs the client tools into
# ~/.acp/bin: `acp-agent` (the single workstation service: content firewall, MCP proxy or guard,
# forward proxy), and `acp-verify` (independent, offline evidence verification). These are run on
# demand. If you set ACP_SERVER (the control-plane URL), the installer also configures acp-agent
# as a background service (launchd on macOS, systemd --user on Linux) that pulls its governed endpoint
# set from the control plane and refreshes it, so you manage endpoints in the console, not in a file.
# The control plane, gateway and console run on a server: use install-server.sh for those.
#
# Environment overrides:
#   ACP_VERSION          a release tag such as v0.1.0 (default: the latest release)
#   ACP_REPO             owner/name of the GitHub repo (default: kytelang/acp)
#   ACP_HOME             install location (default: $HOME/.acp)
#   ACP_SERVER           control-plane base URL (e.g. http://cp.internal:8787); enables the
#                        acp-agent (content firewall) background service and its config sync
#   ACP_LISTEN           address the acp-agent firewall listens on (default: 127.0.0.1:8890)
#   ACP_NO_SERVICE       set to 1 to install binaries only, without configuring the service
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

ASSET="acp-user-$VERSION-$OS-$ARCH.tar.gz"
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
SRC="$TMP/acp-user-$VERSION-$OS-$ARCH"
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

# Configure acp-agent (content firewall) as a background service that syncs its config from the control plane. This
# only runs when ACP_SERVER is set; otherwise the tools stay on-demand.
LISTEN="${ACP_LISTEN:-127.0.0.1:8890}"
SERVICE_MSG=""
if [ -n "${ACP_SERVER:-}" ] && [ "${ACP_NO_SERVICE:-0}" != "1" ]; then
  case "$OS" in
    macos)
      AGENTS="$HOME/Library/LaunchAgents"; PLIST="$AGENTS/ai.acp.intercept.plist"
      mkdir -p "$AGENTS"
      cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ai.acp.intercept</string>
  <key>ProgramArguments</key><array>
    <string>$BIN/acp-agent</string>
    <string>firewall</string>
    <string>--listen</string><string>$LISTEN</string>
    <string>--control-plane</string><string>$ACP_SERVER</string>
    <string>--ledger</string><string>$ACP_HOME/agent.db</string>
    <string>--refresh-secs</string><string>30</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$ACP_HOME/intercept.log</string>
  <key>StandardErrorPath</key><string>$ACP_HOME/intercept.log</string>
</dict></plist>
PL
      if command -v launchctl >/dev/null 2>&1; then
        launchctl unload "$PLIST" 2>/dev/null || true
        if launchctl load -w "$PLIST" 2>/dev/null; then
          SERVICE_MSG="acp-agent (content firewall) is running as a launchd service on $LISTEN (config from $ACP_SERVER)."
        else
          SERVICE_MSG="Wrote $PLIST. Load it with: launchctl load -w \"$PLIST\""
        fi
      else
        SERVICE_MSG="Wrote $PLIST (launchctl not found; load it when available)."
      fi
      ;;
    linux)
      UDIR="$HOME/.config/systemd/user"; UNIT="$UDIR/acp-intercept.service"
      mkdir -p "$UDIR"
      cat > "$UNIT" <<UN
[Unit]
Description=Varman (ACP) forward proxy (acp-intercept)
After=network-online.target

[Service]
ExecStart=$BIN/acp-agent firewall --listen $LISTEN --control-plane $ACP_SERVER --ledger $ACP_HOME/agent.db --refresh-secs 30
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
UN
      if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload 2>/dev/null || true
        if systemctl --user enable --now acp-intercept.service 2>/dev/null; then
          SERVICE_MSG="acp-agent (content firewall) is running as a systemd --user service on $LISTEN (config from $ACP_SERVER)."
        else
          SERVICE_MSG="Wrote $UNIT. Enable it with: systemctl --user enable --now acp-intercept.service (you may need: loginctl enable-linger $USER)."
        fi
      else
        SERVICE_MSG="Wrote $UNIT (systemctl not found; enable it when available)."
      fi
      ;;
  esac
fi

say ""
say "Varman (ACP) $VERSION is installed in $ACP_HOME."
if [ -n "$added_profile" ]; then
  say "Added $BIN to your PATH in $added_profile. Open a new terminal, or run: export PATH=\"$BIN:\$PATH\""
else
  say "Add $BIN to your PATH:  export PATH=\"$BIN:\$PATH\""
fi
say "Verify evidence independently:  acp-verify <ledger.db>"
if [ -n "${SERVICE_MSG:-}" ]; then
  say "$SERVICE_MSG"
  say "Point your agents/browser HTTP(S) proxy at $LISTEN. Enrol endpoints from the console AI Endpoints page; the service picks them up on its next refresh."
elif [ -z "${ACP_SERVER:-}" ]; then
  say "Tip: set ACP_SERVER=<control-plane-url> and re-run to install acp-intercept as a background service that syncs rules from the console."
fi
say "Run the proxy in front of an MCP server, and operate everything else from the console."
say "Setup runbook:  https://acpdocs.web.app/guide/16-setup"
