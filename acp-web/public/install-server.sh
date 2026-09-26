#!/bin/sh
# Varman (ACP) server installer for Linux with systemd.
#
#   curl -fsSL https://acpdocs.web.app/install-server.sh | sudo sh
#
# Installs the ACP binaries system-wide and configures the components that should run as services:
# the control plane (acp-server) and, when an upstream is set, the LLM gateway (acp-gateway). It
# creates a service user, a config directory (/etc/acp) and a data directory (/var/lib/acp), and
# generates a random key-encryption key so the evidence ledger is encrypted at rest by default.
#
# Environment overrides:
#   ACP_VERSION        release tag (default: latest)         ACP_REPO      owner/name (default: kytelang/acp)
#   ACP_PREFIX         install prefix (default: /opt/acp)    ACP_DATA      data dir (default: /var/lib/acp)
#   ACP_ETC            config dir (default: /etc/acp)        ACP_USER      service user (default: acp)
#   ACP_UPSTREAM       model provider base URL; setting it enables and starts the gateway service
#   ACP_BUDGET_PG      Postgres DSN for shared budgets (used by the gateway when set)
#   ACP_NO_START       set to 1 to install and enable but not start the services
set -eu

REPO="${ACP_REPO:-kytelang/acp}"
PREFIX="${ACP_PREFIX:-/opt/acp}"
DATA="${ACP_DATA:-/var/lib/acp}"
ETC="${ACP_ETC:-/etc/acp}"
SVCUSER="${ACP_USER:-acp}"

say() { printf '%s\n' "$*"; }
err() { printf 'acp-server-install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "this installer needs '$1'"; }

[ "$(id -u)" = "0" ] || err "run this as root (sudo). It installs system binaries and systemd services."
[ "$(uname -s)" = "Linux" ] || err "the server installer targets Linux with systemd."
command -v systemctl >/dev/null 2>&1 || err "systemd (systemctl) is required."
need uname; need tar; need install; need useradd
if command -v curl >/dev/null 2>&1; then DL="curl"; elif command -v wget >/dev/null 2>&1; then DL="wget"; else err "need curl or wget"; fi
fetch() { if [ "$DL" = "curl" ]; then curl -fSL --proto '=https' --tlsv1.2 -o "$2" "$1"; else wget -q -O "$2" "$1"; fi; }
fetch_stdout() { if [ "$DL" = "curl" ]; then curl -fsSL "$1" 2>/dev/null || true; else wget -q -O - "$1" 2>/dev/null || true; fi; }

arch_raw=$(uname -m)
case "$arch_raw" in arm64|aarch64) ARCH="aarch64" ;; x86_64|amd64) ARCH="x86_64" ;; *) err "unsupported CPU '$arch_raw'" ;; esac

VERSION="${ACP_VERSION:-}"
if [ -z "$VERSION" ]; then
  body=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest")
  VERSION=$(printf '%s' "$body" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || err "could not find the latest release; set ACP_VERSION=vX.Y.Z"
fi
ASSET="acp-server-$VERSION-linux-$ARCH.tar.gz"
CONSOLE_ASSET="acp-console-$VERSION-linux-$ARCH.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"
say "Installing Varman (ACP) server $VERSION (linux-$ARCH)"

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT INT TERM
verify_asset() { # verify_asset <asset>
  s=$(fetch_stdout "$BASE/$1.sha256")
  if [ -n "$s" ]; then printf '%s\n' "$s" > "$TMP/$1.sha256"; ( cd "$TMP" && sha256sum -c "$1.sha256" >/dev/null 2>&1 ) || err "checksum failed for $1"; fi
}
fetch "$BASE/$ASSET" "$TMP/$ASSET" || err "download failed: $BASE/$ASSET"
verify_asset "$ASSET"
tar -xzf "$TMP/$ASSET" -C "$TMP"
SRC="$TMP/acp-server-$VERSION-linux-$ARCH"
[ -d "$SRC/bin" ] || err "unexpected server archive layout"

# The console is a best-effort asset (built by the Kyte toolchain in CI). A release without it still
# installs the control plane and gateway; only the web UI is skipped.
CONSOLE_SRC=""
if fetch "$BASE/$CONSOLE_ASSET" "$TMP/$CONSOLE_ASSET" 2>/dev/null; then
  verify_asset "$CONSOLE_ASSET"
  tar -xzf "$TMP/$CONSOLE_ASSET" -C "$TMP"
  CONSOLE_SRC="$TMP/acp-console-$VERSION-linux-$ARCH"
  say "Console archive found; it will be installed as a service."
else
  say "No console archive in this release; skipping the web UI (control plane and gateway still install)."
fi

# ---- service user, dirs ---------------------------------------------------
id "$SVCUSER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVCUSER"
install -d -m 0755 "$PREFIX/bin" "$ETC"
install -d -m 0750 -o "$SVCUSER" -g "$SVCUSER" "$DATA"

# ---- binaries -------------------------------------------------------------
for b in "$SRC"/bin/*; do install -m 0755 "$b" "$PREFIX/bin/"; done
for b in acp acp-server acp-gateway acp-guard acp-verify; do
  [ -f "$PREFIX/bin/$b" ] && ln -sf "$PREFIX/bin/$b" "/usr/local/bin/$b"
done
[ -f "$SRC/models/injection-lr.json" ] && install -m 0644 "$SRC/models/injection-lr.json" "$ETC/injection-lr.json"

# ---- default policy -------------------------------------------------------
if [ ! -f "$ETC/policy.yaml" ]; then
  cat > "$ETC/policy.yaml" <<'YAML'
version: 1
# Start in observe mode; move to default: deny once `acp posture` says coverage is high enough.
default: allow
rules:
  - id: no-prod-delete
    when: { resource: database, operation: delete }
    verdict: deny
  - id: payments-need-approval
    when: { resource: payments }
    verdict: step_up
    approvers: ["finance"]
YAML
fi

# ---- at-rest KEK (generated once) ----------------------------------------
if [ ! -f "$ETC/ledger.kek" ]; then
  ( od -An -N32 -tx1 /dev/urandom | tr -d ' \n' ) > "$ETC/ledger.kek"
  chmod 0640 "$ETC/ledger.kek"; chown root:"$SVCUSER" "$ETC/ledger.kek"
  say "Generated an evidence at-rest key at $ETC/ledger.kek (keep it safe; losing it makes argument payloads unreadable)."
fi

# ---- env files ------------------------------------------------------------
[ -f "$ETC/server.env" ] || cat > "$ETC/server.env" <<EOF
ACP_LEDGER_KEK_FILE=$ETC/ledger.kek
ACP_LOG=info
ACP_LOG_FORMAT=json
# Control-plane database (identity, endpoints, GRC). The backend is chosen by the URL scheme, so you
# pick the database that fits your size forecast: sqlite for small/single-node, postgres or mysql for
# larger. Default is a local sqlite file; set ACP_STORE before install to use another backend, e.g.
#   ACP_STORE=postgres://acp_app:secret@db/acp
ACP_STORE=${ACP_STORE:-sqlite://$DATA/control.db?mode=rwc}
EOF
[ -f "$ETC/gateway.env" ] || cat > "$ETC/gateway.env" <<EOF
ACP_LEDGER_KEK_FILE=$ETC/ledger.kek
ACP_LOG=info
ACP_LOG_FORMAT=json
ACP_UPSTREAM=${ACP_UPSTREAM:-}
ACP_BUDGET_PG=${ACP_BUDGET_PG:-}
EOF
chmod 0640 "$ETC"/server.env "$ETC"/gateway.env; chown root:"$SVCUSER" "$ETC"/server.env "$ETC"/gateway.env

# ---- web console (best-effort) -------------------------------------------
if [ -n "$CONSOLE_SRC" ] && [ -x "$CONSOLE_SRC/bin/acp-console" ]; then
  install -d -m 0755 "$PREFIX/console/bin"
  install -m 0755 "$CONSOLE_SRC/bin/acp-console" "$PREFIX/console/bin/acp-console"
  cp -R "$CONSOLE_SRC/wwwroot" "$PREFIX/console/wwwroot"
  [ -f "$CONSOLE_SRC/app.yaml" ] && cp "$CONSOLE_SRC/app.yaml" "$PREFIX/console/app.yaml"
  cat > /etc/systemd/system/acp-console.service <<EOF
[Unit]
Description=Varman (ACP) web console
After=network-online.target acp-server.service
Wants=network-online.target
[Service]
User=$SVCUSER
Group=$SVCUSER
WorkingDirectory=$PREFIX/console
ExecStart=$PREFIX/console/bin/acp-console
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
fi

# ---- systemd units --------------------------------------------------------
cat > /etc/systemd/system/acp-server.service <<EOF
[Unit]
Description=Varman (ACP) control plane
After=network-online.target
Wants=network-online.target
[Service]
User=$SVCUSER
Group=$SVCUSER
EnvironmentFile=$ETC/server.env
ExecStart=$PREFIX/bin/acp-server --addr 127.0.0.1:8787 --ledger $DATA/evidence.db --approvals $DATA/approvals.db --store \${ACP_STORE} --cp-key $DATA/cp.key --policy-store $DATA/policy --break-glass-file $DATA/break-glass.signed
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATA
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/acp-gateway.service <<EOF
[Unit]
Description=Varman (ACP) LLM gateway
After=network-online.target
Wants=network-online.target
[Service]
User=$SVCUSER
Group=$SVCUSER
EnvironmentFile=$ETC/gateway.env
ExecStart=$PREFIX/bin/acp-gateway --addr 0.0.0.0:8799 --policy $ETC/policy.yaml --upstream \${ACP_UPSTREAM} --content-firewall
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable acp-server >/dev/null 2>&1 || true
if [ "${ACP_NO_START:-0}" != "1" ]; then systemctl restart acp-server; fi
if [ -f /etc/systemd/system/acp-console.service ]; then
  systemctl enable acp-console >/dev/null 2>&1 || true
  [ "${ACP_NO_START:-0}" != "1" ] && systemctl restart acp-console || true
  say "Web console enabled (default http://127.0.0.1:8080)."
fi

# The gateway only makes sense with an upstream; enable and start it when one is configured.
if grep -q '^ACP_UPSTREAM=..*' "$ETC/gateway.env"; then
  systemctl enable acp-gateway >/dev/null 2>&1 || true
  [ "${ACP_NO_START:-0}" != "1" ] && systemctl restart acp-gateway || true
  say "Gateway enabled (upstream configured)."
else
  say "Gateway NOT started: set ACP_UPSTREAM in $ETC/gateway.env, then: systemctl enable --now acp-gateway"
fi

say ""
say "Varman (ACP) server $VERSION installed."
say "  binaries : $PREFIX/bin (acp, acp-server, acp-gateway, ...)"
say "  config   : $ETC (policy.yaml, server.env, gateway.env, ledger.kek)"
say "  data     : $DATA (evidence.db, approvals.db, enroll.json)"
say "  services : systemctl status acp-server acp-console   (API 127.0.0.1:8787, console 127.0.0.1:8080)"
say ""
say "Verify the evidence ledger:  acp-verify $DATA/evidence.db"
say "Full runbook:                https://acpdocs.web.app/guide/16-setup"
