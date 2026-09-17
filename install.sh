#!/bin/sh
# ACP installer (v0): build from source and install acp + acp-proxy to a bin dir.
set -e
BIN="${ACP_BIN:-$HOME/.acp/bin}"
echo "Building ACP (release)..."
cargo build --release --workspace
mkdir -p "$BIN"
cp target/release/acp-cli "$BIN/acp"
cp target/release/acp-proxy "$BIN/acp-proxy"
echo "Installed:"
echo "  $BIN/acp"
echo "  $BIN/acp-proxy"
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) echo; echo "Add to your PATH:  export PATH=\"$BIN:\$PATH\"" ;;
esac
echo
echo "Get started:  acp init && acp-proxy stdio --policy acp-demo/policy.yaml --ledger acp-demo/ledger.db -- <your-mcp-server>"
