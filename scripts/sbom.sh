#!/usr/bin/env bash
# Generate a CycloneDX-style SBOM for the ACP workspace from the resolved dependency graph.
# Offline: uses `cargo metadata`, no network. Output: sbom.json at the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo metadata --format-version 1 --locked > /tmp/acp-metadata.json 2>/dev/null || \
  cargo metadata --format-version 1 > /tmp/acp-metadata.json
python3 scripts/sbom_build.py /tmp/acp-metadata.json > sbom.json
echo "wrote sbom.json ($(python3 -c 'import json,sys;print(len(json.load(open("sbom.json"))["components"]))') components)"
# Sign the SBOM so consumers can verify what they run (H0.9). Key is generated on first run.
if [ -x target/release/acp-cli ]; then CLI=target/release/acp-cli; else CLI="cargo run -q -p acp-cli --"; fi
$CLI sign-artifact sbom.json release-signing.key >/dev/null 2>&1 && echo "signed sbom.json -> sbom.json.sig" || echo "(build acp-cli to sign the SBOM)"
