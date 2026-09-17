#!/usr/bin/env bash
# Generate a CycloneDX-style SBOM for the ACP workspace from the resolved dependency graph.
# Offline: uses `cargo metadata`, no network. Output: sbom.json at the repo root.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo metadata --format-version 1 --locked > /tmp/acp-metadata.json 2>/dev/null || \
  cargo metadata --format-version 1 > /tmp/acp-metadata.json
python3 scripts/sbom_build.py /tmp/acp-metadata.json > sbom.json
echo "wrote sbom.json ($(python3 -c 'import json,sys;print(len(json.load(open("sbom.json"))["components"]))') components)"
