#!/usr/bin/env bash
# Assemble a compliance evidence pack from a live ACP ledger, dogfooding ACP's own GRC. This is the
# runtime-evidence half of a SOC 2 / EU AI Act / NIST / ISO 42001 audit pack: the tamper-evident
# proof of what the system actually did. Combine it with the control-and-policy pack from your SOC 2
# tooling (Vanta / Drata).
#   scripts/evidence-pack.sh <ledger.db> [out-dir]
set -euo pipefail
LEDGER="${1:?usage: evidence-pack.sh <ledger.db> [out-dir]}"
OUT="${2:-evidence-pack}"
CLI="./target/release/acp-cli"; [ -x "$CLI" ] || CLI="./target/debug/acp-cli"
mkdir -p "$OUT"

echo "== independent verification =="
"$CLI" verify "$LEDGER" | tee "$OUT/verification.txt"

echo "== framework-mapped evidence report (EU AI Act / NIST AI RMF / ISO 42001) =="
"$CLI" grc-report "$LEDGER" > "$OUT/grc-report.txt"

echo "== signed export pack (independently verifiable with the embedded public key) =="
"$CLI" export "$LEDGER" > "$OUT/evidence-pack.json"
"$CLI" verify-pack "$OUT/evidence-pack.json" >> "$OUT/verification.txt" 2>&1 || true

echo "== SIEM export (CEF) for the SOC =="
"$CLI" siem "$LEDGER" --format cef > "$OUT/decisions.cef" 2>/dev/null || true

cp docs/security/whitepaper.md "$OUT/security-whitepaper.md" 2>/dev/null || true
cat > "$OUT/README.txt" <<TXT
ACP compliance evidence pack
- verification.txt      : independent verification result (ledger + standalone pack, public key only)
- grc-report.txt        : EU AI Act / NIST AI RMF / ISO 42001 controls, each cited by real ledger records
- evidence-pack.json    : the signed, re-verifiable decision export
- decisions.cef         : SIEM (ArcSight CEF) stream of governed decisions
- security-whitepaper.md: the cryptographic and threat model reference
This is the runtime-evidence half of an audit pack; pair it with your SOC 2 control pack.
TXT
echo "== evidence pack written to $OUT/ =="
ls -1 "$OUT"
