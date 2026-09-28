#!/usr/bin/env bash
# CI gate: fail if the total number of passing tests drops below the recorded baseline. Consolidation
# once silently dropped ~50 integration tests; this makes any future drop a hard build failure.
# Update scripts/test-count.baseline deliberately (and in review) when you legitimately add/remove tests.
set -uo pipefail
cd "$(dirname "$0")/.."
BASELINE_FILE="scripts/test-count.baseline"
BASELINE=$(cat "$BASELINE_FILE" 2>/dev/null || echo 0)
# Count passing tests across the workspace (default features). --features runs are additional and not
# counted here so the gate is deterministic without optional backends.
OUT=$(cargo test --workspace 2>&1)
COUNT=$(printf '%s\n' "$OUT" | grep -oE 'test result: ok\. [0-9]+ passed' | awk '{s+=$4} END{print s+0}')
echo "passing tests: $COUNT (baseline $BASELINE)"
if [ "$COUNT" -lt "$BASELINE" ]; then
  echo "FAIL: test count dropped from $BASELINE to $COUNT. Tests were removed or are not running." >&2
  echo "If this is intentional, lower $BASELINE_FILE in the same change." >&2
  exit 1
fi
if [ "$COUNT" -gt "$BASELINE" ]; then
  echo "note: test count rose above baseline; consider bumping $BASELINE_FILE to $COUNT to ratchet."
fi
echo "OK: test count gate passed."
