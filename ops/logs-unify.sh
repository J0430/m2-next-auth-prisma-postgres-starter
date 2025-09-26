#!/usr/bin/env bash
set -euo pipefail

DAY=$(date -u +%F)
LOGROOT="logs/$DAY"
OUT="logs2.txt"

# Secret masking function
mask_secrets() {
  sed -E \
    -e 's#postgres://[A-Za-z0-9._:%@/-]+#postgres://***REDACTED***#g' \
    -e 's#(DATABASE_URL=)[^[:space:]]+#\1***REDACTED***#g' \
    -e 's#(NEON_[A-Z0-9_]*=)[^[:space:]]+#\1***REDACTED***#g' \
    -e 's#(Authorization: )[Bb]earer [^[:space:]]+#\1Bearer ***REDACTED***#g' \
    -e 's#([?&]apikey=)[^& ]+#\1***REDACTED***#g'
}

# Start fresh header
{
  echo "== Unified Logs $(date -u +%H:%M:%S)Z =="
  echo "Source: ${LOGROOT}"
} > "$OUT"

# Append each log with header and snippets
shopt -s nullglob
for f in "${LOGROOT}"/*.log; do
  [[ -f "$f" ]] || continue
  {
    echo
    echo "===== $(basename "$f") @ $(date -u +%H:%M:%S)Z ====="
    echo "--- head (first 120 lines) ---"
    sed -n '1,120p' "$f" | mask_secrets
    echo "--- tail (last 60 lines) ---"
    tail -n 60 "$f" | mask_secrets
  } >> "$OUT"
done

# Auto-summary
{
  echo
  echo "---- SUMMARY ----"
  grep -hE 'NODE_OK|PNPM_OK|NEXT_REMOTE_PATTERNS_OK|REQUIRED_FILES_OK|MERGE_CONFLICTS|TS_OK|ESLINT_OK|BUILD_OK|DEV_READY|SMOKE_OK' "${LOGROOT}"/*.log 2>/dev/null | sort | uniq
} >> "$OUT"

# Also write to daily unified log
cp "$OUT" "$LOGROOT/99-unified.log"

exit 0