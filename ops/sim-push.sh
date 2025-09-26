#!/usr/bin/env bash
set -euo pipefail

# Sim-Push: Full rehearsal of preflight → merge → lint+typecheck → build → smoke → logs-unify
# This simulates a push to main without actually committing or pushing

DAY=$(date -u +%F)
LOGROOT="logs/$DAY"
mkdir -p "$LOGROOT"

echo "== SIM-PUSH 2025-09-26T$(date -u +%H:%M:%S)Z =="

# Preflight check
echo ">> SIM-PUSH: preflight $(date -u +%H:%M:%S)Z"
if ! bash ops/preflight.sh > "$LOGROOT/01-preflight.log" 2>&1; then
  echo "❌ SIM-PUSH FAILED: preflight"
  exit 1
fi
echo "✓ Preflight PASS"

# Dry-run merge
echo ">> SIM-PUSH: dryrun merge $(date -u +%H:%M:%S)Z"
if ! bash ops/dryrun-merge.sh > "$LOGROOT/02-merge.log" 2>&1; then
  echo "❌ SIM-PUSH FAILED: merge conflicts"
  exit 1
fi
echo "✓ Merge PASS"

# Lint + Typecheck
echo ">> SIM-PUSH: lint+typecheck $(date -u +%H:%M:%S)Z"
if ! bash ops/lint-typecheck.sh > "$LOGROOT/03-lint-typecheck.log" 2>&1; then
  echo "❌ SIM-PUSH FAILED: lint/typecheck"
  exit 1
fi
echo "✓ Lint+Typecheck PASS"

# Install + Build
echo ">> SIM-PUSH: install + build $(date -u +%H:%M:%S)Z"
if ! bash ops/install-build.sh > "$LOGROOT/04-build-install.log" 2>&1; then
  echo "❌ SIM-PUSH FAILED: build"
  exit 1
fi
echo "✓ Build PASS"

# Smoke test
echo ">> SIM-PUSH: smoke $(date -u +%H:%M:%S)Z"
if ! bash ops/smoke.sh > "$LOGROOT/05-smoke.log" 2>&1; then
  echo "❌ SIM-PUSH FAILED: smoke test"
  exit 1
fi
echo "✓ Smoke PASS"

# Unify logs
echo ">> SIM-PUSH: unify logs $(date -u +%H:%M:%S)Z"
bash ops/logs-unify.sh > "$LOGROOT/06-unify.log" 2>&1 || true

echo "✓ SIM-PUSH completed (non-blocking)"