#!/usr/bin/env bash
set -euo pipefail

echo "== Install $(date -u +%H:%M:%S)Z =="
echo "Environment variables loaded from .env"

# Install dependencies
pnpm install --no-frozen-lockfile

echo "== Build (prod-like) $(date -u +%H:%M:%S)Z =="
echo " ⚠ Linting is disabled."

# Clean build directory
rm -rf .next

# Build with telemetry disabled
if NEXT_TELEMETRY_DISABLED=1 pnpm -s build --no-lint; then
  echo "✓ Build OK"
  echo "BUILD_OK: true"
else
  echo "❌ Build failed"
  echo "BUILD_OK: false"
  exit 1
fi
