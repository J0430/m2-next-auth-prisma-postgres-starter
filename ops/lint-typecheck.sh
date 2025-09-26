#!/usr/bin/env bash
set -euo pipefail

echo "== Lint+Typecheck $(date -u +%H:%M:%S)Z =="

# Run lint
echo "Running ESLint..."
if pnpm -s lint; then
  echo "✓ ESLint OK"
  echo "ESLINT_OK: true"
else
  echo "❌ ESLint failed"
  echo "ESLINT_OK: false"
  exit 1
fi

# Run typecheck
echo "Running TypeScript check..."
if pnpm -s typecheck; then
  echo "✓ TypeScript OK"
  echo "TS_OK: true"
else
  echo "❌ TypeScript failed"
  echo "TS_OK: false"
  exit 1
fi
