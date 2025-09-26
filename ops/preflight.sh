#!/usr/bin/env bash
set -euo pipefail

echo "== Preflight $(date -u +%H:%M:%S)Z =="

# Check Node version
NODE_VERSION=$(node -v | sed 's/v//')
if [[ $(echo "$NODE_VERSION" | cut -d. -f1) -lt 18 ]]; then
  echo "❌ Node version $NODE_VERSION < 18"
  exit 1
fi
echo "✓ Node $NODE_VERSION OK"

# Check PNPM version
PNPM_VERSION=$(pnpm -v)
if [[ $(echo "$PNPM_VERSION" | cut -d. -f1) -lt 9 ]]; then
  echo "❌ PNPM version $PNPM_VERSION < 9"
  exit 1
fi
echo "✓ PNPM $PNPM_VERSION OK"

# Check required files
REQUIRED_FILES=(
  "package.json"
  "next.config.ts"
  "src/lib/prisma.ts"
  "prisma/schema.prisma"
)

for file in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "❌ Missing required file: $file"
    exit 1
  fi
done
echo "✓ Required files present"

# Check Next.js config has remotePatterns
if ! grep -q "remotePatterns" next.config.ts; then
  echo "❌ next.config.ts missing remotePatterns"
  exit 1
fi
echo "✓ Next.js config OK"

echo "NODE_OK: true"
echo "PNPM_OK: true"
echo "REQUIRED_FILES_OK: true"
echo "NEXT_REMOTE_PATTERNS_OK: true"
