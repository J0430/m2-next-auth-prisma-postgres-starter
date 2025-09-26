#!/usr/bin/env bash
set -euo pipefail

echo "== Dry-run Merge $(date -u +%H:%M:%S)Z =="

# Fetch latest
git fetch --all --prune

# Get merge base
MERGE_BASE=$(git merge-base origin/main HEAD)

# Use git merge-tree to check for conflicts
MERGE_OUTPUT=$(git merge-tree "$MERGE_BASE" HEAD origin/main 2>&1 || true)

# Check for conflict markers
if echo "$MERGE_OUTPUT" | grep -qE "<<<<<<<|>>>>>>>|CONFLICT|added in both"; then
  echo "❌ Merge conflicts detected:"
  echo "$MERGE_OUTPUT"
  echo "MERGE_CONFLICTS: true"
  exit 1
fi

echo "✓ No merge conflicts"
echo "MERGE_CONFLICTS: false"