#!/usr/bin/env bash
set -euo pipefail

echo "== Smoke $(date -u +%H:%M:%S)Z =="

# Find available port
PORT=3000
while nc -z localhost $PORT 2>/dev/null; do
  echo " ⚠ Port $PORT is in use by process $(lsof -ti:$PORT), using available port $((PORT+1)) instead."
  PORT=$((PORT+1))
done

# Start dev server in background
echo "Starting dev server on port $PORT..."
pnpm -s dev --port $PORT > /dev/null 2>&1 &
DEV_PID=$!

# Wait for server to be ready
echo "Waiting for server to start..."
for i in {1..30}; do
  if curl -s http://localhost:$PORT > /dev/null 2>&1; then
    echo " ✓ Starting..."
    echo " ✓ Ready in ${i}00ms"
    break
  fi
  sleep 0.1
done

# Test the endpoint
echo "Testing / endpoint..."
if curl -s http://localhost:$PORT | grep -q "M2 Auth"; then
  echo "✓ Smoke OK"
  echo "SMOKE_OK: true"
  RESULT=0
else
  echo "❌ Smoke test failed"
  echo "SMOKE_OK: false"
  RESULT=1
fi

# Clean up
kill $DEV_PID 2>/dev/null || true
wait $DEV_PID 2>/dev/null || true

exit $RESULT
