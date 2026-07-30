#!/usr/bin/env bash
set -e

NODE=/home/sah/.nvm/versions/node/v22.23.1/bin/node
NPM=/home/sah/.nvm/versions/node/v22.23.1/bin/npm
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! docker ps --filter name=threatflow-pg16 --filter status=running -q | grep -q .; then
  echo "starting threatflow-pg16..."
  docker start threatflow-pg16
  sleep 2
fi

echo "starting API on :4173..."
"$NODE" "$ROOT/server/index.js" > /tmp/threatflow-api.log 2>&1 &
API_PID=$!

echo "starting frontend on :4400..."
(cd "$ROOT/frontend-v4" && "$NPM" start > /tmp/threatflow-frontend.log 2>&1) &
FRONTEND_PID=$!

echo "API pid $API_PID (log: /tmp/threatflow-api.log)"
echo "frontend pid $FRONTEND_PID (log: /tmp/threatflow-frontend.log)"

trap "kill $API_PID $FRONTEND_PID 2>/dev/null" INT TERM
wait
