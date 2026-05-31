#!/usr/bin/env bash
# Final gate: run the agent against the REAL server and verify the public URL
# serves a known body. Run this from your Mac after deploying the server.
#
# Required env:
#   CHUTE_SERVER       e.g. tunnel.example.com
#   CHUTE_TOKEN        the shared secret
#   CHUTE_SERVER_CERT  path to the pinned cert (PEM)
#   CHUTE_PUBLIC_URL   e.g. http://tunnel.example.com/
set -euo pipefail

: "${CHUTE_SERVER:?set CHUTE_SERVER}"
: "${CHUTE_TOKEN:?set CHUTE_TOKEN}"
: "${CHUTE_SERVER_CERT:?set CHUTE_SERVER_CERT}"
: "${CHUTE_PUBLIC_URL:?set CHUTE_PUBLIC_URL}"

PORT=8000
MARKER="chute-smoke-$$"
TMPDIR_LOCAL="$(mktemp -d)"
echo "$MARKER" > "$TMPDIR_LOCAL/index.html"

echo "==> starting local app on :$PORT"
( cd "$TMPDIR_LOCAL" && python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
APP_PID=$!

echo "==> starting chute agent"
chute "$PORT" &
AGENT_PID=$!

cleanup() { kill "$APP_PID" "$AGENT_PID" 2>/dev/null || true; rm -rf "$TMPDIR_LOCAL"; }
trap cleanup EXIT

echo "==> waiting for tunnel to come up"
sleep 4

echo "==> GET $CHUTE_PUBLIC_URL"
BODY="$(curl -fsS --max-time 10 "$CHUTE_PUBLIC_URL")"
if [[ "$BODY" == *"$MARKER"* ]]; then
  echo "PASS: tunnel served the expected body"
  exit 0
fi
echo "FAIL: got unexpected body:"; echo "$BODY"
exit 1
