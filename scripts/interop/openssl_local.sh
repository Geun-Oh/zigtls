#!/usr/bin/env bash
set -euo pipefail

# Local OpenSSL TLS1.3 loopback check.
# Requires: openssl command available on PATH.

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
LOG="$WORKDIR/server.log"

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -keyout "$KEY" -out "$CERT" -days 1 >/dev/null 2>&1

openssl s_server -tls1_3 -accept 8443 -cert "$CERT" -key "$KEY" -quiet >"$LOG" 2>&1 &
SERVER_PID=$!

sleep 1
set +e
OUTPUT="$(echo "ping" | openssl s_client -connect 127.0.0.1:8443 -tls1_3 -servername localhost 2>/dev/null)"
STATUS=$?
set -e

kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" 2>/dev/null || true

if [[ $STATUS -ne 0 ]]; then
  echo "openssl interop failed" >&2
  exit 1
fi

if ! grep -q "TLSv1.3" <<<"$OUTPUT"; then
  echo "openssl interop did not negotiate TLSv1.3" >&2
  exit 1
fi

echo "openssl local TLS1.3 check passed"
