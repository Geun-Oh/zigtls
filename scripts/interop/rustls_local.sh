#!/usr/bin/env bash
set -euo pipefail

# rustls interop harness entrypoint.
# This script expects rustls client/server binaries supplied by environment.
# Example:
#   RUSTLS_CLIENT=/path/to/rustls-client RUSTLS_SERVER=/path/to/rustls-server ./scripts/interop/rustls_local.sh

: "${RUSTLS_CLIENT:?RUSTLS_CLIENT is required}"
: "${RUSTLS_SERVER:?RUSTLS_SERVER is required}"

if [[ ! -x "$RUSTLS_CLIENT" ]]; then
  echo "RUSTLS_CLIENT is not executable: $RUSTLS_CLIENT" >&2
  exit 1
fi
if [[ ! -x "$RUSTLS_SERVER" ]]; then
  echo "RUSTLS_SERVER is not executable: $RUSTLS_SERVER" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl required to generate temporary certs" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$KEY" -out "$CERT" -days 1 >/dev/null 2>&1

server_uses_modern_cli=0
if "$RUSTLS_SERVER" --help 2>/dev/null | grep -q -- "--certs"; then
  server_uses_modern_cli=1
fi

if [[ "$server_uses_modern_cli" -eq 1 ]]; then
  "$RUSTLS_SERVER" --certs "$CERT" --key "$KEY" --port 8444 http >/dev/null 2>&1 &
else
  "$RUSTLS_SERVER" --cert "$CERT" --key "$KEY" --port 8444 >/dev/null 2>&1 &
fi
SERVER_PID=$!

sleep 1
client_uses_modern_cli=0
if "$RUSTLS_CLIENT" --help 2>/dev/null | grep -q -- "Usage: tlsclient-mio"; then
  client_uses_modern_cli=1
fi

set +e
if [[ "$client_uses_modern_cli" -eq 1 ]]; then
  "$RUSTLS_CLIENT" --http --cafile "$CERT" --port 8444 localhost >/dev/null 2>&1
  STATUS=$?
else
  "$RUSTLS_CLIENT" --cafile "$CERT" --hostname localhost --port 8444 127.0.0.1 >/dev/null 2>&1
  STATUS=$?
fi
set -e

kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" 2>/dev/null || true

if [[ $STATUS -ne 0 ]]; then
  echo "rustls interop failed" >&2
  exit 1
fi

echo "rustls local TLS check passed"
