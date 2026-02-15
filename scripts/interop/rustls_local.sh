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

pick_port() {
  local p
  local i
  for i in $(seq 1 50); do
    p=$((24000 + (RANDOM % 20000)))
    if ! command -v nc >/dev/null 2>&1; then
      echo "$p"
      return 0
    fi
    if ! nc -z 127.0.0.1 "$p" >/dev/null 2>&1; then
      echo "$p"
      return 0
    fi
  done
  echo "failed to select free port" >&2
  return 1
}

PORT=0
SERVER_PID=0

CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
LOG="$WORKDIR/server.log"

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

wait_for_listener() {
  if ! command -v nc >/dev/null 2>&1; then
    sleep 1
    return 0
  fi
  local attempts=50
  local i=0
  while [[ "$i" -lt "$attempts" ]]; do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      return 1
    fi
    if nc -z 127.0.0.1 "$PORT" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

start_server_once() {
  PORT="$(pick_port)"
  if [[ "$server_uses_modern_cli" -eq 1 ]]; then
    "$RUSTLS_SERVER" --certs "$CERT" --key "$KEY" --port "$PORT" http >"$LOG" 2>&1 &
  else
    "$RUSTLS_SERVER" --cert "$CERT" --key "$KEY" --port "$PORT" >"$LOG" 2>&1 &
  fi
  SERVER_PID=$!
  if wait_for_listener; then
    return 0
  fi
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  wait "$SERVER_PID" 2>/dev/null || true
  return 1
}

READY=0
for _ in 1 2 3; do
  if start_server_once; then
    READY=1
    break
  fi
  sleep 0.2
done

if [[ "$READY" -ne 1 ]]; then
  echo "rustls server did not become ready" >&2
  if [[ -f "$LOG" ]]; then
    tail -n 40 "$LOG" >&2 || true
  fi
  exit 1
fi

client_uses_modern_cli=0
if "$RUSTLS_CLIENT" --help 2>/dev/null | grep -q -- "Usage: tlsclient-mio"; then
  client_uses_modern_cli=1
fi

STATUS=1
for _ in 1 2 3; do
  set +e
  if [[ "$client_uses_modern_cli" -eq 1 ]]; then
    "$RUSTLS_CLIENT" --http --cafile "$CERT" --port "$PORT" localhost >/dev/null 2>&1
    STATUS=$?
  else
    "$RUSTLS_CLIENT" --cafile "$CERT" --hostname localhost --port "$PORT" 127.0.0.1 >/dev/null 2>&1
    STATUS=$?
  fi
  set -e
  [[ "$STATUS" -eq 0 ]] && break
  sleep 0.2
done

kill "$SERVER_PID" >/dev/null 2>&1 || true
wait "$SERVER_PID" 2>/dev/null || true

if [[ $STATUS -ne 0 ]]; then
  echo "rustls interop failed" >&2
  exit 1
fi

echo "rustls local TLS check passed"
