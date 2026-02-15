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

pick_port() {
  local p
  local i
  for i in $(seq 1 50); do
    p=$((20000 + (RANDOM % 20000)))
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

CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
LOG="$WORKDIR/server.log"

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -keyout "$KEY" -out "$CERT" -days 1 >/dev/null 2>&1

PORT=0
SERVER_PID=0

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
  openssl s_server -tls1_3 -accept "$PORT" -cert "$CERT" -key "$KEY" -quiet >"$LOG" 2>&1 &
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
  echo "openssl server did not become ready" >&2
  if [[ -f "$LOG" ]]; then
    tail -n 40 "$LOG" >&2 || true
  fi
  exit 1
fi

STATUS=1
OUTPUT=""
for _ in 1 2 3; do
  set +e
  OUTPUT="$(echo "ping" | openssl s_client -connect "127.0.0.1:${PORT}" -tls1_3 -servername localhost 2>/dev/null)"
  STATUS=$?
  set -e
  [[ "$STATUS" -eq 0 ]] && break
  sleep 0.2
done

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
