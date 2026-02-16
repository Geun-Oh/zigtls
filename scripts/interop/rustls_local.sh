#!/usr/bin/env bash
set -euo pipefail

# Direct rustls client <-> zigtls TLS1.3 handshake check.
# Required env vars:
#   RUSTLS_CLIENT: rustls client binary path

: "${RUSTLS_CLIENT:?RUSTLS_CLIENT is required}"
if [[ ! -x "$RUSTLS_CLIENT" ]]; then
  echo "RUSTLS_CLIENT is not executable: $RUSTLS_CLIENT" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INTEROP_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "${ZIGTLS_SKIP_LOCAL_CHECK:-0}" != "1" ]]; then
  bash "$INTEROP_DIR/zigtls_local.sh"
fi

WORKDIR="$(mktemp -d)"
cleanup() {
  if [[ "${ZIGTLS_INTEROP_KEEP_TMP:-0}" == "1" ]]; then
    echo "keeping interop tmp: $WORKDIR" >&2
    return
  fi
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

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl required to generate temporary certs" >&2
  exit 1
fi

CERT="$WORKDIR/cert.pem"
KEY="$WORKDIR/key.pem"
SERVER_LOG="$WORKDIR/zigtls-server.log"
RUSTLS_LOG="$WORKDIR/rustls-client.log"

openssl req -x509 -newkey ed25519 -nodes \
  -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$KEY" -out "$CERT" -days 1 >/dev/null 2>&1

(
  cd "$REPO_ROOT"
  zig build interop-termination-server --cache-dir .zig-cache --global-cache-dir .zig-global-cache >/dev/null
)
SERVER_BIN="$REPO_ROOT/zig-out/bin/interop-termination-server"
if [[ ! -x "$SERVER_BIN" ]]; then
  echo "zigtls interop server binary missing: $SERVER_BIN" >&2
  exit 1
fi

PORT="$(pick_port)"
"$SERVER_BIN" \
  --host ::1 \
  --port "$PORT" \
  --cert "$CERT" \
  --key "$KEY" \
  --sni localhost \
  --alpn h2 \
  --timeout-ms 10000 \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

wait_for_listener() {
  local attempts=60
  local i=0
  while [[ "$i" -lt "$attempts" ]]; do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      return 1
    fi
    # Avoid active TCP probes (e.g., nc -z) because this server accepts a
    # single connection for the handshake and probe connections consume it.
    sleep 0.05
    i=$((i + 1))
  done
  return 0
}

if ! wait_for_listener; then
  echo "zigtls interop server did not become ready" >&2
  tail -n 80 "$SERVER_LOG" >&2 || true
  exit 1
fi

client_uses_modern_cli=0
if "$RUSTLS_CLIENT" --help 2>/dev/null | grep -q -- "Usage: tlsclient-mio"; then
  client_uses_modern_cli=1
fi

STATUS=1
if [[ "$client_uses_modern_cli" -eq 1 ]]; then
  set +e
  "$RUSTLS_CLIENT" --proto h2 --cafile "$CERT" --port "$PORT" localhost </dev/null >"$RUSTLS_LOG" 2>&1
  STATUS=$?
  if [[ "$STATUS" -ne 0 ]]; then
    "$RUSTLS_CLIENT" --http --proto h2 --cafile "$CERT" --port "$PORT" localhost </dev/null >"$RUSTLS_LOG" 2>&1
    STATUS=$?
  fi
  set -e
else
  set +e
  "$RUSTLS_CLIENT" --cafile "$CERT" --hostname localhost --port "$PORT" 127.0.0.1 </dev/null >"$RUSTLS_LOG" 2>&1
  STATUS=$?
  set -e
fi

SERVER_STATUS=0
for _ in $(seq 1 120); do
  if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    wait "$SERVER_PID" || SERVER_STATUS=$?
    break
  fi
  sleep 0.1
done
if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
  kill "$SERVER_PID" >/dev/null 2>&1 || true
  wait "$SERVER_PID" || SERVER_STATUS=$?
fi

# rustls example client may panic with Broken pipe after a successful handshake
# if the peer closes immediately without application-data exchange.
if [[ $STATUS -ne 0 && $SERVER_STATUS -eq 0 && -s "$RUSTLS_LOG" ]] && grep -q "Broken pipe" "$RUSTLS_LOG"; then
  STATUS=0
fi

if [[ $STATUS -ne 0 ]]; then
  echo "rustls->zigtls interop failed" >&2
  if [[ -s "$RUSTLS_LOG" ]]; then
    echo "--- rustls client log ---" >&2
    cat "$RUSTLS_LOG" >&2
  fi
  tail -n 80 "$SERVER_LOG" >&2 || true
  exit 1
fi

if [[ $SERVER_STATUS -ne 0 ]]; then
  echo "zigtls interop server exited non-zero: $SERVER_STATUS" >&2
  tail -n 80 "$SERVER_LOG" >&2 || true
  exit 1
fi

echo "rustls direct zigtls TLS check passed"
