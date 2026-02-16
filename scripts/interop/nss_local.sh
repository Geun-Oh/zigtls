#!/usr/bin/env bash
set -euo pipefail

# Direct NSS tstclnt <-> zigtls TLS1.3 handshake check.
# Required env vars:
#   NSS_DIR: path to NSS root
# Optional env vars:
#   NSS_BIN_DIR: override binary directory (default: $NSS_DIR/dist/Release/bin)
#   NSS_LIB_DIR: override lib directory (default: $NSS_DIR/dist/Release/lib)
#   NSS_CHECK_ONLY: if 1, only validate tool availability (default: 0)

: "${NSS_DIR:?NSS_DIR is required}"

NSS_BIN_DIR="${NSS_BIN_DIR:-$NSS_DIR/dist/Release/bin}"
NSS_LIB_DIR="${NSS_LIB_DIR:-$NSS_DIR/dist/Release/lib}"
NSS_CHECK_ONLY="${NSS_CHECK_ONLY:-0}"

if [[ ! -d "$NSS_BIN_DIR" ]]; then
  echo "NSS bin directory not found: $NSS_BIN_DIR" >&2
  exit 1
fi
if [[ ! -d "$NSS_LIB_DIR" ]]; then
  echo "NSS lib directory not found: $NSS_LIB_DIR" >&2
  exit 1
fi

TSTCLNT="$NSS_BIN_DIR/tstclnt"
if [[ ! -x "$TSTCLNT" ]]; then
  echo "required NSS tool missing or not executable: $TSTCLNT" >&2
  exit 1
fi

if [[ "$NSS_CHECK_ONLY" == "1" ]]; then
  echo "nss interop environment check passed"
  exit 0
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
    p=$((28000 + (RANDOM % 20000)))
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
  --host 127.0.0.1 \
  --port "$PORT" \
  --cert "$CERT" \
  --key "$KEY" \
  --sni 127.0.0.1 \
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

export DYLD_LIBRARY_PATH="$NSS_LIB_DIR:${DYLD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$NSS_LIB_DIR:${LD_LIBRARY_PATH:-}"

set +e
"$TSTCLNT" \
  -h 127.0.0.1 \
  -p "$PORT" \
  -D \
  -o \
  -V tls1.3:tls1.3 \
  -q \
  -t 5 \
  >/dev/null 2>&1
CLIENT_STATUS=$?
set -e

SERVER_STATUS=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
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

if [[ $CLIENT_STATUS -ne 0 ]]; then
  echo "nss tstclnt->zigtls interop failed" >&2
  tail -n 80 "$SERVER_LOG" >&2 || true
  exit 1
fi

if [[ $SERVER_STATUS -ne 0 ]]; then
  echo "zigtls interop server exited non-zero: $SERVER_STATUS" >&2
  tail -n 80 "$SERVER_LOG" >&2 || true
  exit 1
fi

echo "nss direct zigtls TLS check passed"
