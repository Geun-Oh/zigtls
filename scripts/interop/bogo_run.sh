#!/usr/bin/env bash
set -euo pipefail

# Run BoringSSL BoGo runner with zigtls shim.
# Required env vars:
#   BORINGSSL_DIR: path to boringssl checkout
# Optional env vars:
#   BOGO_FILTER: regex filter for test names
#   BOGO_OUTPUT: output json file (default: bogo-results.json)
#   BOGO_MAX_CRITICAL: maximum allowed critical failures in summary (default: 0)
#   BOGO_ALLOW_UNIMPLEMENTED: pass -allow-unimplemented to runner (default: 1)

: "${BORINGSSL_DIR:?BORINGSSL_DIR is required}"
BOGO_FILTER="${BOGO_FILTER:-}"
BOGO_OUTPUT="${BOGO_OUTPUT:-bogo-results.json}"
BOGO_MAX_CRITICAL="${BOGO_MAX_CRITICAL:-0}"
BOGO_ALLOW_UNIMPLEMENTED="${BOGO_ALLOW_UNIMPLEMENTED:-1}"

RUNNER="$BORINGSSL_DIR/ssl/test/runner"
if [[ ! -d "$RUNNER" ]]; then
  echo "runner directory not found: $RUNNER" >&2
  exit 1
fi

# Build and install artifacts so shim path is fresh.
zig build bogo-shim
zig build
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHIM_BIN="$REPO_ROOT/zig-out/bin/bogo-shim"
if [[ ! -x "$SHIM_BIN" ]]; then
  echo "shim binary not found after build/install: $SHIM_BIN" >&2
  exit 1
fi

pushd "$RUNNER" >/dev/null
set +e
RUNNER_FLAGS=()
RUNNER_FLAGS+=("-pipe")
if [[ "$BOGO_ALLOW_UNIMPLEMENTED" == "1" ]]; then
  RUNNER_FLAGS+=("-allow-unimplemented")
fi
if [[ -n "$BOGO_FILTER" ]]; then
  go test -v -run "${BOGO_FILTER}" . "${RUNNER_FLAGS[@]}" \
    -shim-path "$SHIM_BIN" -json-output "$BOGO_OUTPUT"
else
  go test -v . "${RUNNER_FLAGS[@]}" \
    -shim-path "$SHIM_BIN" -json-output "$BOGO_OUTPUT"
fi
STATUS=$?
set -e
popd >/dev/null

echo "BoGo runner exited with status: $STATUS"
echo "Results: $RUNNER/$BOGO_OUTPUT"

if [[ -f "$RUNNER/$BOGO_OUTPUT" ]]; then
  echo "BoGo summary:"
  if ! python3 "$(dirname "$0")/bogo_summary.py" --max-critical "$BOGO_MAX_CRITICAL" "$RUNNER/$BOGO_OUTPUT"; then
    echo "warning: failed to summarize BoGo output" >&2
    exit 1
  fi
fi

exit "$STATUS"
