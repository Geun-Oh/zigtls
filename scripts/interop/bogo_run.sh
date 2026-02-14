#!/usr/bin/env bash
set -euo pipefail

# Run BoringSSL BoGo runner with zigtls shim.
# Required env vars:
#   BORINGSSL_DIR: path to boringssl checkout
# Optional env vars:
#   BOGO_FILTER: regex filter for test names
#   BOGO_OUTPUT: output json file (default: bogo-results.json)

: "${BORINGSSL_DIR:?BORINGSSL_DIR is required}"
BOGO_FILTER="${BOGO_FILTER:-}"
BOGO_OUTPUT="${BOGO_OUTPUT:-bogo-results.json}"

RUNNER="$BORINGSSL_DIR/ssl/test/runner"
if [[ ! -d "$RUNNER" ]]; then
  echo "runner directory not found: $RUNNER" >&2
  exit 1
fi

zig build bogo-shim
SHIM_BIN="./zig-out/bin/bogo-shim"
if [[ ! -x "$SHIM_BIN" ]]; then
  echo "shim binary not found: $SHIM_BIN" >&2
  exit 1
fi

pushd "$RUNNER" >/dev/null
set +e
if [[ -n "$BOGO_FILTER" ]]; then
  go test -v -run "${BOGO_FILTER}" ./... \
    -shim-path "$SHIM_BIN" -json-output "$BOGO_OUTPUT"
else
  go test -v ./... \
    -shim-path "$SHIM_BIN" -json-output "$BOGO_OUTPUT"
fi
STATUS=$?
set -e
popd >/dev/null

echo "BoGo runner exited with status: $STATUS"
echo "Results: $RUNNER/$BOGO_OUTPUT"
exit "$STATUS"
