#!/usr/bin/env bash
set -euo pipefail

# NSS interop harness entrypoint.
# Required env vars:
#   NSS_DIR: path to NSS build root containing dist/ directory
# Optional env vars:
#   NSS_BIN_DIR: override binary directory (default: $NSS_DIR/dist/Release/bin)
#   NSS_LIB_DIR: override lib directory (default: $NSS_DIR/dist/Release/lib)
#   NSS_DB_DIR: cert DB directory (default: temporary directory)
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

CERTUTIL="$NSS_BIN_DIR/certutil"
SELFSERV="$NSS_BIN_DIR/selfserv"
TSTCLNT="$NSS_BIN_DIR/tstclnt"

for tool in "$CERTUTIL" "$SELFSERV" "$TSTCLNT"; do
  if [[ ! -x "$tool" ]]; then
    echo "required NSS tool missing or not executable: $tool" >&2
    exit 1
  fi
done

if [[ "$NSS_CHECK_ONLY" == "1" ]]; then
  echo "nss interop environment check passed"
  exit 0
fi

WORKDIR="${NSS_DB_DIR:-$(mktemp -d)}"
CLEANUP_TMP=0
if [[ -z "${NSS_DB_DIR:-}" ]]; then
  CLEANUP_TMP=1
fi

cleanup() {
  if [[ "$CLEANUP_TMP" -eq 1 ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

mkdir -p "$WORKDIR"

if [[ ! -f "$WORKDIR/cert9.db" ]]; then
  "$CERTUTIL" -N -d sql:"$WORKDIR" --empty-password >/dev/null 2>&1
fi

# Sanity probe: verify NSS binaries can start and report usage/version.
# Full handshake wiring is intentionally deferred to target-environment integration.
"$SELFSERV" -h >/dev/null 2>&1 || {
  echo "selfserv command probe failed" >&2
  exit 1
}
"$TSTCLNT" -h >/dev/null 2>&1 || {
  echo "tstclnt command probe failed" >&2
  exit 1
}

echo "nss local harness check passed"
