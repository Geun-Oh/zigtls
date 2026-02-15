#!/usr/bin/env bash
set -euo pipefail

# Generate reproducible interop evidence bundle with a single command.
# Default behavior executes strict matrix and stores logs/metadata/report.

SELF_TEST=0
OUT_ROOT=""
MATRIX_SCRIPT="$(cd "$(dirname "$0")" && pwd)/matrix_local.sh"

usage() {
  cat <<USAGE
usage: generate_evidence.sh [--self-test] [--out-root <dir>] [--matrix-script <path>]

Options:
  --self-test            Run internal bundle-generation self-test
  --out-root <dir>       Override output root (default: artifacts/interop)
  --matrix-script <path> Override matrix command (default: scripts/interop/matrix_local.sh)
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "required command not found: $cmd" >&2
    return 1
  fi
}

timestamp_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

collect_metadata() {
  local file="$1"
  {
    echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "host=$(uname -a)"
    echo "repo_root=$REPO_ROOT"
    echo "matrix_script=$MATRIX_SCRIPT"
    echo "zig_version=$(zig version 2>/dev/null || echo unknown)"
    echo "openssl_version=$(openssl version 2>/dev/null || echo unavailable)"
    echo "rustc_version=$(rustc --version 2>/dev/null || echo unavailable)"
    echo "nss_dir=${NSS_DIR:-unset}"
    echo "nss_bin_dir=${NSS_BIN_DIR:-unset}"
    echo "nss_lib_dir=${NSS_LIB_DIR:-unset}"
    echo "rustls_client=${RUSTLS_CLIENT:-unset}"
    echo "rustls_server=${RUSTLS_SERVER:-unset}"
  } >"$file"
}

write_report() {
  local bundle_dir="$1"
  local matrix_exit="$2"
  local report="$bundle_dir/report.md"
  local status="FAIL"
  if [[ "$matrix_exit" -eq 0 ]]; then
    status="PASS"
  fi

  cat >"$report" <<REPORT
# Interop Evidence Bundle

- Timestamp (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- Matrix status: $status
- Matrix exit code: $matrix_exit

## Files
- metadata: metadata.txt
- matrix output: matrix.log
- environment snapshot: env.txt
REPORT
}

run_bundle() {
  local root="$1"
  local stamp
  stamp="$(timestamp_utc)"
  local bundle_dir="$root/$stamp"

  mkdir -p "$bundle_dir"

  env | LC_ALL=C sort >"$bundle_dir/env.txt"
  collect_metadata "$bundle_dir/metadata.txt"

  local matrix_exit=0
  set +e
  "$MATRIX_SCRIPT" --strict >"$bundle_dir/matrix.log" 2>&1
  matrix_exit=$?
  set -e

  write_report "$bundle_dir" "$matrix_exit"

  echo "interop evidence bundle: $bundle_dir"
  if [[ "$matrix_exit" -eq 0 ]]; then
    echo "matrix strict status: PASS"
    return 0
  fi

  echo "matrix strict status: FAIL (exit=$matrix_exit)" >&2
  return "$matrix_exit"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"

  cat >"$tmp/fake_matrix_ok.sh" <<'S'
#!/usr/bin/env bash
set -euo pipefail
exit 0
S
  chmod +x "$tmp/fake_matrix_ok.sh"

  OUT_ROOT="$tmp/out"
  MATRIX_SCRIPT="$tmp/fake_matrix_ok.sh"
  set +e
  run_bundle "$OUT_ROOT" >/tmp/zigtls-evidence-selftest.log 2>&1
  local code=$?
  set -e

  if [[ "$code" -ne 0 ]]; then
    echo "self-test failed: expected success from fake matrix"
    rm -rf "$tmp"
    return 1
  fi

  local bundle
  bundle="$(find "$OUT_ROOT" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$bundle" ]]; then
    echo "self-test failed: bundle directory missing"
    rm -rf "$tmp"
    return 1
  fi

  for f in env.txt metadata.txt matrix.log report.md; do
    if [[ ! -f "$bundle/$f" ]]; then
      echo "self-test failed: missing bundle file $f"
      rm -rf "$tmp"
      return 1
    fi
  done

  if ! grep -q "Matrix status: PASS" "$bundle/report.md"; then
    echo "self-test failed: report did not record PASS"
    rm -rf "$tmp"
    return 1
  fi

  rm -rf "$tmp"
  echo "self-test: ok"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test)
      SELF_TEST=1
      shift
      ;;
    --out-root)
      [[ $# -ge 2 ]] || {
        echo "missing value for --out-root" >&2
        exit 2
      }
      OUT_ROOT="$2"
      shift 2
      ;;
    --matrix-script)
      [[ $# -ge 2 ]] || {
        echo "missing value for --matrix-script" >&2
        exit 2
      }
      MATRIX_SCRIPT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [[ "$SELF_TEST" -eq 1 ]]; then
  self_test
  exit 0
fi

if [[ ! -x "$MATRIX_SCRIPT" ]]; then
  echo "matrix script not executable: $MATRIX_SCRIPT" >&2
  exit 1
fi

if [[ -z "$OUT_ROOT" ]]; then
  OUT_ROOT="$REPO_ROOT/artifacts/interop"
fi

require_cmd date
require_cmd uname

mkdir -p "$OUT_ROOT"
run_bundle "$OUT_ROOT"
