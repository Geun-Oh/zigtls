#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
INTEROP_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
  cat <<USAGE
usage: matrix_local.sh [--self-test]

Options:
  --self-test    Run internal harness self-test
USAGE
}

run_target() {
  local name="$1"
  local script="$2"
  local code=0

  if [[ ! -x "$script" ]]; then
    echo "[interop] $name: missing executable script ($script)"
    return 2
  fi

  if "$script"; then
    code=0;
  else
    code=$?;
  fi

  if [[ "$code" -eq 0 ]]; then
    echo "[interop] $name: PASS"
    return 0
  fi

  echo "[interop] $name: FAIL (exit=$code)"
  return "$code"
}

run_matrix() {
  local openssl_script="$1"
  local rustls_script="$2"
  local nss_script="$3"

  local failures=0

  run_target "openssl" "$openssl_script" || failures=$((failures + 1))
  run_target "rustls" "$rustls_script" || failures=$((failures + 1))
  run_target "nss" "$nss_script" || failures=$((failures + 1))

  if [[ "$failures" -eq 0 ]]; then
    echo "[interop] summary: PASS (3/3)"
    return 0
  fi

  echo "[interop] summary: FAIL ($failures failures)"
  return 1
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"

  cat <<'S' >"$tmp/ok.sh"
#!/usr/bin/env bash
exit 0
S
  cat <<'S' >"$tmp/fail.sh"
#!/usr/bin/env bash
exit 7
S
  chmod +x "$tmp/ok.sh" "$tmp/fail.sh"

  set +e
  run_matrix "$tmp/ok.sh" "$tmp/fail.sh" "$tmp/ok.sh" >/dev/null
  local code_fail=$?
  run_matrix "$tmp/ok.sh" "$tmp/missing.sh" "$tmp/ok.sh" >/dev/null
  local code_missing=$?
  set -e
  rm -rf "$tmp"

  if [[ "$code_fail" -ne 1 ]]; then
    echo "self-test failed: expected matrix failure exit code 1 for failing target"
    return 1
  fi

  if [[ "$code_missing" -ne 1 ]]; then
    echo "self-test failed: expected matrix failure exit code 1 for missing target"
    return 1
  fi

  echo "self-test: ok"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test)
      SELF_TEST=1
      shift
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

if [[ "$SELF_TEST" -eq 1 ]]; then
  self_test
  exit 0
fi

run_matrix \
  "$INTEROP_DIR/openssl_local.sh" \
  "$INTEROP_DIR/rustls_local.sh" \
  "$INTEROP_DIR/nss_local.sh"
