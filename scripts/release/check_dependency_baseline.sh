#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
BASELINE_FILE="docs/dependency-baseline.md"

usage() {
  cat <<USAGE
usage: check_dependency_baseline.sh [--self-test]
USAGE
}

get_baseline() {
  local key="$1"
  awk -v k="$key" '$1 == "-" && $2 == k":" {print $3}' "$BASELINE_FILE"
}

check_prefix() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  if [[ "$actual" != "$expected"* ]]; then
    echo "dependency baseline mismatch: $name expected_prefix=$expected actual=$actual" >&2
    return 1
  fi
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  cat >"$tmp/base.md" <<'B'
- zig: 1.2.3
- python3: 3.13
B
  BASELINE_FILE="$tmp/base.md"
  if [[ "$(get_baseline zig)" != "1.2.3" ]]; then
    echo "self-test failed: zig parse" >&2
    rm -rf "$tmp"
    return 1
  fi
  if [[ "$(get_baseline python3)" != "3.13" ]]; then
    echo "self-test failed: python parse" >&2
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

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "missing baseline file: $BASELINE_FILE" >&2
  exit 1
fi

zig_expected="$(get_baseline zig)"
python_expected="$(get_baseline python3)"
openssl_expected="$(get_baseline openssl)"

[[ -n "$zig_expected" ]] || { echo "missing zig baseline" >&2; exit 1; }
[[ -n "$python_expected" ]] || { echo "missing python3 baseline" >&2; exit 1; }
[[ -n "$openssl_expected" ]] || { echo "missing openssl baseline" >&2; exit 1; }

zig_actual="$(zig version)"
python_actual="$(python3 --version | awk '{print $2}')"
openssl_actual="$(openssl version | awk '{print $2}')"

check_prefix "zig" "$zig_expected" "$zig_actual"
check_prefix "python3" "$python_expected" "$python_actual"
check_prefix "openssl" "$openssl_expected" "$openssl_actual"

echo "dependency baseline check passed"
