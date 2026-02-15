#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
TARGET_FILE="${1:-scripts/interop/bogo_expected_failures_v1_prod.txt}"

if [[ "${1:-}" == "--self-test" ]]; then
  SELF_TEST=1
fi

check_file() {
  local path="$1"
  [[ -f "$path" ]] || { echo "inventory file not found: $path" >&2; return 1; }

  # no empty lines/comments in canonical inventory
  if awk 'NF == 0 || $0 ~ /^#/' "$path" | grep -q .; then
    echo "inventory contains empty/comment lines: $path" >&2
    return 1
  fi

  if [[ "$(sort "$path" | uniq -d | wc -l | tr -d ' ')" != "0" ]]; then
    echo "inventory contains duplicate entries: $path" >&2
    return 1
  fi

  if ! diff -u "$path" <(sort "$path") >/dev/null; then
    echo "inventory is not lexicographically sorted: $path" >&2
    return 1
  fi
}

if [[ "$SELF_TEST" -eq 1 ]]; then
  tmp="$(mktemp /tmp/zigtls-expected-inv.XXXXXX)"
  trap 'rm -f "$tmp"' EXIT
  cat > "$tmp" <<'EOF'
A-case
B-case
C-case
EOF
  check_file "$tmp"
  echo "self-test: ok"
  exit 0
fi

check_file "$TARGET_FILE"
echo "expected-failure inventory check passed: $TARGET_FILE"
