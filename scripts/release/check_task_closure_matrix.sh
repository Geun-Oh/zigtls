#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
ROOT_OVERRIDE=""

usage() {
  cat <<USAGE
usage: check_task_closure_matrix.sh [--self-test] [--root <dir>]

Options:
  --self-test    Run internal self-test
  --root <dir>   Override repository root (default: auto-detect)
USAGE
}

extract_ws_ids() {
  local file="$1"
  grep -E '^## WS-[A-Z][\.: ]' "$file" \
    | sed -E 's/^## (WS-[A-Z]).*/\1/' \
    | awk '!seen[$0]++'
}

section_has_reference() {
  local file="$1"
  local ws="$2"
  awk -v ws="$ws" '
    BEGIN { in_ws = 0; found = 0 }
    $0 ~ "^## " ws"[.: ]" { in_ws = 1; next }
    in_ws && $0 ~ /^## / { exit }
    in_ws && $0 ~ /`[^`]+`/ { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

run_check() {
  local root="$1"
  local task_file="$root/_task.md"
  local closure_file="$root/docs/task-closure-matrix.md"
  local failed=0

  if [[ ! -f "$task_file" ]]; then
    echo "missing task definition: _task.md" >&2
    return 1
  fi
  if [[ ! -f "$closure_file" ]]; then
    echo "missing closure matrix: docs/task-closure-matrix.md" >&2
    return 1
  fi

  local task_ws
  task_ws="$(extract_ws_ids "$task_file")"
  local closure_ws
  closure_ws="$(extract_ws_ids "$closure_file")"

  while IFS= read -r ws; do
    [[ -n "$ws" ]] || continue
    if ! grep -qx "$ws" <<<"$closure_ws"; then
      echo "missing WS section in closure matrix: $ws" >&2
      failed=1
      continue
    fi
    if ! section_has_reference "$closure_file" "$ws"; then
      echo "WS section has no evidence references: $ws" >&2
      failed=1
    fi
  done <<<"$task_ws"

  while IFS= read -r ws; do
    [[ -n "$ws" ]] || continue
    if ! grep -qx "$ws" <<<"$task_ws"; then
      echo "unexpected WS section not present in _task.md: $ws" >&2
      failed=1
    fi
  done <<<"$closure_ws"

  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi

  echo "task closure matrix check passed"
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  local root="$tmp/repo"
  mkdir -p "$root/docs"

  cat > "$root/_task.md" <<'R'
# task

## WS-A. A title
## WS-B. B title
R

  cat > "$root/docs/task-closure-matrix.md" <<'R'
# closure

## WS-A A title
- `src/a.zig`
## WS-B B title
- `docs/b.md`
R

  run_check "$root" >/dev/null

  cat > "$root/docs/task-closure-matrix.md" <<'R'
# closure

## WS-A A title
- `src/a.zig`
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected missing WS section failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  cat > "$root/docs/task-closure-matrix.md" <<'R'
# closure

## WS-A A title
- `src/a.zig`
## WS-B B title
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected missing reference failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  cat > "$root/docs/task-closure-matrix.md" <<'R'
# closure

## WS-A A title
- `src/a.zig`
## WS-B B title
- `docs/b.md`
## WS-C extra title
- `docs/c.md`
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected unexpected WS section failure" >&2
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
    --root)
      [[ $# -ge 2 ]] || { echo "missing value for --root" >&2; exit 2; }
      ROOT_OVERRIDE="$2"
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

if [[ "$SELF_TEST" -eq 1 ]]; then
  self_test
  exit 0
fi

if [[ -n "$ROOT_OVERRIDE" ]]; then
  ROOT="$ROOT_OVERRIDE"
else
  ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fi

run_check "$ROOT"
