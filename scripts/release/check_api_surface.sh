#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
REFRESH=0
ROOT_FILE="src/root.zig"
BASELINE_FILE="docs/api-surface-baseline.txt"

usage() {
  cat <<USAGE
usage: check_api_surface.sh [--self-test] [--refresh]

Options:
  --self-test   Run internal self-test
  --refresh     Update baseline snapshot from current root exports
USAGE
}

extract_surface() {
  local source="$1"
  awk '/^pub const /{ sub(/;.*/, ""); print } /^pub fn /{ sub(/\{.*/, ""); print }' "$source"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  cat >"$tmp/root.zig" <<'S'
pub const a = @import("a.zig");
pub fn version() []const u8 {
    return "x";
}
const hidden = 1;
S
  local out
  out="$(extract_surface "$tmp/root.zig")"
  if ! grep -q "pub const a = @import(\"a.zig\")" <<<"$out"; then
    echo "self-test failed: const missing" >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! grep -q "pub fn version() \[]const u8" <<<"$out"; then
    echo "self-test failed: fn missing" >&2
    rm -rf "$tmp"
    return 1
  fi
  if grep -q "hidden" <<<"$out"; then
    echo "self-test failed: hidden symbol leaked" >&2
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$tmp"
  echo "self-test: ok"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test)
      SELF_TEST=1
      shift
      ;;
    --refresh)
      REFRESH=1
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

if [[ ! -f "$ROOT_FILE" ]]; then
  echo "missing root file: $ROOT_FILE" >&2
  exit 1
fi

current="$(extract_surface "$ROOT_FILE")"

if [[ "$REFRESH" -eq 1 ]]; then
  printf '%s\n' "$current" >"$BASELINE_FILE"
  echo "refreshed baseline: $BASELINE_FILE"
  exit 0
fi

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "missing baseline file: $BASELINE_FILE" >&2
  echo "run with --refresh to create baseline" >&2
  exit 1
fi

baseline="$(cat "$BASELINE_FILE")"
if [[ "$baseline" != "$current" ]]; then
  echo "api surface drift detected" >&2
  diff -u <(printf '%s\n' "$baseline") <(printf '%s\n' "$current") || true
  echo "if intended, update baseline: bash scripts/release/check_api_surface.sh --refresh" >&2
  exit 1
fi

echo "api surface check passed"
