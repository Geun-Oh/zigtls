#!/usr/bin/env bash
set -euo pipefail

CORPUS_DIR="tests/fuzz/corpus"
SELF_TEST=0
RUN_BASELINE=1

usage() {
  cat <<USAGE
usage: replay_corpus.sh [--corpus <dir>] [--skip-baseline] [--self-test]

Options:
  --corpus <dir>     Corpus root directory (default: tests/fuzz/corpus)
  --skip-baseline    Skip baseline zig fuzz test invocation
  --self-test        Run internal script self-test
USAGE
}

run_replay() {
  local corpus_dir="$1"
  local run_baseline="$2"
  local record_count=0
  local handshake_count=0
  local session_count=0

  if [[ ! -d "$corpus_dir" ]]; then
    echo "corpus directory not found: $corpus_dir" >&2
    return 1
  fi

  if [[ "$run_baseline" == "1" ]]; then
    zig test src/tls13/fuzz.zig >/dev/null
  fi

  local replayed=0
  while IFS= read -r -d '' file; do
    local rel
    rel="${file#$corpus_dir/}"
    case "${rel%%/*}" in
      record) record_count=$((record_count + 1)) ;;
      handshake) handshake_count=$((handshake_count + 1)) ;;
      session) session_count=$((session_count + 1)) ;;
    esac
    # Placeholder replay hook: ensure corpus files are readable and tracked.
    # Target-specific harness execution can be wired here in follow-up commits.
    wc -c <"$file" >/dev/null
    replayed=$((replayed + 1))
  done < <(find "$corpus_dir" -type f -print0)

  if [[ "$replayed" -eq 0 ]]; then
    echo "no corpus files found under: $corpus_dir" >&2
    return 1
  fi

  if [[ "$record_count" -eq 0 || "$handshake_count" -eq 0 || "$session_count" -eq 0 ]]; then
    echo "missing required corpus buckets (record=$record_count handshake=$handshake_count session=$session_count)" >&2
    return 1
  fi

  echo "replayed corpus files: $replayed"
  echo "bucket counts: record=$record_count handshake=$handshake_count session=$session_count"
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  mkdir -p "$tmp/record"
  mkdir -p "$tmp/handshake"
  mkdir -p "$tmp/session"
  printf '\x16\x03\x04\x00\x00' >"$tmp/record/seed1.bin"
  printf '\x01\x00\x00' >"$tmp/handshake/seed1.bin"
  printf 'seed-case\n' >"$tmp/session/seed1.bin"

  run_replay "$tmp" 0 >/dev/null
  rm -rf "$tmp"
  echo "self-test: ok"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      CORPUS_DIR="$2"
      shift 2
      ;;
    --skip-baseline)
      RUN_BASELINE=0
      shift
      ;;
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

run_replay "$CORPUS_DIR" "$RUN_BASELINE"
