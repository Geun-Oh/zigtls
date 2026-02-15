#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
ASSERT_MODE=0
ITERATIONS="${TIMING_ITERATIONS:-12000}"
WARMUP="${TIMING_WARMUP:-1200}"
MAX_GAP_RATIO="${TIMING_MAX_GAP_RATIO:-0.35}"
ASSERT_ATTEMPTS="${TIMING_ASSERT_ATTEMPTS:-3}"
ASSERT_REQUIRED_PASSES="${TIMING_ASSERT_REQUIRED_PASSES:-1}"

usage() {
  cat <<USAGE
usage: run_timing_harness.sh [--self-test] [--assert] [--iterations <n>] [--warmup <n>]

Options:
  --self-test         Run parser/assertion self-test
  --assert            Fail if any suite absolute mean gap ratio exceeds threshold
  --iterations <n>    Probe iterations per case (default: TIMING_ITERATIONS or 12000)
  --warmup <n>        Warmup iterations per case (default: TIMING_WARMUP or 1200)

Environment:
  TIMING_MAX_GAP_RATIO   Assertion threshold (default: 0.35)
  TIMING_ASSERT_ATTEMPTS Assertion attempts for --assert majority vote (default: 3)
  TIMING_ASSERT_REQUIRED_PASSES Required passing attempts for --assert (default: 1)
USAGE
}

extract_gap_rows() {
  awk '
    /gap_ratio_abs=/ {
      suite=""; gap="";
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^suite=/) {
          suite = substr($i, 7);
        } else if ($i ~ /^gap_ratio_abs=/) {
          gap = substr($i, 15);
        }
      }
      if (suite != "" && gap != "") {
        print suite " " gap;
      }
    }
  '
}

assert_gap_threshold() {
  local output="$1"
  local failed=0
  while IFS=' ' read -r suite gap; do
    [[ -z "$suite" ]] && continue
    awk -v suite="$suite" -v gap="$gap" -v max="$MAX_GAP_RATIO" '
      BEGIN {
        if (gap > max) {
          printf "[timing][assert] FAIL suite=%s gap_ratio_abs=%s threshold=%s\n", suite, gap, max;
          exit 1;
        }
      }
    ' || failed=1
  done < <(printf '%s\n' "$output" | extract_gap_rows)

  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi

  echo "[timing][assert] PASSED threshold=${MAX_GAP_RATIO}"
  return 0
}

assert_with_retries() {
  local probe_bin="$1"
  local need="$ASSERT_REQUIRED_PASSES"
  local pass_count=0
  local fail_count=0
  local i
  for (( i=1; i<=ASSERT_ATTEMPTS; i++ )); do
    echo "[timing][assert] attempt=${i}/${ASSERT_ATTEMPTS}"
    local output
    output="$($probe_bin --iterations "$ITERATIONS" --warmup "$WARMUP")"
    printf '%s\n' "$output"
    if assert_gap_threshold "$output"; then
      pass_count=$((pass_count + 1))
    else
      fail_count=$((fail_count + 1))
    fi
  done

  if (( pass_count >= need )); then
    echo "[timing][assert] consensus PASS pass=${pass_count} fail=${fail_count} need=${need}"
    return 0
  fi
  echo "[timing][assert] consensus FAIL pass=${pass_count} fail=${fail_count} need=${need}" >&2
  return 1
}

self_test() {
  local sample
  sample=$'suite=TLS_AES_128_GCM_SHA256 gap_ratio_abs=0.120000 mean_delta_ns=1.2\n'
  sample+=$'suite=TLS_AES_256_GCM_SHA384 gap_ratio_abs=0.480000 mean_delta_ns=4.8\n'

  local rows
  rows="$(printf '%s\n' "$sample" | extract_gap_rows)"
  if [[ "$(printf '%s\n' "$rows" | wc -l | tr -d ' ')" != "2" ]]; then
    echo "self-test failed: expected two parsed gap rows" >&2
    return 1
  fi

  local old_threshold="$MAX_GAP_RATIO"
  MAX_GAP_RATIO="0.50"
  assert_gap_threshold "$sample"

  MAX_GAP_RATIO="0.30"
  if assert_gap_threshold "$sample"; then
    echo "self-test failed: assert should fail when threshold is strict" >&2
    MAX_GAP_RATIO="$old_threshold"
    return 1
  fi

  MAX_GAP_RATIO="$old_threshold"
  echo "self-test: ok"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --self-test)
      SELF_TEST=1
      shift
      ;;
    --assert)
      ASSERT_MODE=1
      shift
      ;;
    --iterations)
      [[ $# -ge 2 ]] || { echo "missing value for --iterations" >&2; exit 2; }
      ITERATIONS="$2"
      shift 2
      ;;
    --warmup)
      [[ $# -ge 2 ]] || { echo "missing value for --warmup" >&2; exit 2; }
      WARMUP="$2"
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

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

zig build timing-probe >/dev/null
PROBE_BIN="$REPO_ROOT/zig-out/bin/timing-probe"
if [[ ! -x "$PROBE_BIN" ]]; then
  echo "timing probe binary not found: $PROBE_BIN" >&2
  exit 1
fi

  if [[ "$ASSERT_MODE" -eq 1 ]]; then
  if ! [[ "$ASSERT_ATTEMPTS" =~ ^[0-9]+$ ]] || [[ "$ASSERT_ATTEMPTS" -lt 1 ]]; then
    echo "TIMING_ASSERT_ATTEMPTS must be a positive integer" >&2
    exit 2
  fi
  if ! [[ "$ASSERT_REQUIRED_PASSES" =~ ^[0-9]+$ ]] || [[ "$ASSERT_REQUIRED_PASSES" -lt 1 ]]; then
    echo "TIMING_ASSERT_REQUIRED_PASSES must be a positive integer" >&2
    exit 2
  fi
  if [[ "$ASSERT_REQUIRED_PASSES" -gt "$ASSERT_ATTEMPTS" ]]; then
    echo "TIMING_ASSERT_REQUIRED_PASSES cannot exceed TIMING_ASSERT_ATTEMPTS" >&2
    exit 2
  fi
  assert_with_retries "$PROBE_BIN"
else
  OUTPUT="$($PROBE_BIN --iterations "$ITERATIONS" --warmup "$WARMUP")"
  printf '%s\n' "$OUTPUT"
fi
