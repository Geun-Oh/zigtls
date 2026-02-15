#!/usr/bin/env bash
set -euo pipefail

ASSERT_MODE=0

usage() {
  cat <<USAGE
usage: run_local_perf.sh [--assert]

Options:
  --assert    Enforce threshold checks and exit non-zero on regression
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --assert)
      ASSERT_MODE=1
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

# Conservative defaults; override with env vars per host class.
: "${PERF_MIN_MIB_AES128:=10}"
: "${PERF_MIN_MIB_AES256:=10}"
: "${PERF_MIN_MIB_CHACHA20:=5}"
: "${PERF_MAX_NS_PER_ITER_AES128:=200000}"
: "${PERF_MAX_NS_PER_ITER_AES256:=400000}"
: "${PERF_MAX_NS_PER_ITER_CHACHA20:=200000}"

float_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit (a + 0 >= b + 0) ? 0 : 1 }'
}

float_le() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit (a + 0 <= b + 0) ? 0 : 1 }'
}

extract_suite_field() {
  local output="$1"
  local suite="$2"
  local field="$3"
  local line
  line="$(grep -E "^suite=${suite} " <<<"$output" | head -n 1 || true)"
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  sed -E "s/.*${field}=([0-9.]+).*/\1/" <<<"$line"
}

zig build perf-probe
OUTPUT="$(./zig-out/bin/perf-probe)"
printf "%s\n" "$OUTPUT"

if [[ "$ASSERT_MODE" -eq 0 ]]; then
  exit 0
fi

failures=0

assert_suite() {
  local suite="$1"
  local min_mib="$2"
  local max_ns_iter="$3"

  local mib
  mib="$(extract_suite_field "$OUTPUT" "$suite" "app_throughput_mib_s")"
  local ns_iter
  ns_iter="$(extract_suite_field "$OUTPUT" "$suite" "handshake_ks_ns_per_iter")"

  if [[ -z "$mib" || -z "$ns_iter" ]]; then
    echo "[perf][assert] missing metrics for suite: $suite" >&2
    failures=$((failures + 1))
    return
  fi

  if ! float_ge "$mib" "$min_mib"; then
    echo "[perf][assert] throughput regression: suite=$suite got=${mib}MiB/s min=${min_mib}" >&2
    failures=$((failures + 1))
  fi

  if ! float_le "$ns_iter" "$max_ns_iter"; then
    echo "[perf][assert] latency regression: suite=$suite got=${ns_iter}ns max=${max_ns_iter}" >&2
    failures=$((failures + 1))
  fi
}

assert_suite "TLS_AES_128_GCM_SHA256" "$PERF_MIN_MIB_AES128" "$PERF_MAX_NS_PER_ITER_AES128"
assert_suite "TLS_AES_256_GCM_SHA384" "$PERF_MIN_MIB_AES256" "$PERF_MAX_NS_PER_ITER_AES256"
assert_suite "TLS_CHACHA20_POLY1305_SHA256" "$PERF_MIN_MIB_CHACHA20" "$PERF_MAX_NS_PER_ITER_CHACHA20"

memory_line="$(grep -E '^memory_ceiling_bytes ' <<<"$OUTPUT" | head -n 1 || true)"
if [[ -z "$memory_line" ]]; then
  echo "[perf][assert] missing memory_ceiling_bytes line" >&2
  failures=$((failures + 1))
else
  baseline="$(sed -E 's/.*baseline=([0-9]+).*/\1/' <<<"$memory_line")"
  early="$(sed -E 's/.*early_data_enabled=([0-9]+).*/\1/' <<<"$memory_line")"
  if [[ "$baseline" -le 0 || "$early" -le "$baseline" ]]; then
    echo "[perf][assert] unexpected memory ceiling values: baseline=$baseline early_data_enabled=$early" >&2
    failures=$((failures + 1))
  fi
fi

if [[ "$failures" -ne 0 ]]; then
  echo "[perf][assert] FAILED ($failures checks)" >&2
  exit 1
fi

echo "[perf][assert] PASSED"
