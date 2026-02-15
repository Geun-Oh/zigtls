#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
PROFILE="quick"
OUT_DIR=""
SOAK_HOURS="${SOAK_DURATION_HOURS:-24}"
SOAK_ITERATIONS="${SOAK_ITERATIONS:-}"

usage() {
  cat <<USAGE
usage: run_soak_chaos.sh [--self-test] [--profile <quick|prod>] [--out-dir <dir>]

Options:
  --self-test            Run internal self-test only
  --profile <name>       quick | prod (default: quick)
  --out-dir <dir>        Output directory (default: artifacts/reliability/<timestamp>)

Environment:
  SOAK_DURATION_HOURS    Target soak duration for report metadata (default: 24)
  SOAK_ITERATIONS        Number of soak loop iterations (default: quick=2, prod=6)
USAGE
}

timestamp_utc() {
  date -u +"%Y%m%dT%H%M%SZ"
}

run_cmd() {
  local name="$1"
  local cmd="$2"
  local log="$3"
  local code=0
  set +e
  eval "$cmd" >"$log" 2>&1
  code=$?
  set -e
  echo "$name|$code"
  return 0
}

render_report() {
  local report="$1"
  local profile="$2"
  local soak_hours="$3"
  local records="$4"
  local iterations="$5"
  local elapsed_sec="$6"

  {
    echo "# Soak/Chaos Reliability Report"
    echo
    echo "- Timestamp (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "- Profile: $profile"
    echo "- Target soak duration (hours): $soak_hours"
    echo "- Iterations: $iterations"
    echo "- Elapsed seconds: $elapsed_sec"
    echo "- Mode: deterministic local soak + chaos gate"
    echo
    echo "## Command Results"
    echo "| Check | Exit |"
    echo "|---|---|"
    while IFS='|' read -r name code; do
      [[ -z "$name" ]] && continue
      echo "| $name | $code |"
    done <<<"$records"
  } >"$report"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  OUT_DIR="$tmp/out"
  PROFILE="quick"

  local records=""
  records+="$(run_cmd "selftest-true" "true" "$tmp/a.log")"$'\n'
  records+="$(run_cmd "selftest-false" "false" "$tmp/b.log")"$'\n'

  mkdir -p "$OUT_DIR"
  render_report "$OUT_DIR/report.md" "$PROFILE" "1" "$records" "1" "0"

  [[ -f "$OUT_DIR/report.md" ]] || { echo "self-test failed: missing report" >&2; rm -rf "$tmp"; return 1; }
  grep -q "selftest-true" "$OUT_DIR/report.md" || { echo "self-test failed: missing selftest-true row" >&2; rm -rf "$tmp"; return 1; }
  grep -q "selftest-false" "$OUT_DIR/report.md" || { echo "self-test failed: missing selftest-false row" >&2; rm -rf "$tmp"; return 1; }

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
    --profile)
      [[ $# -ge 2 ]] || { echo "missing value for --profile" >&2; exit 2; }
      PROFILE="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || { echo "missing value for --out-dir" >&2; exit 2; }
      OUT_DIR="$2"
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

if [[ "$PROFILE" != "quick" && "$PROFILE" != "prod" ]]; then
  echo "unsupported profile: $PROFILE" >&2
  exit 2
fi

if [[ -z "$SOAK_ITERATIONS" ]]; then
  if [[ "$PROFILE" == "quick" ]]; then
    SOAK_ITERATIONS=2
  else
    SOAK_ITERATIONS=6
  fi
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

# Keep Zig cache paths inside repository-writable roots for sandboxed runs.
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$REPO_ROOT/.zig-global-cache}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$REPO_ROOT/.zig-cache}"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$REPO_ROOT/artifacts/reliability/$(timestamp_utc)"
fi
mkdir -p "$OUT_DIR"

records=""
records+="$(run_cmd "interop-matrix-self-test" "bash scripts/interop/matrix_local.sh --self-test" "$OUT_DIR/interop-matrix-self-test.log")"$'\n'
records+="$(run_cmd "fuzz-replay-self-test" "bash scripts/fuzz/replay_corpus.sh --self-test" "$OUT_DIR/fuzz-replay-self-test.log")"$'\n'
records+="$(run_cmd "timing-harness-assert" "bash scripts/security/run_timing_harness.sh --assert" "$OUT_DIR/timing-harness-assert.log")"$'\n'
records+="$(run_cmd "perf-assert" "bash scripts/benchmark/run_local_perf.sh --assert" "$OUT_DIR/perf-assert.log")"$'\n'

start_sec="$(date +%s)"
iter=1
while [[ "$iter" -le "$SOAK_ITERATIONS" ]]; do
  records+="$(run_cmd "soak-termination-${iter}" "zig test src/termination.zig" "$OUT_DIR/soak-termination-${iter}.log")"$'\n'
  records+="$(run_cmd "soak-session-${iter}" "zig test src/tls13/session.zig" "$OUT_DIR/soak-session-${iter}.log")"$'\n'
  iter=$((iter + 1))
done

records+="$(run_cmd "chaos-cert-reload-rollback" "zig test src/cert_reload.zig" "$OUT_DIR/chaos-cert-reload-rollback.log")"$'\n'
records+="$(run_cmd "chaos-ticket-rotation-drift" "zig test src/tls13/ticket_keys.zig" "$OUT_DIR/chaos-ticket-rotation-drift.log")"$'\n'

if [[ "$PROFILE" == "prod" ]]; then
  records+="$(run_cmd "preflight-dry-run" "bash scripts/release/preflight.sh --dry-run" "$OUT_DIR/preflight-dry-run.log")"$'\n'
fi

end_sec="$(date +%s)"
elapsed_sec=$((end_sec - start_sec))

render_report "$OUT_DIR/report.md" "$PROFILE" "$SOAK_HOURS" "$records" "$SOAK_ITERATIONS" "$elapsed_sec"

echo "reliability report: $OUT_DIR/report.md"

echo "$records" | awk -F'|' '{ if (NF == 2 && $2 != 0) bad = 1 } END { exit bad }'
if [[ $? -ne 0 ]]; then
  echo "reliability gate failed" >&2
  exit 1
fi

echo "reliability gate passed"
