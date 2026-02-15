#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0

usage() {
  cat <<USAGE
usage: preflight.sh [--dry-run]

Options:
  --dry-run    Print commands without executing
USAGE
}

run_cmd() {
  local cmd="$1"
  echo "[preflight] $cmd"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    eval "$cmd"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
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

run_cmd "zig test src/tls13/record.zig"
run_cmd "zig test src/tls13/handshake.zig"
run_cmd "zig test src/tls13/messages.zig"
run_cmd "zig test src/tls13/state.zig"
run_cmd "zig test src/tls13/keyschedule.zig"
run_cmd "zig test src/tls13/session.zig"
run_cmd "zig test src/tls13/certificate_validation.zig"
run_cmd "zig test src/tls13/ocsp.zig"
run_cmd "zig test src/tls13/trust_store.zig"
run_cmd "zig build test"
run_cmd "python3 scripts/interop/bogo_summary.py --self-test"
run_cmd "bash -n scripts/interop/bogo_run.sh"
run_cmd "bash -n scripts/interop/openssl_local.sh"
run_cmd "bash -n scripts/interop/rustls_local.sh"
run_cmd "bash -n scripts/interop/nss_local.sh"
run_cmd "bash -n scripts/interop/matrix_local.sh"
run_cmd "bash -n scripts/interop/generate_evidence.sh"
run_cmd "bash scripts/interop/matrix_local.sh --self-test"
run_cmd "bash -n scripts/security/run_timing_harness.sh"
run_cmd "bash scripts/security/run_timing_harness.sh --self-test"
run_cmd "bash -n scripts/reliability/run_soak_chaos.sh"
run_cmd "bash scripts/reliability/run_soak_chaos.sh --self-test"
run_cmd "bash -n scripts/release/check_api_surface.sh"
run_cmd "bash scripts/release/check_api_surface.sh --self-test"
run_cmd "bash scripts/release/check_api_surface.sh"
run_cmd "bash -n scripts/fuzz/replay_corpus.sh"
run_cmd "bash scripts/fuzz/replay_corpus.sh --self-test"
run_cmd "bash scripts/benchmark/run_local_perf.sh"
run_cmd "bash scripts/benchmark/run_local_perf.sh --assert"
run_cmd "bash scripts/security/run_timing_harness.sh --assert"

echo "[preflight] all checks passed"
