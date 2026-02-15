#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
STRICT_INTEROP=0

usage() {
  cat <<USAGE
usage: preflight.sh [--dry-run] [--strict-interop]

Options:
  --dry-run         Print commands without executing
  --strict-interop  Run strict interop matrix + evidence generation
USAGE
}

run_cmd() {
  local cmd="$1"
  echo "[preflight] $cmd"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    eval "$cmd"
  fi
}

maybe_set_default_env() {
  local name="$1"
  local value="$2"
  if [[ -z "${!name:-}" && -n "$value" ]]; then
    export "$name=$value"
  fi
}

configure_strict_interop_env() {
  if [[ "$STRICT_INTEROP" -ne 1 ]]; then
    return 0
  fi

  if [[ -z "${RUSTLS_CLIENT:-}" && -x "/tmp/rustls/target/release/tlsclient-mio" ]]; then
    maybe_set_default_env "RUSTLS_CLIENT" "/tmp/rustls/target/release/tlsclient-mio"
  fi
  if [[ -z "${RUSTLS_SERVER:-}" && -x "/tmp/rustls/target/release/tlsserver-mio" ]]; then
    maybe_set_default_env "RUSTLS_SERVER" "/tmp/rustls/target/release/tlsserver-mio"
  fi

  if [[ -z "${NSS_DIR:-}" && -d "/opt/homebrew/opt/nss" ]]; then
    maybe_set_default_env "NSS_DIR" "/opt/homebrew/opt/nss"
  fi
  if [[ -z "${NSS_BIN_DIR:-}" && -n "${NSS_DIR:-}" && -d "${NSS_DIR}/bin" ]]; then
    maybe_set_default_env "NSS_BIN_DIR" "${NSS_DIR}/bin"
  fi
  if [[ -z "${NSS_LIB_DIR:-}" && -n "${NSS_DIR:-}" && -d "${NSS_DIR}/lib" ]]; then
    maybe_set_default_env "NSS_LIB_DIR" "${NSS_DIR}/lib"
  fi
}

assert_strict_interop_env() {
  if [[ "$STRICT_INTEROP" -ne 1 ]]; then
    return 0
  fi

  local missing=()
  [[ -n "${RUSTLS_CLIENT:-}" ]] || missing+=("RUSTLS_CLIENT")
  [[ -n "${RUSTLS_SERVER:-}" ]] || missing+=("RUSTLS_SERVER")
  [[ -n "${NSS_DIR:-}" ]] || missing+=("NSS_DIR")
  [[ -n "${NSS_BIN_DIR:-}" ]] || missing+=("NSS_BIN_DIR")
  [[ -n "${NSS_LIB_DIR:-}" ]] || missing+=("NSS_LIB_DIR")

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  echo "[preflight] strict interop missing env: ${missing[*]}" >&2
  echo "[preflight] set vars manually or ensure local toolchains exist at default discovery paths" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --strict-interop)
      STRICT_INTEROP=1
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

configure_strict_interop_env
assert_strict_interop_env

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
run_cmd "bash -n scripts/release/check_dependency_baseline.sh"
run_cmd "bash scripts/release/check_dependency_baseline.sh --self-test"
run_cmd "bash scripts/release/check_dependency_baseline.sh"
run_cmd "bash -n scripts/release/check_production_artifacts.sh"
run_cmd "bash scripts/release/check_production_artifacts.sh --self-test"
run_cmd "bash -n scripts/fuzz/replay_corpus.sh"
run_cmd "bash scripts/fuzz/replay_corpus.sh --self-test"
run_cmd "bash scripts/benchmark/run_local_perf.sh"
run_cmd "bash scripts/benchmark/run_local_perf.sh --assert"
run_cmd "bash scripts/security/run_timing_harness.sh --assert"

if [[ "$STRICT_INTEROP" -eq 1 ]]; then
  run_cmd "bash scripts/interop/matrix_local.sh --strict"
  run_cmd "bash scripts/interop/generate_evidence.sh"
  run_cmd "bash scripts/release/check_production_artifacts.sh"
fi

echo "[preflight] all checks passed"
