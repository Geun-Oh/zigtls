#!/usr/bin/env bash
set -euo pipefail

MODE="all"
DRY_RUN=0
SYNC_EVIDENCE_DOCS=0

usage() {
  cat <<USAGE
usage: verify_task_gates.sh [--basic-only|--strict-only] [--dry-run] [--sync-evidence-docs]

Run _task.md section 5 gate commands in deterministic order.

Options:
  --basic-only   Run section 5.1 basic gates only
  --strict-only  Run section 5.2 strict gates only
  --dry-run      Print commands without executing
  --sync-evidence-docs  Sync evidence docs before strict artifact gate
USAGE
}

run_cmd() {
  local cmd="$1"
  echo "[task-gates] $cmd"
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

configure_strict_env_defaults() {
  if [[ "$MODE" == "basic" ]]; then
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

assert_strict_env() {
  if [[ "$MODE" == "basic" ]]; then
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    : "${BORINGSSL_DIR:=<BORINGSSL_DIR>}"
    : "${RUSTLS_CLIENT:=<RUSTLS_CLIENT>}"
    : "${RUSTLS_SERVER:=<RUSTLS_SERVER>}"
    : "${NSS_DIR:=<NSS_DIR>}"
    : "${NSS_BIN_DIR:=<NSS_BIN_DIR>}"
    : "${NSS_LIB_DIR:=<NSS_LIB_DIR>}"
    return 0
  fi

  local missing=()
  [[ -n "${BORINGSSL_DIR:-}" ]] || missing+=("BORINGSSL_DIR")
  [[ -n "${RUSTLS_CLIENT:-}" ]] || missing+=("RUSTLS_CLIENT")
  [[ -n "${RUSTLS_SERVER:-}" ]] || missing+=("RUSTLS_SERVER")
  [[ -n "${NSS_DIR:-}" ]] || missing+=("NSS_DIR")
  [[ -n "${NSS_BIN_DIR:-}" ]] || missing+=("NSS_BIN_DIR")
  [[ -n "${NSS_LIB_DIR:-}" ]] || missing+=("NSS_LIB_DIR")

  if [[ "${#missing[@]}" -ne 0 ]]; then
    echo "[task-gates] missing strict env: ${missing[*]}" >&2
    echo "[task-gates] set vars manually or provide local toolchains at default discovery paths" >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --basic-only)
      MODE="basic"
      shift
      ;;
    --strict-only)
      MODE="strict"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --sync-evidence-docs)
      SYNC_EVIDENCE_DOCS=1
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

configure_strict_env_defaults
assert_strict_env

run_cmd "bash scripts/release/check_write_ahead_log.sh"
run_cmd "bash scripts/release/check_task_closure_matrix.sh"

if [[ "$MODE" == "all" || "$MODE" == "basic" ]]; then
  run_cmd "zig build test"
  run_cmd "zig test tools/bogo_shim.zig"
  run_cmd "python3 scripts/interop/bogo_summary.py --self-test"
  run_cmd "bash scripts/interop/matrix_local.sh --self-test"
  run_cmd "bash scripts/fuzz/replay_corpus.sh --self-test"
  run_cmd "bash scripts/benchmark/run_local_perf.sh --assert"
  run_cmd "bash scripts/security/run_timing_harness.sh --assert"
  run_cmd "bash scripts/release/check_production_artifacts.sh"
fi

if [[ "$MODE" == "all" || "$MODE" == "strict" ]]; then
  if [[ "$SYNC_EVIDENCE_DOCS" -eq 0 ]]; then
    echo "[task-gates] warning: --sync-evidence-docs is disabled; final artifact check may fail if strict run generates newer evidence artifacts." >&2
  fi
  run_cmd "bash scripts/interop/matrix_local.sh --strict"
  run_cmd "bash scripts/interop/generate_evidence.sh"
  run_cmd "BOGO_PROFILE=scripts/interop/bogo_profile_v1_prod.json BOGO_STRICT=1 BOGO_ALLOW_UNIMPLEMENTED=0 BOGO_MAX_CRITICAL=0 BORINGSSL_DIR=${BORINGSSL_DIR} bash scripts/interop/bogo_run.sh"
  run_cmd "bash scripts/fuzz/replay_corpus.sh --skip-baseline"
  run_cmd "bash scripts/reliability/run_soak_chaos.sh --profile prod"
  if [[ "$SYNC_EVIDENCE_DOCS" -eq 1 ]]; then
    run_cmd "bash scripts/release/sync_latest_evidence_refs.sh"
  fi
  run_cmd "bash scripts/release/check_production_artifacts.sh"
fi

echo "[task-gates] completed mode=${MODE}"
