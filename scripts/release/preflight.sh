#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
STRICT_INTEROP=0
TASK_GATES=0
SYNC_EVIDENCE_DOCS=0

usage() {
  cat <<USAGE
usage: preflight.sh [--dry-run] [--strict-interop] [--task-gates] [--sync-evidence-docs]

Options:
  --dry-run         Print commands without executing
  --strict-interop  Run strict interop matrix + evidence generation
  --task-gates      Also run canonical _task.md gate sequence via verify_task_gates.sh
  --sync-evidence-docs  Sync docs evidence references to latest artifact outputs
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
  if [[ -z "${BORINGSSL_DIR:-}" && -d "/tmp/boringssl" ]]; then
    maybe_set_default_env "BORINGSSL_DIR" "/tmp/boringssl"
  fi
}

assert_strict_interop_env() {
  if [[ "$STRICT_INTEROP" -ne 1 ]]; then
    return 0
  fi

  local missing=()
  local invalid=()
  [[ -n "${RUSTLS_CLIENT:-}" ]] || missing+=("RUSTLS_CLIENT")
  [[ -n "${RUSTLS_SERVER:-}" ]] || missing+=("RUSTLS_SERVER")
  [[ -n "${NSS_DIR:-}" ]] || missing+=("NSS_DIR")
  [[ -n "${NSS_BIN_DIR:-}" ]] || missing+=("NSS_BIN_DIR")
  [[ -n "${NSS_LIB_DIR:-}" ]] || missing+=("NSS_LIB_DIR")
  if [[ "$TASK_GATES" -eq 1 ]]; then
    [[ -n "${BORINGSSL_DIR:-}" ]] || missing+=("BORINGSSL_DIR")
  fi

  if [[ -n "${RUSTLS_CLIENT:-}" && ! -x "${RUSTLS_CLIENT}" ]]; then
    invalid+=("RUSTLS_CLIENT(not executable):${RUSTLS_CLIENT}")
  fi
  if [[ -n "${RUSTLS_SERVER:-}" && ! -x "${RUSTLS_SERVER}" ]]; then
    invalid+=("RUSTLS_SERVER(not executable):${RUSTLS_SERVER}")
  fi
  if [[ -n "${NSS_DIR:-}" && ! -d "${NSS_DIR}" ]]; then
    invalid+=("NSS_DIR(not directory):${NSS_DIR}")
  fi
  if [[ -n "${NSS_BIN_DIR:-}" && ! -d "${NSS_BIN_DIR}" ]]; then
    invalid+=("NSS_BIN_DIR(not directory):${NSS_BIN_DIR}")
  fi
  if [[ -n "${NSS_LIB_DIR:-}" && ! -d "${NSS_LIB_DIR}" ]]; then
    invalid+=("NSS_LIB_DIR(not directory):${NSS_LIB_DIR}")
  fi
  if [[ "$TASK_GATES" -eq 1 && -n "${BORINGSSL_DIR:-}" && ! -d "${BORINGSSL_DIR}" ]]; then
    invalid+=("BORINGSSL_DIR(not directory):${BORINGSSL_DIR}")
  fi

  if [[ "${#missing[@]}" -eq 0 && "${#invalid[@]}" -eq 0 ]]; then
    return 0
  fi

  if [[ "${#missing[@]}" -ne 0 ]]; then
    echo "[preflight] strict interop missing env: ${missing[*]}" >&2
  fi
  if [[ "${#invalid[@]}" -ne 0 ]]; then
    echo "[preflight] strict interop invalid env: ${invalid[*]}" >&2
  fi
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
    --task-gates)
      TASK_GATES=1
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
run_cmd "bash scripts/release/check_production_artifacts.sh"
run_cmd "bash -n scripts/fuzz/replay_corpus.sh"
run_cmd "bash scripts/fuzz/replay_corpus.sh --self-test"
run_cmd "bash scripts/benchmark/run_local_perf.sh"
run_cmd "bash scripts/benchmark/run_local_perf.sh --assert"
run_cmd "bash scripts/security/run_timing_harness.sh --assert"

if [[ "$STRICT_INTEROP" -eq 1 ]]; then
  run_cmd "bash scripts/interop/matrix_local.sh --strict"
  run_cmd "bash scripts/interop/generate_evidence.sh"
  if [[ "$SYNC_EVIDENCE_DOCS" -eq 1 ]]; then
    run_cmd "bash scripts/release/sync_latest_evidence_refs.sh"
  fi
  run_cmd "bash scripts/release/check_production_artifacts.sh"
fi

if [[ "$TASK_GATES" -eq 1 ]]; then
  if [[ "$STRICT_INTEROP" -eq 1 ]]; then
    if [[ "$SYNC_EVIDENCE_DOCS" -eq 1 ]]; then
      run_cmd "bash scripts/release/verify_task_gates.sh --strict-only --sync-evidence-docs"
    else
      run_cmd "bash scripts/release/verify_task_gates.sh --strict-only"
    fi
  else
    run_cmd "bash scripts/release/verify_task_gates.sh --basic-only"
  fi
fi

if [[ "$SYNC_EVIDENCE_DOCS" -eq 1 && "$STRICT_INTEROP" -eq 0 ]]; then
  run_cmd "bash scripts/release/sync_latest_evidence_refs.sh"
fi

echo "[preflight] all checks passed"
