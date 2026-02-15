#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
ROOT_OVERRIDE=""

usage() {
  cat <<USAGE
usage: check_production_artifacts.sh [--self-test] [--root <dir>]

Options:
  --self-test    Run internal self-test
  --root <dir>   Override repository root (default: auto-detect)
USAGE
}

run_check() {
  local root="$1"
  local missing=0

  local required_docs=(
    "docs/termination-api.md"
    "docs/rfc8446-matrix.md"
    "docs/risk-acceptance.md"
    "docs/release-runbook.md"
    "docs/performance-baseline.md"
    "docs/bogo-profile-v1-prod.md"
    "docs/release-signoff.md"
    "docs/rollout-canary-gate.md"
    "docs/api-compatibility-policy.md"
    "docs/external-validation-2026-02-15.md"
    "docs/task-closure-matrix.md"
  )

  for rel in "${required_docs[@]}"; do
    if [[ ! -f "$root/$rel" ]]; then
      echo "missing required document: $rel" >&2
      missing=1
    fi
  done

  if [[ ! -f "$root/scripts/interop/bogo_expected_failures_v1_prod.txt" ]]; then
    echo "missing expected-failure inventory file: scripts/interop/bogo_expected_failures_v1_prod.txt" >&2
    missing=1
  fi

  if ! find "$root/artifacts/interop" -mindepth 2 -maxdepth 2 -name report.md -print -quit >/dev/null 2>&1; then
    echo "missing interop evidence report under artifacts/interop/*/report.md" >&2
    missing=1
  fi

  if ! find "$root/artifacts/reliability" -mindepth 2 -maxdepth 2 -name report.md -print -quit >/dev/null 2>&1; then
    echo "missing reliability report under artifacts/reliability/*/report.md" >&2
    missing=1
  fi

  local signoff_doc="$root/docs/release-signoff.md"
  local external_doc="$root/docs/external-validation-2026-02-15.md"
  local signoff_interop_ref=""
  local external_interop_ref=""
  local signoff_reliability_ref=""

  local strict_zero_metrics=(
    "critical_failure_count=0"
    "expected_failure_name_count=0"
    "in_scope_required_non_pass=0"
    "in_scope_required_non_pass_raw=0"
  )

  if [[ -f "$signoff_doc" ]]; then
    signoff_interop_ref="$(grep -Eo 'artifacts/interop/[0-9]{8}T[0-9]{6}Z/' "$signoff_doc" | head -n 1 || true)"
    signoff_reliability_ref="$(grep -Eo 'artifacts/reliability/[0-9]{8}T[0-9]{6}Z/report\.md' "$signoff_doc" | head -n 1 || true)"
  fi
  if [[ -f "$external_doc" ]]; then
    external_interop_ref="$(grep -Eo 'artifacts/interop/[0-9]{8}T[0-9]{6}Z/' "$external_doc" | head -n 1 || true)"
  fi

  if [[ -z "$signoff_interop_ref" ]]; then
    echo "missing interop evidence path in docs/release-signoff.md" >&2
    missing=1
  fi
  if [[ -z "$external_interop_ref" ]]; then
    echo "missing interop evidence path in docs/external-validation-2026-02-15.md" >&2
    missing=1
  fi
  if [[ -n "$signoff_interop_ref" && -n "$external_interop_ref" && "$signoff_interop_ref" != "$external_interop_ref" ]]; then
    echo "interop evidence path mismatch between signoff and external validation docs" >&2
    echo "  signoff: $signoff_interop_ref" >&2
    echo "  external: $external_interop_ref" >&2
    missing=1
  fi
  if [[ -n "$signoff_interop_ref" && ! -f "$root/$signoff_interop_ref/report.md" ]]; then
    echo "referenced interop evidence report missing: $signoff_interop_ref" >&2
    missing=1
  fi

  if [[ -z "$signoff_reliability_ref" ]]; then
    echo "missing reliability report path in docs/release-signoff.md" >&2
    missing=1
  elif [[ ! -f "$root/$signoff_reliability_ref" ]]; then
    echo "referenced reliability report missing: $signoff_reliability_ref" >&2
    missing=1
  fi

  for metric in "${strict_zero_metrics[@]}"; do
    if [[ -f "$external_doc" ]] && ! grep -q "$metric" "$external_doc"; then
      echo "missing strict metric '$metric' in docs/external-validation-2026-02-15.md" >&2
      missing=1
    fi
    if [[ -f "$signoff_doc" ]] && ! grep -q "$metric" "$signoff_doc"; then
      echo "missing strict metric '$metric' in docs/release-signoff.md" >&2
      missing=1
    fi
  done

  local latest_interop_report=""
  latest_interop_report="$(find "$root/artifacts/interop" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"
  local latest_interop_ref=""
  if [[ -n "$latest_interop_report" ]]; then
    latest_interop_ref="${latest_interop_report#"$root/"}"
    latest_interop_ref="${latest_interop_ref%/report.md}/"
    if ! grep -q "Matrix status: PASS" "$latest_interop_report"; then
      echo "latest interop report is not PASS: $latest_interop_report" >&2
      missing=1
    fi
  fi

  local latest_reliability_report=""
  latest_reliability_report="$(find "$root/artifacts/reliability" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"
  local latest_reliability_ref=""
  if [[ -n "$latest_reliability_report" ]]; then
    latest_reliability_ref="${latest_reliability_report#"$root/"}"
    if ! grep -q "Profile: prod" "$latest_reliability_report"; then
      echo "latest reliability report is not prod profile: $latest_reliability_report" >&2
      missing=1
    fi
    if ! grep -q "Target soak duration (hours): 24" "$latest_reliability_report"; then
      echo "latest reliability report target duration is not 24h: $latest_reliability_report" >&2
      missing=1
    fi
  fi

  if [[ -n "$latest_interop_ref" && -n "$signoff_interop_ref" && "$signoff_interop_ref" != "$latest_interop_ref" ]]; then
    echo "signoff interop reference is stale (expected latest): $latest_interop_ref" >&2
    echo "  found: $signoff_interop_ref" >&2
    missing=1
  fi
  if [[ -n "$latest_interop_ref" && -n "$external_interop_ref" && "$external_interop_ref" != "$latest_interop_ref" ]]; then
    echo "external validation interop reference is stale (expected latest): $latest_interop_ref" >&2
    echo "  found: $external_interop_ref" >&2
    missing=1
  fi
  if [[ -n "$latest_reliability_ref" && -n "$signoff_reliability_ref" && "$signoff_reliability_ref" != "$latest_reliability_ref" ]]; then
    echo "signoff reliability reference is stale (expected latest): $latest_reliability_ref" >&2
    echo "  found: $signoff_reliability_ref" >&2
    missing=1
  fi

  if [[ "$missing" -ne 0 ]]; then
    return 1
  fi

  echo "production artifact check passed"
  return 0
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  local root="$tmp/repo"
  mkdir -p "$root/docs" "$root/scripts/interop" "$root/artifacts/interop/20260101T000000Z" "$root/artifacts/reliability/20260101T000000Z"

  local required_docs=(
    "termination-api.md"
    "rfc8446-matrix.md"
    "risk-acceptance.md"
    "release-runbook.md"
    "performance-baseline.md"
    "bogo-profile-v1-prod.md"
    "release-signoff.md"
    "rollout-canary-gate.md"
    "api-compatibility-policy.md"
    "external-validation-2026-02-15.md"
    "task-closure-matrix.md"
  )
  for doc in "${required_docs[@]}"; do
    echo "# stub" > "$root/docs/$doc"
  done

  cat > "$root/docs/release-signoff.md" <<'R'
# Release Sign-off (zigtls)

- Strict interop evidence bundle (`artifacts/interop/20260101T000000Z/`)
- Reliability report (`artifacts/reliability/20260101T000000Z/report.md`)
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R

  cat > "$root/docs/external-validation-2026-02-15.md" <<'R'
# External Validation

- interop evidence bundle:
  - `artifacts/interop/20260101T000000Z/`
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R

  : > "$root/scripts/interop/bogo_expected_failures_v1_prod.txt"
  cat > "$root/artifacts/interop/20260101T000000Z/report.md" <<'R'
# Interop Evidence Bundle

- Matrix status: PASS
R
  cat > "$root/artifacts/reliability/20260101T000000Z/report.md" <<'R'
# Soak/Chaos Reliability Report

- Profile: prod
- Target soak duration (hours): 24
R

  run_check "$root" >/dev/null

  mkdir -p "$root/artifacts/interop/20260102T000000Z"
  cat > "$root/artifacts/interop/20260102T000000Z/report.md" <<'R'
# Interop Evidence Bundle

- Matrix status: PASS
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected stale signoff interop reference failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  cat > "$root/docs/release-signoff.md" <<'R'
# Release Sign-off (zigtls)

- Strict interop evidence bundle (`artifacts/interop/20260102T000000Z/`)
- Reliability report (`artifacts/reliability/20260101T000000Z/report.md`)
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R

  cat > "$root/docs/external-validation-2026-02-15.md" <<'R'
# External Validation

- interop evidence bundle:
  - `artifacts/interop/20260101T000000Z/`
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected external interop mismatch failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  cat > "$root/docs/external-validation-2026-02-15.md" <<'R'
# External Validation

- interop evidence bundle:
  - `artifacts/interop/20260102T000000Z/`
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R

  mkdir -p "$root/artifacts/reliability/20260102T000000Z"
  cat > "$root/artifacts/reliability/20260102T000000Z/report.md" <<'R'
# Soak/Chaos Reliability Report

- Profile: prod
- Target soak duration (hours): 24
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected stale signoff reliability reference failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  cat > "$root/docs/release-signoff.md" <<'R'
# Release Sign-off (zigtls)

- Strict interop evidence bundle (`artifacts/interop/20260102T000000Z/`)
- Reliability report (`artifacts/reliability/20260102T000000Z/report.md`)
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=0`
R

  run_check "$root" >/dev/null

  cat > "$root/docs/external-validation-2026-02-15.md" <<'R'
# External Validation

- interop evidence bundle:
  - `artifacts/interop/20260102T000000Z/`
- BoGo strict metrics:
  - `critical_failure_count=0`
  - `expected_failure_name_count=0`
  - `in_scope_required_non_pass=0`
  - `in_scope_required_non_pass_raw=7`
R
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected stale strict metric failure" >&2
    rm -rf "$tmp"
    return 1
  fi

  rm "$root/docs/release-signoff.md"
  if run_check "$root" >/dev/null 2>&1; then
    echo "self-test failed: expected missing-doc failure" >&2
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
