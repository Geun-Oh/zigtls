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
  )
  for doc in "${required_docs[@]}"; do
    echo "# stub" > "$root/docs/$doc"
  done
  : > "$root/scripts/interop/bogo_expected_failures_v1_prod.txt"
  echo "ok" > "$root/artifacts/interop/20260101T000000Z/report.md"
  echo "ok" > "$root/artifacts/reliability/20260101T000000Z/report.md"

  run_check "$root" >/dev/null

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
