#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
SELF_TEST=0
ROOT_OVERRIDE=""
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

usage() {
  cat <<USAGE
usage: sync_latest_evidence_refs.sh [--dry-run] [--self-test] [--root <dir>]

Update release evidence references in docs to latest artifact timestamps.
USAGE
}

update_file() {
  local src="$1"
  local dst="$2"
  local interop="$3"
  local reliability="$4"
  awk -v interop="$interop" -v reliability="$reliability" '
    /^- Strict interop evidence bundle \(`/ {
      print "- Strict interop evidence bundle (`" interop "`)"
      next
    }
    /^- Reliability report \(`/ {
      print "- Reliability report (`" reliability "`)"
      next
    }
    /^  - `artifacts\/interop\// {
      print "  - `" interop "`"
      next
    }
    { print }
  ' "$src" > "$dst"
}

run_sync() {
  local root="$1"
  local dry_run="$2"
  local latest_interop_report
  local latest_reliability_report
  local latest_interop_rel
  local latest_interop_dir
  local latest_reliability_rel
  local signoff_doc
  local external_doc
  local tmp_signoff
  local tmp_external

  latest_interop_report="$(find "$root/artifacts/interop" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"
  latest_reliability_report="$(find "$root/artifacts/reliability" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"

  if [[ -z "$latest_interop_report" ]]; then
    echo "no interop report found under artifacts/interop" >&2
    return 1
  fi
  if [[ -z "$latest_reliability_report" ]]; then
    echo "no reliability report found under artifacts/reliability" >&2
    return 1
  fi

  latest_interop_rel="${latest_interop_report#"$root/"}"
  latest_interop_dir="${latest_interop_rel%/report.md}/"
  latest_reliability_rel="${latest_reliability_report#"$root/"}"

  signoff_doc="$root/docs/release-signoff.md"
  external_doc="$root/docs/external-validation-2026-02-15.md"

  if [[ ! -f "$signoff_doc" || ! -f "$external_doc" ]]; then
    echo "required docs not found" >&2
    return 1
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    tmp_signoff="$(mktemp)"
    tmp_external="$(mktemp)"
    update_file "$signoff_doc" "$tmp_signoff" "$latest_interop_dir" "$latest_reliability_rel"
    update_file "$external_doc" "$tmp_external" "$latest_interop_dir" "$latest_reliability_rel"

    echo "[sync-evidence] latest interop: $latest_interop_dir"
    echo "[sync-evidence] latest reliability: $latest_reliability_rel"

    if cmp -s "$signoff_doc" "$tmp_signoff" && cmp -s "$external_doc" "$tmp_external"; then
      echo "[sync-evidence] no changes"
    else
      echo "[sync-evidence] would update docs:"
      diff -u "$signoff_doc" "$tmp_signoff" || true
      diff -u "$external_doc" "$tmp_external" || true
    fi

    rm -f "$tmp_signoff" "$tmp_external"
    return 0
  fi

  tmp_signoff="$(mktemp)"
  tmp_external="$(mktemp)"
  update_file "$signoff_doc" "$tmp_signoff" "$latest_interop_dir" "$latest_reliability_rel"
  update_file "$external_doc" "$tmp_external" "$latest_interop_dir" "$latest_reliability_rel"
  mv "$tmp_signoff" "$signoff_doc"
  mv "$tmp_external" "$external_doc"

  echo "[sync-evidence] updated docs to interop=$latest_interop_dir reliability=$latest_reliability_rel"
  return 0
}

self_test() {
  local tmp
  local root
  tmp="$(mktemp -d)"
  root="$tmp/repo"
  mkdir -p "$root/docs" "$root/artifacts/interop/20260101T000000Z" "$root/artifacts/interop/20260102T000000Z" "$root/artifacts/reliability/20260101T000000Z" "$root/artifacts/reliability/20260102T000000Z"

  cat > "$root/docs/release-signoff.md" <<'R'
# Release Sign-off
- Strict interop evidence bundle (`artifacts/interop/20260101T000000Z/`)
- Reliability report (`artifacts/reliability/20260101T000000Z/report.md`)
R
  cat > "$root/docs/external-validation-2026-02-15.md" <<'R'
# External
- interop evidence bundle:
  - `artifacts/interop/20260101T000000Z/`
R
  cat > "$root/artifacts/interop/20260101T000000Z/report.md" <<'R'
# Interop
R
  cat > "$root/artifacts/interop/20260102T000000Z/report.md" <<'R'
# Interop newer
R
  cat > "$root/artifacts/reliability/20260101T000000Z/report.md" <<'R'
# Reliability
R
  cat > "$root/artifacts/reliability/20260102T000000Z/report.md" <<'R'
# Reliability newer
R

  run_sync "$root" 1 >/dev/null
  run_sync "$root" 0 >/dev/null

  if ! grep -q 'artifacts/interop/20260102T000000Z/' "$root/docs/release-signoff.md"; then
    echo "self-test failed: signoff interop not updated" >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! grep -q 'artifacts/reliability/20260102T000000Z/report.md' "$root/docs/release-signoff.md"; then
    echo "self-test failed: signoff reliability not updated" >&2
    rm -rf "$tmp"
    return 1
  fi
  if ! grep -q 'artifacts/interop/20260102T000000Z/' "$root/docs/external-validation-2026-02-15.md"; then
    echo "self-test failed: external interop not updated" >&2
    rm -rf "$tmp"
    return 1
  fi

  rm -rf "$tmp"
  echo "self-test: ok"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
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
fi

run_sync "$ROOT" "$DRY_RUN"
