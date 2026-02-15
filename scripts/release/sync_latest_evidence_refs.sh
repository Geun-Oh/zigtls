#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=0
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

usage() {
  cat <<USAGE
usage: sync_latest_evidence_refs.sh [--dry-run]

Update release evidence references in docs to latest artifact timestamps.
USAGE
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

latest_interop_report="$(find "$ROOT/artifacts/interop" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"
latest_reliability_report="$(find "$ROOT/artifacts/reliability" -mindepth 2 -maxdepth 2 -name report.md 2>/dev/null | LC_ALL=C sort | tail -n 1)"

if [[ -z "$latest_interop_report" ]]; then
  echo "no interop report found under artifacts/interop" >&2
  exit 1
fi
if [[ -z "$latest_reliability_report" ]]; then
  echo "no reliability report found under artifacts/reliability" >&2
  exit 1
fi

latest_interop_rel="${latest_interop_report#"$ROOT/"}"
latest_interop_dir="${latest_interop_rel%/report.md}/"
latest_reliability_rel="${latest_reliability_report#"$ROOT/"}"

signoff_doc="$ROOT/docs/release-signoff.md"
external_doc="$ROOT/docs/external-validation-2026-02-15.md"

if [[ ! -f "$signoff_doc" || ! -f "$external_doc" ]]; then
  echo "required docs not found" >&2
  exit 1
fi

update_file() {
  local src="$1"
  local dst="$2"
  awk -v interop="$latest_interop_dir" -v reliability="$latest_reliability_rel" '
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

if [[ "$DRY_RUN" -eq 1 ]]; then
  tmp_signoff="$(mktemp)"
  tmp_external="$(mktemp)"
  update_file "$signoff_doc" "$tmp_signoff"
  update_file "$external_doc" "$tmp_external"

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
  exit 0
fi

tmp_signoff="$(mktemp)"
tmp_external="$(mktemp)"
update_file "$signoff_doc" "$tmp_signoff"
update_file "$external_doc" "$tmp_external"
mv "$tmp_signoff" "$signoff_doc"
mv "$tmp_external" "$external_doc"

echo "[sync-evidence] updated docs to interop=$latest_interop_dir reliability=$latest_reliability_rel"
