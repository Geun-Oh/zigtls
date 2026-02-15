#!/usr/bin/env bash
set -euo pipefail

SELF_TEST=0
ROOT_OVERRIDE=""
WAL_PATH=""

usage() {
  cat <<USAGE
usage: check_write_ahead_log.sh [--self-test] [--root <dir>] [--wal <path>]

Validate _write_ahead_log.md metadata header format.
USAGE
}

run_check() {
  local wal_file="$1"
  [[ -f "$wal_file" ]] || { echo "missing WAL file: $wal_file" >&2; return 1; }

  awk '
    BEGIN {
      allowed_type["plan"] = 1
      allowed_type["analysis"] = 1
      allowed_type["design"] = 1
      allowed_type["code change"] = 1
      allowed_type["refactor"] = 1
      allowed_type["test"] = 1
      allowed_type["benchmark"] = 1
      allowed_type["docs"] = 1
      allowed_type["review"] = 1
      allowed_type["release"] = 1
      allowed_type["rollback"] = 1

      in_header = 0
      ts = ""
      desc = ""
      typ = ""
      bad = 0
      line_no = 0
      entry_index = 0
    }

    function reset_header() {
      ts = ""
      desc = ""
      typ = ""
      spacing_error = 0
      unknown_key_error = 0
      malformed_line_error = 0
      saw_meta = 0
    }

    function report_error(msg) {
      print "WAL format error: " msg > "/dev/stderr"
      bad = 1
    }

    {
      line_no++
      if ($0 == "===") {
        if (in_header == 0) {
          in_header = 1
          entry_index++
          reset_header()
          next
        }

        # finalize header
        in_header = 0
        if (ts == "") report_error("entry " entry_index " missing timestamp")
        if (desc == "") report_error("entry " entry_index " missing description")
        if (typ == "") report_error("entry " entry_index " missing type")

        if (ts != "" && ts !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})$/) {
          report_error("entry " entry_index " invalid timestamp format: " ts)
        }

        if (typ != "" && !(typ in allowed_type)) {
          report_error("entry " entry_index " invalid type: " typ)
        }

        if (spacing_error) {
          print "WAL format warning: metadata key spacing drift in entry " entry_index " timestamp=" ts > "/dev/stderr"
        }

        next
      }

      if (in_header == 1) {
        saw_meta = 1
        if (index($0, ":") == 0) {
          malformed_line_error = 1
          report_error("entry " entry_index " malformed metadata line at " line_no ": " $0)
          next
        }

        raw = $0
        prefix = ""
        if (raw ~ /^[[:space:]]+/) {
          spacing_error = 1
          raw = substr(raw, RLENGTH + 1)
        }

        split(raw, parts, ":")
        key = parts[1]
        sub(/^[[:space:]]+/, "", key)
        sub(/[[:space:]]+$/, "", key)
        gsub(/^[^A-Za-z]+/, "", key)
        if (key ~ /timestamp$/) key = "timestamp"
        if (key ~ /description$/) key = "description"
        if (key ~ /type$/) key = "type"

        val = substr(raw, index(raw, ":") + 1)
        sub(/^[[:space:]]+/, "", val)

        if (key == "timestamp") {
          ts = val
        } else if (key == "description") {
          desc = val
        } else if (key == "type") {
          typ = val
        } else {
          unknown_key_error = 1
          report_error("entry " entry_index " unknown metadata key: " key)
        }
      }
    }

    END {
      if (in_header == 1) {
        report_error("unterminated metadata header at EOF")
      }
      if (bad == 0) {
        print "write-ahead-log check passed"
      }
      exit bad
    }
  ' "$wal_file"
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"

  cat > "$tmp/valid.md" <<'R'
===
timestamp: 2026-02-16T00:00:00+09:00
description: valid
type: plan
===
body
R

  cat > "$tmp/invalid_key.md" <<'R'
===
timestamp: 2026-02-16T00:00:00+09:00
description: invalid
typo: test
===
body
R

  cat > "$tmp/warn_spacing.md" <<'R'
===
timestamp: 2026-02-16T00:00:00+09:00
description: warn
 type: test
===
body
R

  cat > "$tmp/invalid_timestamp.md" <<'R'
===
timestamp: 2026/02/16 00:00:00
description: invalid timestamp
type: test
===
body
R

  cat > "$tmp/invalid_type.md" <<'R'
===
timestamp: 2026-02-16T00:00:00+09:00
description: invalid type
type: tests
===
body
R

  cat > "$tmp/unterminated_header.md" <<'R'
===
timestamp: 2026-02-16T00:00:00+09:00
description: missing terminator
type: test
R

  run_check "$tmp/valid.md" >/dev/null

  if run_check "$tmp/invalid_key.md" >/dev/null 2>&1; then
    echo "self-test failed: invalid key should fail" >&2
    rm -rf "$tmp"
    return 1
  fi

  if run_check "$tmp/invalid_timestamp.md" >/dev/null 2>&1; then
    echo "self-test failed: invalid timestamp should fail" >&2
    rm -rf "$tmp"
    return 1
  fi

  if run_check "$tmp/invalid_type.md" >/dev/null 2>&1; then
    echo "self-test failed: invalid type should fail" >&2
    rm -rf "$tmp"
    return 1
  fi

  if run_check "$tmp/unterminated_header.md" >/dev/null 2>&1; then
    echo "self-test failed: unterminated header should fail" >&2
    rm -rf "$tmp"
    return 1
  fi

  run_check "$tmp/warn_spacing.md" >/dev/null

  rm -rf "$tmp"
  echo "self-test: ok"
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
    --wal)
      [[ $# -ge 2 ]] || { echo "missing value for --wal" >&2; exit 2; }
      WAL_PATH="$2"
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

if [[ -n "$WAL_PATH" ]]; then
  TARGET="$WAL_PATH"
else
  if [[ -n "$ROOT_OVERRIDE" ]]; then
    TARGET="$ROOT_OVERRIDE/_write_ahead_log.md"
  else
    TARGET="$(cd "$(dirname "$0")/../.." && pwd)/_write_ahead_log.md"
  fi
fi

run_check "$TARGET"
