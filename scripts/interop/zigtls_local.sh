#!/usr/bin/env bash
set -euo pipefail

# zigtls local runtime smoke check.
# Ensures local consumer import/build path and event-loop sample execution are healthy.

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

(
  cd "$REPO_ROOT"
  bash scripts/release/check_external_consumer.sh
  zig build lb-example --cache-dir .zig-cache --global-cache-dir .zig-global-cache
)

echo "zigtls local runtime check passed"
