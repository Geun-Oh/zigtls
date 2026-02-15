#!/usr/bin/env bash
set -euo pipefail

zig build perf-probe
./zig-out/bin/perf-probe
