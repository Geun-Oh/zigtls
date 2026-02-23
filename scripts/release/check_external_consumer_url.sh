#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: check_external_consumer_url.sh --url <tarball-url-or-path> --hash <zig-package-hash> [--self-test]

Builds a temporary Zig consumer project using URL/hash dependency form and verifies import/build/run succeeds.
USAGE
}

self_test() {
  bash -n "$0"
  echo "self-test: ok"
}

PACKAGE_URL=""
PACKAGE_HASH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      PACKAGE_URL="${2:-}"
      shift 2
      ;;
    --hash)
      PACKAGE_HASH="${2:-}"
      shift 2
      ;;
    --self-test)
      self_test
      exit 0
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

if [[ -z "$PACKAGE_URL" || -z "$PACKAGE_HASH" ]]; then
  echo "--url and --hash are required" >&2
  usage
  exit 2
fi

dep_url="$PACKAGE_URL"
if [[ "$dep_url" != *"://"* && -f "$dep_url" ]]; then
  dep_dir="$(cd "$(dirname "$dep_url")" && pwd -P)"
  dep_file="$(basename "$dep_url")"
  dep_url="file://${dep_dir}/${dep_file}"
fi

tmpdir="$(mktemp -d /tmp/zigtls-consumer-url.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/build.zig.zon" <<EOF_ZON
.{
    .name = .consumer_app,
    .version = "0.0.0",
    .fingerprint = 0x918ef80468037d09,
    .minimum_zig_version = "0.15.0",
    .dependencies = .{
        .zigtls = .{
            .url = "${dep_url}",
            .hash = "${PACKAGE_HASH}",
        },
    },
    .paths = .{
        "build.zig",
        "src",
    },
}
EOF_ZON

cat > "$tmpdir/build.zig" <<'EOF_BUILD'
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dep = b.dependency("zigtls", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "consumer-url-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigtls", .module = dep.module("zigtls") },
            },
        }),
    });

    b.installArtifact(exe);
}
EOF_BUILD

mkdir -p "$tmpdir/src"
cat > "$tmpdir/src/main.zig" <<'EOF_MAIN'
const std = @import("std");
const zigtls = @import("zigtls");

pub fn main() !void {
    std.debug.print("external-consumer-url-ok:{s}\n", .{zigtls.version()});
}
EOF_MAIN

(
  cd "$tmpdir"
  export ZIG_GLOBAL_CACHE_DIR="$tmpdir/.zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$tmpdir/.zig-cache"
  zig build
  zig-out/bin/consumer-url-app
)

echo "external consumer URL/hash check passed"
