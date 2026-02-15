#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: check_external_consumer.sh [--self-test]

Builds a temporary external Zig application that depends on this repository
as a local path package and verifies import/build/run succeeds.
USAGE
}

self_test() {
  bash -n "$0"
  echo "self-test: ok"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmpdir="$(mktemp -d /tmp/zigtls-consumer.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT
ln -s "$repo_root" "$tmpdir/zigtls"

cat > "$tmpdir/build.zig.zon" <<EOF
.{
    .name = .consumer_app,
    .version = "0.0.0",
    .fingerprint = 0x918ef80468037d09,
    .minimum_zig_version = "0.15.0",
    .dependencies = .{
        .zigtls = .{
            .path = "zigtls",
        },
    },
    .paths = .{
        "build.zig",
        "src",
    },
}
EOF

cat > "$tmpdir/build.zig" <<'EOF'
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dep = b.dependency("zigtls", .{
        .target = target,
        .optimize = optimize,
    });
    const mod = dep.module("zigtls");

    const exe = b.addExecutable(.{
        .name = "consumer-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zigtls", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);
}
EOF

mkdir -p "$tmpdir/src"
cat > "$tmpdir/src/main.zig" <<'EOF'
const std = @import("std");
const zigtls = @import("zigtls");

pub fn main() !void {
    var conn = zigtls.termination.Connection.init(std.heap.page_allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 77 });
    _ = try conn.write_plaintext("hello");
    std.debug.print("external-consumer-ok:{s}\n", .{zigtls.version()});
}
EOF

(
  cd "$tmpdir"
  export ZIG_GLOBAL_CACHE_DIR="$tmpdir/.zig-global-cache"
  export ZIG_LOCAL_CACHE_DIR="$tmpdir/.zig-cache"
  zig build
  zig-out/bin/consumer-app
)

echo "external consumer check passed"
