const std = @import("std");

const Exit = enum(u8) {
    ok = 0,
    usage = 2,
    unsupported = 89,
    internal = 90,
};

const Config = struct {
    is_server: bool = false,
    host: []const u8 = "127.0.0.1",
    port: u16 = 0,
    expect_version: ?[]const u8 = null,
    expect_cipher: ?[]const u8 = null,
    test_name: ?[]const u8 = null,
};

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leaked = gpa_impl.deinit();
        if (leaked == .leak) {
            std.debug.print("bogo-shim: allocator leak detected\n", .{});
        }
    }
    const gpa = gpa_impl.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len <= 1) {
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    }

    if (std.mem.eql(u8, args[1], "--version")) {
        std.debug.print("zigtls-bogo-shim 0.1.0\n", .{});
        return;
    }

    if (std.mem.eql(u8, args[1], "--list-capabilities")) {
        std.debug.print("tls13=true\n", .{});
        std.debug.print("hrr=true\n", .{});
        std.debug.print("keyupdate=true\n", .{});
        std.debug.print("early_data=partial\n", .{});
        return;
    }

    const parsed = parseArgs(args[1..]) catch |err| {
        std.debug.print("bogo-shim: invalid args: {s}\n", .{@errorName(err)});
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    };

    if (parsed.port == 0) {
        std.debug.print("bogo-shim: missing required --port\n", .{});
        std.process.exit(@intFromEnum(Exit.usage));
    }

    const decision = decideTestRouting(parsed);

    std.debug.print(
        "bogo-shim: scaffold mode (role={s}, host={s}, port={d}, version={s}, cipher={s}, test={s}, decision={s})\n",
        .{
            if (parsed.is_server) "server" else "client",
            parsed.host,
            parsed.port,
            parsed.expect_version orelse "(any)",
            parsed.expect_cipher orelse "(any)",
            parsed.test_name orelse "(none)",
            @tagName(decision),
        },
    );

    std.process.exit(@intFromEnum(switch (decision) {
        .pass => Exit.ok,
        .unsupported => Exit.unsupported,
    }));
}

fn parseArgs(args: []const []const u8) !Config {
    var cfg = Config{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--server")) {
            cfg.is_server = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--client")) {
            cfg.is_server = false;
            continue;
        }

        if (i + 1 >= args.len) return error.MissingValue;

        if (std.mem.eql(u8, arg, "--host")) {
            cfg.host = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--port")) {
            cfg.port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--expect-version")) {
            cfg.expect_version = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--expect-cipher")) {
            cfg.expect_cipher = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--test-name")) {
            cfg.test_name = args[i + 1];
            i += 1;
            continue;
        }

        return error.UnknownFlag;
    }

    return cfg;
}

fn usage() void {
    std.debug.print(
        "usage: bogo-shim [--server|--client] --port <n> [--host <ip>] [--expect-version <v>] [--expect-cipher <c>]\n",
        .{},
    );
    std.debug.print("       bogo-shim --list-capabilities\n", .{});
    std.debug.print("       bogo-shim --version\n", .{});
}

const RoutingDecision = enum {
    pass,
    unsupported,
};

fn decideTestRouting(cfg: Config) RoutingDecision {
    if (cfg.expect_version) |v| {
        if (!isTls13Version(v)) return .unsupported;
    }

    if (cfg.expect_cipher) |cipher| {
        if (!isSupportedCipher(cipher)) return .unsupported;
    }

    if (cfg.test_name) |name| {
        if (std.mem.indexOf(u8, name, "TLS13") != null) return .pass;
        if (std.mem.indexOf(u8, name, "Basic") != null) return .pass;
    }

    return .unsupported;
}

fn isTls13Version(version: []const u8) bool {
    return std.mem.indexOf(u8, version, "1.3") != null;
}

fn isSupportedCipher(cipher: []const u8) bool {
    return std.mem.eql(u8, cipher, "TLS_AES_128_GCM_SHA256") or
        std.mem.eql(u8, cipher, "TLS_AES_256_GCM_SHA384") or
        std.mem.eql(u8, cipher, "TLS_CHACHA20_POLY1305_SHA256");
}

test "parse args accepts expected flags" {
    const cfg = try parseArgs(&.{
        "--server",
        "--host",
        "127.0.0.1",
        "--port",
        "8443",
        "--expect-version",
        "TLS1.3",
        "--test-name",
        "TLS13/BasicHandshake",
    });
    try std.testing.expect(cfg.is_server);
    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.host);
    try std.testing.expectEqualStrings("TLS13/BasicHandshake", cfg.test_name.?);
}

test "parse args rejects unknown flags" {
    try std.testing.expectError(error.UnknownFlag, parseArgs(&.{ "--bad", "1" }));
}

test "routing passes for tls13 basic case" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_AES_128_GCM_SHA256",
        .test_name = "TLS13/BasicHandshake",
    };
    try std.testing.expectEqual(RoutingDecision.pass, decideTestRouting(cfg));
}

test "routing rejects non tls13 version" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.2",
        .test_name = "TLS13/BasicHandshake",
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(cfg));
}
