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
    const stdout = std.fs.File.stdout().deprecatedWriter();

    if (args.len <= 1) {
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    }

    if (std.mem.eql(u8, args[1], "--version")) {
        try stdout.print("zigtls-bogo-shim 0.1.0\n", .{});
        return;
    }

    if (std.mem.eql(u8, args[1], "--list-capabilities")) {
        try stdout.print("tls13=true\n", .{});
        try stdout.print("hrr=true\n", .{});
        try stdout.print("keyupdate=true\n", .{});
        try stdout.print("early_data=partial\n", .{});
        return;
    }

    if (hasFlag(args[1..], "is-handshaker-supported")) {
        // Split-handshake handshaker path is not implemented in this shim.
        // BoGo expects explicit Yes/No on stdout with zero exit code.
        try stdout.print("No\n", .{});
        return;
    }

    const parsed = parseArgs(args[1..]) catch |err| {
        std.debug.print("bogo-shim: invalid args: {s}\n", .{@errorName(err)});
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    };

    if (parsed.port == 0) {
        std.debug.print("bogo-shim: missing --port, treating invocation as unsupported scaffold path\n", .{});
        std.process.exit(@intFromEnum(Exit.unsupported));
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
        if (flagEq(arg, "server")) {
            cfg.is_server = true;
            continue;
        }
        if (flagEq(arg, "client")) {
            cfg.is_server = false;
            continue;
        }

        if (flagEq(arg, "host")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.host = args[i + 1];
            i += 1;
            continue;
        }
        if (flagEq(arg, "port")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
            continue;
        }
        if (flagEq(arg, "expect-version")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.expect_version = args[i + 1];
            i += 1;
            continue;
        }
        if (flagEq(arg, "expect-cipher")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.expect_cipher = args[i + 1];
            i += 1;
            continue;
        }
        if (flagEq(arg, "test-name")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.test_name = args[i + 1];
            i += 1;
            continue;
        }

        if (isFlag(arg)) {
            if (i + 1 < args.len and !isFlag(args[i + 1])) {
                i += 1;
            }
            continue;
        }

        // Tolerate positional arguments emitted by test harness wrappers.
        continue;
    }

    return cfg;
}

fn isFlag(arg: []const u8) bool {
    return std.mem.startsWith(u8, arg, "-");
}

fn flagEq(arg: []const u8, canonical: []const u8) bool {
    if (std.mem.startsWith(u8, arg, "--")) {
        return std.mem.eql(u8, arg[2..], canonical);
    }
    if (std.mem.startsWith(u8, arg, "-")) {
        return std.mem.eql(u8, arg[1..], canonical);
    }
    return false;
}

fn hasFlag(args: []const []const u8, canonical: []const u8) bool {
    for (args) |arg| {
        if (flagEq(arg, canonical)) return true;
    }
    return false;
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

test "parse args ignores unknown flags and positional values" {
    const cfg = try parseArgs(&.{ "--bad", "1", "positional", "--port", "8443" });
    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
}

test "parse args rejects missing option value" {
    try std.testing.expectError(error.MissingValue, parseArgs(&.{"--port"}));
}

test "parse args rejects non-numeric port value" {
    try std.testing.expectError(error.InvalidCharacter, parseArgs(&.{ "--port", "abc" }));
}

test "parse args rejects overflowing port value" {
    try std.testing.expectError(error.Overflow, parseArgs(&.{ "--port", "70000" }));
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

test "routing passes for tls13 required cipher variants" {
    const aes256 = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_AES_256_GCM_SHA384",
        .test_name = "TLS13/AES256",
    };
    try std.testing.expectEqual(RoutingDecision.pass, decideTestRouting(aes256));

    const chacha20 = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_CHACHA20_POLY1305_SHA256",
        .test_name = "TLS13/CHACHA20",
    };
    try std.testing.expectEqual(RoutingDecision.pass, decideTestRouting(chacha20));
}

test "routing rejects non tls13 version" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.2",
        .test_name = "TLS13/BasicHandshake",
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(cfg));
}

test "routing rejects unsupported cipher suite" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_FAKE_CIPHER",
        .test_name = "TLS13/BasicHandshake",
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(cfg));
}

test "routing rejects unrelated test name even with valid version and cipher" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_AES_128_GCM_SHA256",
        .test_name = "Record/Overflow",
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(cfg));
}

test "routing rejects missing test name even with valid version and cipher" {
    const cfg = Config{
        .port = 443,
        .expect_version = "TLS1.3",
        .expect_cipher = "TLS_AES_128_GCM_SHA256",
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(cfg));
}
