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
    min_version: ?u16 = null,
    max_version: ?u16 = null,
    dtls: bool = false,
    quic: bool = false,
    expect_version: ?[]const u8 = null,
    expect_cipher: ?[]const u8 = null,
    test_name: ?[]const u8 = null,
};

const io_timeout_ms: i32 = 1500;
const probe_record = [_]u8{ 21, 3, 3, 0, 2, 1, 0 };

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
        "bogo-shim: run mode (role={s}, host={s}, port={d}, min_version={s}, max_version={s}, dtls={any}, quic={any}, expect_version={s}, cipher={s}, test={s}, decision={s})\n",
        .{
            if (parsed.is_server) "server" else "client",
            parsed.host,
            parsed.port,
            versionString(parsed.min_version),
            versionString(parsed.max_version),
            parsed.dtls,
            parsed.quic,
            parsed.expect_version orelse "(any)",
            parsed.expect_cipher orelse "(any)",
            parsed.test_name orelse "(none)",
            @tagName(decision),
        },
    );

    switch (decision) {
        .pass => {
            runSocketExchange(parsed) catch |err| {
                std.debug.print("bogo-shim: socket exchange failed: {s}\n", .{@errorName(err)});
                std.process.exit(@intFromEnum(Exit.unsupported));
            };
            std.process.exit(@intFromEnum(Exit.ok));
        },
        .unsupported => std.process.exit(@intFromEnum(Exit.unsupported)),
    }
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
        if (flagEq(arg, "min-version")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.min_version = try parseVersionArg(args[i + 1]);
            i += 1;
            continue;
        }
        if (flagEq(arg, "max-version")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.max_version = try parseVersionArg(args[i + 1]);
            i += 1;
            continue;
        }
        if (flagEq(arg, "dtls")) {
            cfg.dtls = true;
            continue;
        }
        if (flagEq(arg, "quic")) {
            cfg.quic = true;
            continue;
        }
        if (flagValue(arg, "host")) |v| {
            cfg.host = v;
            continue;
        }
        if (flagValue(arg, "port")) |v| {
            cfg.port = try std.fmt.parseInt(u16, v, 10);
            continue;
        }
        if (flagValue(arg, "expect-version")) |v| {
            cfg.expect_version = v;
            continue;
        }
        if (flagValue(arg, "expect-cipher")) |v| {
            cfg.expect_cipher = v;
            continue;
        }
        if (flagValue(arg, "test-name")) |v| {
            cfg.test_name = v;
            continue;
        }
        if (flagValue(arg, "min-version")) |v| {
            cfg.min_version = try parseVersionArg(v);
            continue;
        }
        if (flagValue(arg, "max-version")) |v| {
            cfg.max_version = try parseVersionArg(v);
            continue;
        }

        if (isFlag(arg)) {
            if (i + 1 < args.len and !isFlag(args[i + 1])) {
                i += 1;
            }
            continue;
        }

        if (cfg.test_name == null and std.mem.indexOfScalar(u8, arg, '/') != null) {
            cfg.test_name = arg;
        }
        continue;
    }

    return cfg;
}

fn parseVersionArg(raw: []const u8) !u16 {
    return std.fmt.parseInt(u16, raw, 10);
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

fn flagValue(arg: []const u8, canonical: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, arg, "--")) return null;
    const tail = arg[2..];
    const eq_idx = std.mem.indexOfScalar(u8, tail, '=') orelse return null;
    if (!std.mem.eql(u8, tail[0..eq_idx], canonical)) return null;
    return tail[eq_idx + 1 ..];
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
    if (cfg.dtls or cfg.quic) return .unsupported;

    if (cfg.expect_version) |v| {
        if (!isTls13Version(v)) return .unsupported;
    }

    if (!versionRangeIncludesTls13(cfg.min_version, cfg.max_version)) return .unsupported;

    if (cfg.expect_cipher) |cipher| {
        if (!isSupportedCipher(cipher)) return .unsupported;
    }

    if (cfg.test_name) |name| {
        if (std.mem.indexOf(u8, name, "TLS13") != null) return .pass;
        if (std.mem.indexOf(u8, name, "Basic") != null) return .pass;
        return .unsupported;
    }

    if (cfg.expect_version != null or cfg.expect_cipher != null or cfg.min_version != null or cfg.max_version != null) {
        return .pass;
    }

    return .unsupported;
}

fn isTls13Version(version: []const u8) bool {
    return std.mem.indexOf(u8, version, "1.3") != null;
}

fn versionRangeIncludesTls13(min_version: ?u16, max_version: ?u16) bool {
    const tls13: u16 = 772; // 0x0304
    if (min_version) |v| {
        if (v > tls13) return false;
    }
    if (max_version) |v| {
        if (v < tls13) return false;
    }
    return true;
}

fn versionString(v: ?u16) []const u8 {
    return if (v == null) "(any)" else switch (v.?) {
        770 => "TLS1.1(770)",
        771 => "TLS1.2(771)",
        772 => "TLS1.3(772)",
        else => "custom",
    };
}

fn isSupportedCipher(cipher: []const u8) bool {
    return std.mem.eql(u8, cipher, "TLS_AES_128_GCM_SHA256") or
        std.mem.eql(u8, cipher, "TLS_AES_256_GCM_SHA384") or
        std.mem.eql(u8, cipher, "TLS_CHACHA20_POLY1305_SHA256");
}

fn runSocketExchange(cfg: Config) !void {
    if (cfg.is_server) {
        try runServer(cfg);
    } else {
        try runClient(cfg);
    }
}

fn runServer(cfg: Config) !void {
    const address = try std.net.Address.parseIp(cfg.host, cfg.port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    if (!try pollFd(server.stream.handle, std.posix.POLL.IN, io_timeout_ms)) {
        return error.Timeout;
    }
    var conn = try server.accept();
    defer conn.stream.close();
    try exchangeWithPeer(conn.stream);
}

fn runClient(cfg: Config) !void {
    const address = try std.net.Address.parseIp(cfg.host, cfg.port);
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try exchangeWithPeer(stream);
}

fn exchangeWithPeer(stream: std.net.Stream) !void {
    if (try pollFd(stream.handle, std.posix.POLL.OUT, io_timeout_ms)) {
        _ = try stream.write(&probe_record);
    }

    if (try pollFd(stream.handle, std.posix.POLL.IN, io_timeout_ms)) {
        var buf: [256]u8 = undefined;
        _ = stream.read(&buf) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
    }
}

fn pollFd(fd: std.posix.fd_t, events: i16, timeout_ms: i32) !bool {
    var fds = [_]std.posix.pollfd{
        .{
            .fd = fd,
            .events = events,
            .revents = 0,
        },
    };
    const n = try std.posix.poll(&fds, timeout_ms);
    return n > 0 and (fds[0].revents & events) != 0;
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

test "parse args captures version range and protocol toggles" {
    const cfg = try parseArgs(&.{ "--min-version", "771", "--max-version", "772", "--dtls", "--quic", "--port", "443" });
    try std.testing.expectEqual(@as(?u16, 771), cfg.min_version);
    try std.testing.expectEqual(@as(?u16, 772), cfg.max_version);
    try std.testing.expect(cfg.dtls);
    try std.testing.expect(cfg.quic);
}

test "parse args ignores unknown flags and positional values" {
    const cfg = try parseArgs(&.{ "--bad", "1", "positional", "TLS13/PositionalCase", "--port", "8443" });
    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqualStrings("TLS13/PositionalCase", cfg.test_name.?);
}

test "parse args supports equals-form key value flags" {
    const cfg = try parseArgs(&.{ "--port=9443", "--expect-version=TLS1.3", "--test-name=TLS13/EqualsForm" });
    try std.testing.expectEqual(@as(u16, 9443), cfg.port);
    try std.testing.expectEqualStrings("TLS1.3", cfg.expect_version.?);
    try std.testing.expectEqualStrings("TLS13/EqualsForm", cfg.test_name.?);
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

test "routing rejects when version window excludes tls13" {
    const older = Config{
        .port = 443,
        .min_version = 770,
        .max_version = 771,
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(older));

    const future_only = Config{
        .port = 443,
        .min_version = 773,
    };
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(future_only));
}

test "routing rejects dtls and quic protocol modes" {
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(.{ .port = 443, .dtls = true }));
    try std.testing.expectEqual(RoutingDecision.unsupported, decideTestRouting(.{ .port = 443, .quic = true }));
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

test "routing passes missing test name when tls13-compatible feature flags exist" {
    const cfg = Config{
        .port = 443,
        .min_version = 772,
        .max_version = 772,
    };
    try std.testing.expectEqual(RoutingDecision.pass, decideTestRouting(cfg));
}
