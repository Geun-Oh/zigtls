const std = @import("std");
const tls13 = @import("zigtls").tls13;
const record = tls13.record;
const handshake = tls13.handshake;
const session = tls13.session;

const Exit = enum(u8) {
    ok = 0,
    usage = 2,
    io = 3,
};

const Mode = enum {
    record,
    handshake,
    session,
};

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_impl.deinit();
    const gpa = gpa_impl.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len != 3) {
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    }

    const mode = parseMode(args[1]) orelse {
        usage();
        std.process.exit(@intFromEnum(Exit.usage));
    };

    const bytes = std.fs.cwd().readFileAlloc(gpa, args[2], 1024 * 1024) catch {
        std.process.exit(@intFromEnum(Exit.io));
    };
    defer gpa.free(bytes);

    replay(mode, bytes);
}

fn usage() void {
    std.debug.print("usage: corpus-replay <record|handshake|session> <file>\n", .{});
}

fn parseMode(raw: []const u8) ?Mode {
    if (std.mem.eql(u8, raw, "record")) return .record;
    if (std.mem.eql(u8, raw, "handshake")) return .handshake;
    if (std.mem.eql(u8, raw, "session")) return .session;
    return null;
}

fn replay(mode: Mode, bytes: []const u8) void {
    switch (mode) {
        .record => {
            _ = record.parseRecord(bytes) catch {};
        },
        .handshake => {
            _ = handshake.parseOne(bytes) catch {};
        },
        .session => {
            var engine = session.Engine.init(std.heap.page_allocator, .{
                .role = .client,
                .suite = .tls_aes_128_gcm_sha256,
            });
            defer engine.deinit();
            _ = engine.ingestRecord(bytes) catch {};
        },
    }
}

test "parse mode supports known buckets" {
    try std.testing.expectEqual(Mode.record, parseMode("record").?);
    try std.testing.expectEqual(Mode.handshake, parseMode("handshake").?);
    try std.testing.expectEqual(Mode.session, parseMode("session").?);
    try std.testing.expect(parseMode("unknown") == null);
}

test "replay accepts malformed bytes without crashing" {
    const bad = [_]u8{ 0xff, 0x00, 0x01 };
    replay(.record, &bad);
    replay(.handshake, &bad);
    replay(.session, &bad);
}
