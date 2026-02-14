const std = @import("std");
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const session = @import("session.zig");

fn fillRandom(bytes: []u8, rnd: std.Random) void {
    rnd.bytes(bytes);
}

test "record parser fuzz-style random inputs do not crash" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeefcafebabe);
    const rnd = prng.random();

    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const len = rnd.intRangeAtMost(usize, 0, buf.len);
        fillRandom(buf[0..len], rnd);
        _ = record.parseRecord(buf[0..len]) catch {};
    }
}

test "handshake parser fuzz-style random inputs do not crash" {
    var prng = std.Random.DefaultPrng.init(0x1122334455667788);
    const rnd = prng.random();

    var buf: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 5_000) : (i += 1) {
        const len = rnd.intRangeAtMost(usize, 0, buf.len);
        fillRandom(buf[0..len], rnd);
        _ = handshake.parseOne(buf[0..len]) catch {};
    }
}

test "session ingest fuzz-style random records do not crash" {
    var engine = session.Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    var prng = std.Random.DefaultPrng.init(0x99aabbccddeeff01);
    const rnd = prng.random();

    var buf: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 3_000) : (i += 1) {
        const len = rnd.intRangeAtMost(usize, 0, buf.len);
        fillRandom(buf[0..len], rnd);
        _ = engine.ingestRecord(buf[0..len]) catch {};
    }
}
