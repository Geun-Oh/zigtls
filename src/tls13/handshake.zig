const std = @import("std");
const state = @import("state.zig");

pub const HandshakeType = state.HandshakeType;

pub const max_handshake_bytes: usize = 64 * 1024;

pub const Header = struct {
    handshake_type: HandshakeType,
    length: u24,
};

pub const ParsedHandshake = struct {
    header: Header,
    body: []const u8,
    rest: []const u8,
};

pub const ParseError = error{
    IncompleteHeader,
    InvalidHandshakeType,
    MessageTooLarge,
    IncompleteBody,
};

pub fn parseHeader(bytes: []const u8) ParseError!Header {
    if (bytes.len < 4) return error.IncompleteHeader;

    const handshake_type = std.meta.intToEnum(HandshakeType, bytes[0]) catch return error.InvalidHandshakeType;
    const len = readU24(bytes[1..4]);
    if (len > max_handshake_bytes) return error.MessageTooLarge;

    return .{
        .handshake_type = handshake_type,
        .length = len,
    };
}

pub fn parseOne(bytes: []const u8) ParseError!ParsedHandshake {
    const header = try parseHeader(bytes);
    const len: usize = @intCast(header.length);
    const total = 4 + len;
    if (bytes.len < total) return error.IncompleteBody;

    return .{
        .header = header,
        .body = bytes[4..total],
        .rest = bytes[total..],
    };
}

pub const TranscriptSha256 = struct {
    hasher: std.crypto.hash.sha2.Sha256,

    pub fn init() TranscriptSha256 {
        return .{ .hasher = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    pub fn update(self: *TranscriptSha256, bytes: []const u8) void {
        self.hasher.update(bytes);
    }

    pub fn final(self: *TranscriptSha256) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        var copy = self.hasher;
        copy.final(&out);
        return out;
    }
};

fn readU24(bytes: []const u8) u24 {
    return (@as(u24, bytes[0]) << 16) | (@as(u24, bytes[1]) << 8) | @as(u24, bytes[2]);
}

pub fn writeU24(value: u24) [3]u8 {
    return .{
        @intCast((value >> 16) & 0xff),
        @intCast((value >> 8) & 0xff),
        @intCast(value & 0xff),
    };
}

test "parse handshake frame" {
    var msg: [7]u8 = undefined;
    msg[0] = @intFromEnum(HandshakeType.server_hello);
    const len = writeU24(3);
    @memcpy(msg[1..4], &len);
    @memcpy(msg[4..7], "hey");

    const parsed = try parseOne(&msg);
    try std.testing.expectEqual(HandshakeType.server_hello, parsed.header.handshake_type);
    try std.testing.expectEqual(@as(u24, 3), parsed.header.length);
    try std.testing.expectEqualSlices(u8, "hey", parsed.body);
}

test "message too large is rejected" {
    const bytes = [_]u8{ @intFromEnum(HandshakeType.server_hello), 0x01, 0x00, 0x01 };
    try std.testing.expectError(error.MessageTooLarge, parseOne(&bytes));
}

test "sha256 transcript is deterministic" {
    var t = TranscriptSha256.init();
    t.update("abc");
    const digest = t.final();

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
