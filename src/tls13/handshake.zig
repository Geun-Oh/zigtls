const std = @import("std");
const state = @import("state.zig");

pub const HandshakeType = state.HandshakeType;
pub const HandshakeEvent = state.HandshakeEvent;

pub const max_handshake_bytes: usize = 64 * 1024;
pub const hello_retry_request_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

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

pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
};

pub const KeyUpdateError = error{
    InvalidLength,
    InvalidRequest,
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

pub fn classifyEvent(parsed: ParsedHandshake) HandshakeEvent {
    if (parsed.header.handshake_type == .server_hello and isHelloRetryRequest(parsed.body)) {
        return .hello_retry_request;
    }
    return state.fromHandshakeType(parsed.header.handshake_type);
}

pub fn parseKeyUpdateRequest(body: []const u8) KeyUpdateError!KeyUpdateRequest {
    if (body.len != 1) return error.InvalidLength;
    return std.meta.intToEnum(KeyUpdateRequest, body[0]) catch return error.InvalidRequest;
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

fn isHelloRetryRequest(body: []const u8) bool {
    // ServerHello body starts with legacy_version(2) then random(32).
    if (body.len < 34) return false;
    return std.mem.eql(u8, body[2..34], &hello_retry_request_random);
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

test "classify hello retry request from server hello random marker" {
    var body: [34]u8 = undefined;
    body[0] = 0x03;
    body[1] = 0x03;
    @memcpy(body[2..34], &hello_retry_request_random);

    const parsed: ParsedHandshake = .{
        .header = .{ .handshake_type = .server_hello, .length = 34 },
        .body = &body,
        .rest = "",
    };
    try std.testing.expectEqual(HandshakeEvent.hello_retry_request, classifyEvent(parsed));
}

test "parse keyupdate request value" {
    const parsed = try parseKeyUpdateRequest(&.{1});
    try std.testing.expectEqual(KeyUpdateRequest.update_requested, parsed);
    try std.testing.expectError(error.InvalidLength, parseKeyUpdateRequest(&.{}));
}
