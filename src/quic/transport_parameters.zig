const std = @import("std");

pub const Entry = struct {
    id: u64,
    value: []const u8,
};

pub const OwnedEntries = struct {
    entries: []Entry,

    pub fn deinit(self: *OwnedEntries, allocator: std.mem.Allocator) void {
        for (self.entries) |entry| {
            allocator.free(@constCast(entry.value));
        }
        allocator.free(self.entries);
        self.entries = &.{};
    }
};

pub const VarIntError = error{
    Truncated,
    NonCanonical,
    TooLarge,
};

pub const DecodeError = error{
    DuplicateParameterId,
    LengthOverflow,
} || VarIntError || std.mem.Allocator.Error;

pub const EncodeError = error{
    DuplicateParameterId,
} || VarIntError || std.mem.Allocator.Error;

const DecodedVarInt = struct {
    value: u64,
    consumed: usize,
};

pub fn decode(
    allocator: std.mem.Allocator,
    payload: []const u8,
) DecodeError!OwnedEntries {
    var list = std.ArrayList(Entry).empty;
    defer {
        for (list.items) |entry| allocator.free(@constCast(entry.value));
        list.deinit(allocator);
    }

    var cursor: usize = 0;
    while (cursor < payload.len) {
        const id_dec = try decodeVarInt(payload[cursor..]);
        cursor += id_dec.consumed;

        const len_dec = try decodeVarInt(payload[cursor..]);
        cursor += len_dec.consumed;

        if (len_dec.value > std.math.maxInt(usize)) return error.LengthOverflow;
        const value_len: usize = @intCast(len_dec.value);
        if (cursor + value_len > payload.len) return error.Truncated;

        if (containsId(list.items, id_dec.value)) return error.DuplicateParameterId;

        const copied = try allocator.dupe(u8, payload[cursor .. cursor + value_len]);
        try list.append(allocator, .{
            .id = id_dec.value,
            .value = copied,
        });
        cursor += value_len;
    }

    return .{
        .entries = try list.toOwnedSlice(allocator),
    };
}

pub fn encode(
    allocator: std.mem.Allocator,
    entries: []const Entry,
) EncodeError![]u8 {
    if (hasDuplicateIds(entries)) return error.DuplicateParameterId;

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    for (entries) |entry| {
        try writeVarInt(allocator, &out, entry.id);
        try writeVarInt(allocator, &out, entry.value.len);
        try out.appendSlice(allocator, entry.value);
    }

    return out.toOwnedSlice(allocator);
}

pub fn find(entries: []const Entry, id: u64) ?[]const u8 {
    for (entries) |entry| {
        if (entry.id == id) return entry.value;
    }
    return null;
}

fn containsId(entries: []const Entry, id: u64) bool {
    for (entries) |entry| {
        if (entry.id == id) return true;
    }
    return false;
}

fn hasDuplicateIds(entries: []const Entry) bool {
    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < entries.len) : (j += 1) {
            if (entries[i].id == entries[j].id) return true;
        }
    }
    return false;
}

fn decodeVarInt(bytes: []const u8) VarIntError!DecodedVarInt {
    if (bytes.len == 0) return error.Truncated;

    const prefix = bytes[0] >> 6;
    const len: usize = switch (prefix) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };

    if (bytes.len < len) return error.Truncated;

    var value: u64 = bytes[0] & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) {
        value = (value << 8) | bytes[i];
    }

    if (try encodedLen(value) != len) return error.NonCanonical;

    return .{
        .value = value,
        .consumed = len,
    };
}

fn writeVarInt(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    value: u64,
) (VarIntError || std.mem.Allocator.Error)!void {
    const len = try encodedLen(value);

    switch (len) {
        1 => {
            try out.append(allocator, @as(u8, @intCast(value & 0x3f)));
        },
        2 => {
            try out.append(allocator, 0x40 | @as(u8, @intCast((value >> 8) & 0x3f)));
            try out.append(allocator, @as(u8, @intCast(value & 0xff)));
        },
        4 => {
            try out.append(allocator, 0x80 | @as(u8, @intCast((value >> 24) & 0x3f)));
            try out.append(allocator, @as(u8, @intCast((value >> 16) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 8) & 0xff)));
            try out.append(allocator, @as(u8, @intCast(value & 0xff)));
        },
        8 => {
            try out.append(allocator, 0xc0 | @as(u8, @intCast((value >> 56) & 0x3f)));
            try out.append(allocator, @as(u8, @intCast((value >> 48) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 40) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 32) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 24) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 16) & 0xff)));
            try out.append(allocator, @as(u8, @intCast((value >> 8) & 0xff)));
            try out.append(allocator, @as(u8, @intCast(value & 0xff)));
        },
        else => unreachable,
    }
}

fn encodedLen(value: u64) VarIntError!usize {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    if (value <= 4_611_686_018_427_387_903) return 8;
    return error.TooLarge;
}

test "encode decode roundtrip with multiple entries" {
    const entries = [_]Entry{
        .{ .id = 0x04, .value = "\x00\x10" },
        .{ .id = 0x08, .value = "\x10\x20\x30" },
    };

    const encoded = try encode(std.testing.allocator, &entries);
    defer std.testing.allocator.free(encoded);

    var decoded = try decode(std.testing.allocator, encoded);
    defer decoded.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), decoded.entries.len);
    try std.testing.expectEqual(@as(u64, 0x04), decoded.entries[0].id);
    try std.testing.expectEqualStrings("\x00\x10", decoded.entries[0].value);
    try std.testing.expectEqual(@as(u64, 0x08), decoded.entries[1].id);
    try std.testing.expectEqualStrings("\x10\x20\x30", decoded.entries[1].value);
}

test "decode rejects duplicate parameter id" {
    const payload = [_]u8{
        0x04, 0x01, 0xaa,
        0x04, 0x01, 0xbb,
    };
    try std.testing.expectError(error.DuplicateParameterId, decode(std.testing.allocator, &payload));
}

test "decode rejects truncated value" {
    const payload = [_]u8{
        0x04,
        0x02,
        0xaa,
    };
    try std.testing.expectError(error.Truncated, decode(std.testing.allocator, &payload));
}

test "decode rejects non-canonical varint" {
    const payload = [_]u8{
        0x40,
        0x01,
        0x00,
        0x00,
    };
    try std.testing.expectError(error.NonCanonical, decode(std.testing.allocator, &payload));
}

test "encode rejects duplicate parameter id" {
    const entries = [_]Entry{
        .{ .id = 0x04, .value = "a" },
        .{ .id = 0x04, .value = "b" },
    };
    try std.testing.expectError(error.DuplicateParameterId, encode(std.testing.allocator, &entries));
}

test "find returns parameter value by id" {
    const entries = [_]Entry{
        .{ .id = 0x01, .value = "x" },
        .{ .id = 0x09, .value = "\x11\x22" },
    };

    const found = find(&entries, 0x09) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("\x11\x22", found);
    try std.testing.expect(find(&entries, 0xff) == null);
}

test "encode rejects varint above QUIC maximum" {
    const entries = [_]Entry{
        .{ .id = 4_611_686_018_427_387_904, .value = "x" },
    };
    try std.testing.expectError(error.TooLarge, encode(std.testing.allocator, &entries));
}
