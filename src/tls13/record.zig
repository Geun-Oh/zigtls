const std = @import("std");

pub const tls_legacy_record_version: u16 = 0x0303;
pub const max_plaintext: usize = 16 * 1024;
pub const max_ciphertext_overhead: usize = 256;
pub const max_ciphertext: usize = max_plaintext + max_ciphertext_overhead;

pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

fn isAcceptedLegacyRecordVersion(version: u16) bool {
    return version >= 0x0301 and version <= tls_legacy_record_version;
}

pub const Header = struct {
    content_type: ContentType,
    legacy_version: u16,
    length: u16,

    pub fn encode(self: Header) [5]u8 {
        var out: [5]u8 = undefined;
        out[0] = @intFromEnum(self.content_type);
        std.mem.writeInt(u16, out[1..3], self.legacy_version, .big);
        std.mem.writeInt(u16, out[3..5], self.length, .big);
        return out;
    }
};

pub const ParsedRecord = struct {
    header: Header,
    payload: []const u8,
    rest: []const u8,
};

pub const ParseError = error{
    IncompleteHeader,
    InvalidContentType,
    InvalidLegacyVersion,
    RecordOverflow,
    IncompletePayload,
};

pub fn parseHeader(buf: []const u8) ParseError!Header {
    if (buf.len < 5) return error.IncompleteHeader;

    const content_type = std.meta.intToEnum(ContentType, buf[0]) catch return error.InvalidContentType;
    const legacy_version = std.mem.readInt(u16, buf[1..3], .big);
    if (!isAcceptedLegacyRecordVersion(legacy_version)) return error.InvalidLegacyVersion;

    const len = std.mem.readInt(u16, buf[3..5], .big);
    if (len > max_ciphertext) return error.RecordOverflow;

    return .{
        .content_type = content_type,
        .legacy_version = legacy_version,
        .length = len,
    };
}

pub fn parseRecord(buf: []const u8) ParseError!ParsedRecord {
    const header = try parseHeader(buf);
    const needed = 5 + @as(usize, header.length);
    if (buf.len < needed) return error.IncompletePayload;

    return .{
        .header = header,
        .payload = buf[5..needed],
        .rest = buf[needed..],
    };
}

test "parse record header and payload" {
    const payload = "abc";
    const hdr: Header = .{
        .content_type = .handshake,
        .legacy_version = tls_legacy_record_version,
        .length = payload.len,
    };

    const encoded = hdr.encode();
    var frame: [8]u8 = undefined;
    @memcpy(frame[0..5], &encoded);
    @memcpy(frame[5..8], payload);

    const parsed = try parseRecord(&frame);
    try std.testing.expectEqual(ContentType.handshake, parsed.header.content_type);
    try std.testing.expectEqualSlices(u8, payload, parsed.payload);
    try std.testing.expectEqual(@as(usize, 0), parsed.rest.len);
}

test "record parser rejects invalid legacy version" {
    const buf = [_]u8{ @intFromEnum(ContentType.handshake), 0x03, 0x04, 0x00, 0x00 };
    try std.testing.expectError(error.InvalidLegacyVersion, parseRecord(&buf));
}

test "record parser accepts tls10 legacy version for interoperability" {
    const buf = [_]u8{ @intFromEnum(ContentType.handshake), 0x03, 0x01, 0x00, 0x00 };
    const parsed = try parseRecord(&buf);
    try std.testing.expectEqual(@as(u16, 0x0301), parsed.header.legacy_version);
}

test "record parser rejects overflow length" {
    const buf = [_]u8{ @intFromEnum(ContentType.handshake), 0x03, 0x03, 0x50, 0x01 };
    try std.testing.expectError(error.RecordOverflow, parseRecord(&buf));
}
