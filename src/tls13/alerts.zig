const std = @import("std");

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    internal_error = 80,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

pub const Alert = struct {
    level: AlertLevel,
    description: AlertDescription,

    pub fn encode(self: Alert) [2]u8 {
        return .{ @intFromEnum(self.level), @intFromEnum(self.description) };
    }

    pub fn decode(bytes: []const u8) DecodeError!Alert {
        if (bytes.len != 2) return error.InvalidLength;

        const level = std.meta.intToEnum(AlertLevel, bytes[0]) catch return error.InvalidLevel;
        const description = std.meta.intToEnum(AlertDescription, bytes[1]) catch return error.InvalidDescription;

        return .{ .level = level, .description = description };
    }
};

pub const DecodeError = error{
    InvalidLength,
    InvalidLevel,
    InvalidDescription,
};

test "alert encode/decode roundtrip" {
    const alert: Alert = .{ .level = .fatal, .description = .unexpected_message };
    const enc = alert.encode();
    try std.testing.expectEqualSlices(u8, &.{ 2, 10 }, &enc);

    const dec = try Alert.decode(&enc);
    try std.testing.expectEqual(alert.level, dec.level);
    try std.testing.expectEqual(alert.description, dec.description);
}

test "alert decode validates length" {
    try std.testing.expectError(error.InvalidLength, Alert.decode(&.{1}));
}
