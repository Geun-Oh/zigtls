//! zigtls library root.
const std = @import("std");

pub const tls13 = @import("tls13.zig");

pub fn version() []const u8 {
    return "0.1.0-dev";
}

test "library root is wired" {
    try std.testing.expect(version().len > 0);
}
