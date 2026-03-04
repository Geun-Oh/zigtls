const std = @import("std");

pub const tls13 = @import("quic/tls13.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");

test {
    _ = @import("quic/tls13.zig");
    _ = @import("quic/transport_parameters.zig");
}

test "public quic API stays TLS/crypto scoped" {
    try std.testing.expect(@hasDecl(@This(), "tls13"));
    try std.testing.expect(@hasDecl(@This(), "transport_parameters"));
    try std.testing.expect(!@hasDecl(@This(), "crypto_stream"));
    try std.testing.expect(!@hasDecl(@This(), "handshake_bridge"));
    try std.testing.expect(!@hasDecl(@This(), "packet"));
    try std.testing.expect(!@hasDecl(@This(), "transport"));
    try std.testing.expect(!@hasDecl(@This(), "session_udp"));
}
