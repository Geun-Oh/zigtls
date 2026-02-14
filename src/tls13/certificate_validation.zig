const std = @import("std");

pub const ValidationPolicy = struct {
    allow_expired: bool = false,
    allow_soft_fail_ocsp: bool = false,
};

pub const ValidationError = error{
    EmptyServerName,
    HostnameMismatch,
    UnsupportedChainValidation,
};

pub fn validateServerName(expected_server_name: []const u8, cert_dns_name: []const u8) ValidationError!void {
    if (expected_server_name.len == 0) return error.EmptyServerName;

    if (!std.ascii.eqlIgnoreCase(expected_server_name, cert_dns_name)) {
        return error.HostnameMismatch;
    }
}

pub fn validateChainPlaceholder(_: ValidationPolicy) ValidationError!void {
    // RFC 5280-complete chain validation is intentionally left as a dedicated
    // phase because it requires full path building, KU/EKU checks, name
    // constraints, and trust-anchor integration.
    return error.UnsupportedChainValidation;
}

test "server name validation ignores case" {
    try validateServerName("example.com", "EXAMPLE.COM");
}

test "server name mismatch fails" {
    try std.testing.expectError(error.HostnameMismatch, validateServerName("example.com", "api.example.com"));
}
