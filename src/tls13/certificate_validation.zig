const std = @import("std");
const ocsp = @import("ocsp.zig");

pub const ValidationPolicy = struct {
    allow_expired: bool = false,
    allow_soft_fail_ocsp: bool = false,
};

pub const ExtendedKeyUsage = enum {
    server_auth,
    client_auth,
    code_signing,
    email_protection,
};

pub const KeyUsage = packed struct(u16) {
    digital_signature: bool = false,
    non_repudiation: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,
    _reserved: u7 = 0,
};

pub const CertificateView = struct {
    dns_name: []const u8,
    is_ca: bool,
    path_len_constraint: ?u8 = null,
    key_usage: KeyUsage = .{},
    ext_key_usages: []const ExtendedKeyUsage = &.{},
};

pub const ValidationError = error{
    EmptyServerName,
    HostnameMismatch,
    UnsupportedChainValidation,
    InvalidChain,
    IntermediateNotCa,
    PathLenExceeded,
    LeafMissingDigitalSignature,
    LeafMissingServerAuthEku,
} || ocsp.CheckError;

pub const PeerValidationInput = struct {
    expected_server_name: []const u8,
    chain: []const CertificateView,
    stapled_ocsp: ?ocsp.ResponseView = null,
    now_sec: i64,
    policy: ValidationPolicy = .{},
};

pub const PeerValidationResult = struct {
    ocsp_result: ocsp.ValidationResult,
};

pub fn validateServerName(expected_server_name: []const u8, cert_dns_name: []const u8) ValidationError!void {
    if (expected_server_name.len == 0) return error.EmptyServerName;

    if (!std.ascii.eqlIgnoreCase(expected_server_name, cert_dns_name)) {
        return error.HostnameMismatch;
    }
}

pub fn validateChainPlaceholder(_: ValidationPolicy) ValidationError!void {
    return error.UnsupportedChainValidation;
}

pub fn validateServerChain(chain: []const CertificateView) ValidationError!void {
    if (chain.len == 0) return error.InvalidChain;

    const leaf = chain[0];
    try validateLeafServerUsage(leaf);

    if (chain.len == 1) return;

    // `chain[1..]` are intermediates + optional root. Require CA bit for all.
    for (chain[1..], 0..) |cert, idx| {
        if (!cert.is_ca) return error.IntermediateNotCa;

        if (cert.path_len_constraint) |limit| {
            const below = (chain.len - 2) - idx;
            if (below > limit) return error.PathLenExceeded;
        }
    }
}

pub fn validateLeafServerUsage(leaf: CertificateView) ValidationError!void {
    if (!leaf.key_usage.digital_signature) return error.LeafMissingDigitalSignature;
    if (!hasEku(leaf.ext_key_usages, .server_auth)) return error.LeafMissingServerAuthEku;
}

pub fn validateStapledOcsp(
    response: ?ocsp.ResponseView,
    now_sec: i64,
    policy: ValidationPolicy,
) ValidationError!ocsp.ValidationResult {
    return try ocsp.checkStapled(response, now_sec, policy.allow_soft_fail_ocsp);
}

pub fn validateServerPeer(input: PeerValidationInput) ValidationError!PeerValidationResult {
    try validateServerChain(input.chain);
    try validateServerName(input.expected_server_name, input.chain[0].dns_name);
    const ocsp_result = try validateStapledOcsp(input.stapled_ocsp, input.now_sec, input.policy);
    return .{ .ocsp_result = ocsp_result };
}

fn hasEku(usages: []const ExtendedKeyUsage, target: ExtendedKeyUsage) bool {
    for (usages) |usage| {
        if (usage == target) return true;
    }
    return false;
}

test "server name validation ignores case" {
    try validateServerName("example.com", "EXAMPLE.COM");
}

test "server name mismatch fails" {
    try std.testing.expectError(error.HostnameMismatch, validateServerName("example.com", "api.example.com"));
}

test "server chain validation happy path" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Intermediate CA",
            .is_ca = true,
            .path_len_constraint = 1,
            .key_usage = .{ .key_cert_sign = true },
        },
        .{
            .dns_name = "Root CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        },
    };

    try validateServerChain(&chain);
}

test "server chain rejects non-ca intermediate" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "bad intermediate",
            .is_ca = false,
        },
    };

    try std.testing.expectError(error.IntermediateNotCa, validateServerChain(&chain));
}

test "server chain rejects missing server eku" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.client_auth},
        },
    };

    try std.testing.expectError(error.LeafMissingServerAuthEku, validateServerChain(&chain));
}

test "ocsp policy delegates hard/soft fail behavior" {
    const now: i64 = 1_700_000_000;

    const soft = try validateStapledOcsp(null, now, .{ .allow_soft_fail_ocsp = true });
    try std.testing.expectEqual(ocsp.ValidationResult.soft_fail, soft);

    try std.testing.expectError(error.MissingResponse, validateStapledOcsp(null, now, .{ .allow_soft_fail_ocsp = false }));
}

test "integrated peer validator passes on valid inputs" {
    const now: i64 = 1_700_000_000;
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Root",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        },
    };

    const res = try validateServerPeer(.{
        .expected_server_name = "example.com",
        .chain = &chain,
        .stapled_ocsp = .{
            .status = .good,
            .produced_at = now - 60,
            .this_update = now - 60,
            .next_update = now + 3600,
        },
        .now_sec = now,
    });
    try std.testing.expectEqual(ocsp.ValidationResult.accepted, res.ocsp_result);
}

test "integrated peer validator propagates hostname failure" {
    const now: i64 = 1_700_000_000;
    const chain = [_]CertificateView{
        .{
            .dns_name = "api.example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
    };

    try std.testing.expectError(error.HostnameMismatch, validateServerPeer(.{
        .expected_server_name = "example.com",
        .chain = &chain,
        .stapled_ocsp = null,
        .now_sec = now,
        .policy = .{ .allow_soft_fail_ocsp = true },
    }));
}
