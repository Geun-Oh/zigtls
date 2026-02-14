const std = @import("std");
const ocsp = @import("ocsp.zig");

pub const ValidationPolicy = struct {
    allow_expired: bool = false,
    allow_soft_fail_ocsp: bool = false,
};

pub const max_chain_depth: usize = 8;

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
    permitted_dns_suffixes: []const []const u8 = &.{},
    excluded_dns_suffixes: []const []const u8 = &.{},
};

pub const ValidationError = error{
    EmptyServerName,
    HostnameMismatch,
    UnsupportedChainValidation,
    InvalidChain,
    ChainTooLong,
    LeafMustNotBeCa,
    IntermediateNotCa,
    IntermediateMissingKeyCertSign,
    PathLenExceeded,
    NameConstraintsViolation,
    LeafMissingDigitalSignature,
    LeafMissingServerAuthEku,
    LeafMissingClientAuthEku,
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

    if (!dnsNameMatchesServerName(expected_server_name, cert_dns_name)) {
        return error.HostnameMismatch;
    }
}

pub fn validateChainPlaceholder(_: ValidationPolicy) ValidationError!void {
    return error.UnsupportedChainValidation;
}

pub fn validateServerChain(chain: []const CertificateView) ValidationError!void {
    if (chain.len == 0) return error.InvalidChain;
    if (chain.len > max_chain_depth) return error.ChainTooLong;

    const leaf = chain[0];
    if (leaf.is_ca) return error.LeafMustNotBeCa;
    try validateLeafServerUsage(leaf);
    try validateCaPathAndNameConstraints(chain);
}

pub fn validateClientChain(chain: []const CertificateView) ValidationError!void {
    if (chain.len == 0) return error.InvalidChain;
    if (chain.len > max_chain_depth) return error.ChainTooLong;

    const leaf = chain[0];
    if (leaf.is_ca) return error.LeafMustNotBeCa;
    try validateLeafClientUsage(leaf);
    try validateCaPathAndNameConstraints(chain);
}

fn validateCaPathAndNameConstraints(chain: []const CertificateView) ValidationError!void {
    const leaf = chain[0];
    if (leaf.dns_name.len > 0) {
        try validateNameConstraints(leaf.dns_name, chain[1..]);
    }

    if (chain.len == 1) return;

    // `chain[1..]` are intermediates + optional root. Require CA bit for all.
    for (chain[1..], 0..) |cert, idx| {
        if (!cert.is_ca) return error.IntermediateNotCa;
        if (!cert.key_usage.key_cert_sign) return error.IntermediateMissingKeyCertSign;

        if (cert.path_len_constraint) |limit| {
            const below = (chain.len - 2) - idx;
            if (below > limit) return error.PathLenExceeded;
        }
    }
}

fn validateNameConstraints(leaf_dns_name: []const u8, cas: []const CertificateView) ValidationError!void {
    for (cas) |ca| {
        for (ca.excluded_dns_suffixes) |excluded| {
            if (dnsMatchesConstraint(leaf_dns_name, excluded)) {
                return error.NameConstraintsViolation;
            }
        }

        if (ca.permitted_dns_suffixes.len > 0) {
            var match = false;
            for (ca.permitted_dns_suffixes) |permitted| {
                if (dnsMatchesConstraint(leaf_dns_name, permitted)) {
                    match = true;
                    break;
                }
            }
            if (!match) return error.NameConstraintsViolation;
        }
    }
}

pub fn validateLeafServerUsage(leaf: CertificateView) ValidationError!void {
    if (!leaf.key_usage.digital_signature) return error.LeafMissingDigitalSignature;
    if (!hasEku(leaf.ext_key_usages, .server_auth)) return error.LeafMissingServerAuthEku;
}

pub fn validateLeafClientUsage(leaf: CertificateView) ValidationError!void {
    if (!leaf.key_usage.digital_signature) return error.LeafMissingDigitalSignature;
    if (!hasEku(leaf.ext_key_usages, .client_auth)) return error.LeafMissingClientAuthEku;
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

fn dnsNameMatchesServerName(expected_raw: []const u8, cert_raw: []const u8) bool {
    const expected = trimTrailingDot(expected_raw);
    const cert = trimTrailingDot(cert_raw);
    if (expected.len == 0 or cert.len == 0) return false;

    if (std.ascii.eqlIgnoreCase(expected, cert)) return true;

    if (!(cert.len >= 3 and cert[0] == '*' and cert[1] == '.')) return false;
    if (std.mem.indexOfScalar(u8, cert[1..], '*') != null) return false;

    const suffix = cert[1..]; // ".example.com"
    if (expected.len <= suffix.len) return false;
    const suffix_start = expected.len - suffix.len;
    if (!std.ascii.eqlIgnoreCase(expected[suffix_start..], suffix)) return false;
    if (std.mem.indexOfScalar(u8, expected[0..suffix_start], '.') != null) return false; // wildcard must match exactly one label

    return true;
}

fn dnsMatchesConstraint(hostname_raw: []const u8, constraint_raw: []const u8) bool {
    const hostname = trimTrailingDot(hostname_raw);
    var constraint = trimTrailingDot(constraint_raw);
    if (constraint.len == 0) return false;
    if (constraint[0] == '.') {
        constraint = constraint[1..];
        if (constraint.len == 0) return false;
    }

    if (std.ascii.eqlIgnoreCase(hostname, constraint)) return true;
    if (hostname.len <= constraint.len) return false;

    const suffix_start = hostname.len - constraint.len;
    if (!std.ascii.eqlIgnoreCase(hostname[suffix_start..], constraint)) return false;
    return hostname[suffix_start - 1] == '.';
}

fn trimTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') {
        return name[0 .. name.len - 1];
    }
    return name;
}

test "server name validation ignores case" {
    try validateServerName("example.com", "EXAMPLE.COM");
}

test "server name mismatch fails" {
    try std.testing.expectError(error.HostnameMismatch, validateServerName("example.com", "api.example.com"));
}

test "server name wildcard matches single label" {
    try validateServerName("api.example.com", "*.example.com");
}

test "server name wildcard does not match apex" {
    try std.testing.expectError(error.HostnameMismatch, validateServerName("example.com", "*.example.com"));
}

test "server name wildcard does not match multiple labels" {
    try std.testing.expectError(error.HostnameMismatch, validateServerName("a.b.example.com", "*.example.com"));
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

test "server chain rejects ca-marked leaf" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = true,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Root CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        },
    };

    try std.testing.expectError(error.LeafMustNotBeCa, validateServerChain(&chain));
}

test "server chain rejects ca without keyCertSign usage" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "intermediate missing keyCertSign",
            .is_ca = true,
            .key_usage = .{},
        },
    };

    try std.testing.expectError(error.IntermediateMissingKeyCertSign, validateServerChain(&chain));
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

test "server chain rejects excessive chain depth" {
    var chain: [max_chain_depth + 1]CertificateView = undefined;
    chain[0] = .{
        .dns_name = "example.com",
        .is_ca = false,
        .key_usage = .{ .digital_signature = true },
        .ext_key_usages = &.{.server_auth},
    };
    for (chain[1..]) |*cert| {
        cert.* = .{
            .dns_name = "CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        };
    }

    try std.testing.expectError(error.ChainTooLong, validateServerChain(&chain));
}

test "name constraints allow permitted dns subtree" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "api.example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Constrained CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
            .permitted_dns_suffixes = &.{"example.com"},
        },
    };

    try validateServerChain(&chain);
}

test "name constraints reject dns outside permitted subtree" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "api.other.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Constrained CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
            .permitted_dns_suffixes = &.{"example.com"},
        },
    };

    try std.testing.expectError(error.NameConstraintsViolation, validateServerChain(&chain));
}

test "name constraints reject excluded dns subtree" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "dev.example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Constrained CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
            .permitted_dns_suffixes = &.{"example.com"},
            .excluded_dns_suffixes = &.{"dev.example.com"},
        },
    };

    try std.testing.expectError(error.NameConstraintsViolation, validateServerChain(&chain));
}

test "name constraints require match across constrained issuers" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "api.example.com",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
        .{
            .dns_name = "Intermediate CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
            .permitted_dns_suffixes = &.{"api.example.com"},
        },
        .{
            .dns_name = "Policy Root",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
            .permitted_dns_suffixes = &.{"example.com"},
        },
    };

    try validateServerChain(&chain);
}

test "client chain validation happy path" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.client_auth},
        },
        .{
            .dns_name = "Client Issuer",
            .is_ca = true,
            .path_len_constraint = 0,
            .key_usage = .{ .key_cert_sign = true },
        },
    };

    try validateClientChain(&chain);
}

test "client chain rejects missing client auth eku" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "",
            .is_ca = false,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.server_auth},
        },
    };

    try std.testing.expectError(error.LeafMissingClientAuthEku, validateClientChain(&chain));
}

test "client chain rejects ca-marked leaf" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "",
            .is_ca = true,
            .key_usage = .{ .digital_signature = true },
            .ext_key_usages = &.{.client_auth},
        },
        .{
            .dns_name = "Client Issuer",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        },
    };

    try std.testing.expectError(error.LeafMustNotBeCa, validateClientChain(&chain));
}

test "client chain rejects missing digital signature usage" {
    const chain = [_]CertificateView{
        .{
            .dns_name = "",
            .is_ca = false,
            .key_usage = .{},
            .ext_key_usages = &.{.client_auth},
        },
    };

    try std.testing.expectError(error.LeafMissingDigitalSignature, validateClientChain(&chain));
}

test "client chain rejects excessive chain depth" {
    var chain: [max_chain_depth + 1]CertificateView = undefined;
    chain[0] = .{
        .dns_name = "",
        .is_ca = false,
        .key_usage = .{ .digital_signature = true },
        .ext_key_usages = &.{.client_auth},
    };
    for (chain[1..]) |*cert| {
        cert.* = .{
            .dns_name = "CA",
            .is_ca = true,
            .key_usage = .{ .key_cert_sign = true },
        };
    }

    try std.testing.expectError(error.ChainTooLong, validateClientChain(&chain));
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

test "integrated peer validator default policy hard-fails missing ocsp" {
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

    try std.testing.expectError(error.MissingResponse, validateServerPeer(.{
        .expected_server_name = "example.com",
        .chain = &chain,
        .stapled_ocsp = null,
        .now_sec = now,
    }));
}
