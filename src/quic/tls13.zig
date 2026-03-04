const std = @import("std");
const keyschedule = @import("../tls13/keyschedule.zig");

pub const initial_salt_v1 = [20]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5,
    0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const Perspective = enum {
    client,
    server,
};

pub const InitialSecrets = struct {
    client: [32]u8,
    server: [32]u8,
};

pub const TrafficSecret = union(enum) {
    sha256: [32]u8,
    sha384: [48]u8,
};

pub const PacketProtectionKeys = struct {
    key: [32]u8 = [_]u8{0} ** 32,
    iv: [12]u8 = [_]u8{0} ** 12,
    hp: [32]u8 = [_]u8{0} ** 32,
    key_len: usize,
    hp_len: usize,
};

pub const DeriveError = error{
    SecretSuiteMismatch,
};

pub const SecretDecodeError = error{
    InvalidSecretLength,
};

pub fn deriveInitialSecrets(destination_connection_id: []const u8) InitialSecrets {
    var initial_secret = keyschedule.extract(
        .tls_aes_128_gcm_sha256,
        &initial_salt_v1,
        destination_connection_id,
    );
    defer std.crypto.secureZero(u8, initial_secret[0..]);

    return .{
        .client = keyschedule.deriveLabel(
            .tls_aes_128_gcm_sha256,
            initial_secret,
            "client in",
            "",
            32,
        ),
        .server = keyschedule.deriveLabel(
            .tls_aes_128_gcm_sha256,
            initial_secret,
            "server in",
            "",
            32,
        ),
    };
}

pub fn deriveInitialSecretForPerspective(
    destination_connection_id: []const u8,
    perspective: Perspective,
) [32]u8 {
    const pair = deriveInitialSecrets(destination_connection_id);
    return switch (perspective) {
        .client => pair.client,
        .server => pair.server,
    };
}

pub fn deriveInitialTrafficSecret(
    destination_connection_id: []const u8,
    perspective: Perspective,
) TrafficSecret {
    return .{
        .sha256 = deriveInitialSecretForPerspective(destination_connection_id, perspective),
    };
}

pub fn trafficSecretFromBytes(
    suite: keyschedule.CipherSuite,
    secret_bytes: []const u8,
) SecretDecodeError!TrafficSecret {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => blk: {
            if (secret_bytes.len != 32) return error.InvalidSecretLength;
            var out: [32]u8 = undefined;
            @memcpy(out[0..], secret_bytes);
            break :blk .{ .sha256 = out };
        },
        .tls_aes_256_gcm_sha384 => blk: {
            if (secret_bytes.len != 48) return error.InvalidSecretLength;
            var out: [48]u8 = undefined;
            @memcpy(out[0..], secret_bytes);
            break :blk .{ .sha384 = out };
        },
    };
}

pub fn updateTrafficSecret(
    suite: keyschedule.CipherSuite,
    secret: *const TrafficSecret,
) DeriveError!TrafficSecret {
    var secret_local = secret.*;
    defer zeroizeTrafficSecret(&secret_local);

    return switch (suite) {
        .tls_aes_128_gcm_sha256 => switch (secret_local) {
            .sha256 => |s| .{ .sha256 = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, s, "quic ku", "", 32) },
            .sha384 => error.SecretSuiteMismatch,
        },
        .tls_chacha20_poly1305_sha256 => switch (secret_local) {
            .sha256 => |s| .{ .sha256 = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, s, "quic ku", "", 32) },
            .sha384 => error.SecretSuiteMismatch,
        },
        .tls_aes_256_gcm_sha384 => switch (secret_local) {
            .sha256 => error.SecretSuiteMismatch,
            .sha384 => |s| .{ .sha384 = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, s, "quic ku", "", 48) },
        },
    };
}

pub fn updateTrafficSecretFromBytes(
    suite: keyschedule.CipherSuite,
    secret_bytes: []const u8,
) (DeriveError || SecretDecodeError)!TrafficSecret {
    var secret = try trafficSecretFromBytes(suite, secret_bytes);
    defer zeroizeTrafficSecret(&secret);
    return updateTrafficSecret(suite, &secret);
}

pub fn derivePacketProtectionKeys(
    suite: keyschedule.CipherSuite,
    secret: *const TrafficSecret,
) DeriveError!PacketProtectionKeys {
    var out: PacketProtectionKeys = .{
        .key_len = 0,
        .hp_len = 0,
    };
    var secret_local = secret.*;
    defer zeroizeTrafficSecret(&secret_local);

    switch (suite) {
        .tls_aes_128_gcm_sha256 => switch (secret_local) {
            .sha256 => |s| {
                var key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, s, "quic key", "", 16);
                defer std.crypto.secureZero(u8, key[0..]);
                var iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, s, "quic iv", "", 12);
                defer std.crypto.secureZero(u8, iv[0..]);
                var hp = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, s, "quic hp", "", 16);
                defer std.crypto.secureZero(u8, hp[0..]);
                @memcpy(out.key[0..16], &key);
                @memcpy(out.iv[0..], &iv);
                @memcpy(out.hp[0..16], &hp);
                out.key_len = 16;
                out.hp_len = 16;
            },
            .sha384 => return error.SecretSuiteMismatch,
        },
        .tls_chacha20_poly1305_sha256 => switch (secret_local) {
            .sha256 => |s| {
                var key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, s, "quic key", "", 32);
                defer std.crypto.secureZero(u8, key[0..]);
                var iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, s, "quic iv", "", 12);
                defer std.crypto.secureZero(u8, iv[0..]);
                var hp = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, s, "quic hp", "", 32);
                defer std.crypto.secureZero(u8, hp[0..]);
                @memcpy(out.key[0..32], &key);
                @memcpy(out.iv[0..], &iv);
                @memcpy(out.hp[0..32], &hp);
                out.key_len = 32;
                out.hp_len = 32;
            },
            .sha384 => return error.SecretSuiteMismatch,
        },
        .tls_aes_256_gcm_sha384 => switch (secret_local) {
            .sha256 => return error.SecretSuiteMismatch,
            .sha384 => |s| {
                var key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, s, "quic key", "", 32);
                defer std.crypto.secureZero(u8, key[0..]);
                var iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, s, "quic iv", "", 12);
                defer std.crypto.secureZero(u8, iv[0..]);
                var hp = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, s, "quic hp", "", 32);
                defer std.crypto.secureZero(u8, hp[0..]);
                @memcpy(out.key[0..32], &key);
                @memcpy(out.iv[0..], &iv);
                @memcpy(out.hp[0..32], &hp);
                out.key_len = 32;
                out.hp_len = 32;
            },
        },
    }

    return out;
}

pub fn derivePacketProtectionKeysFromBytes(
    suite: keyschedule.CipherSuite,
    secret_bytes: []const u8,
) (DeriveError || SecretDecodeError)!PacketProtectionKeys {
    var secret = try trafficSecretFromBytes(suite, secret_bytes);
    defer zeroizeTrafficSecret(&secret);
    return derivePacketProtectionKeys(suite, &secret);
}

pub fn buildPacketNonce(base_iv: [12]u8, packet_number: u64) [12]u8 {
    var nonce = base_iv;
    var pn_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_bytes, packet_number, .big);

    var i: usize = 0;
    while (i < pn_bytes.len) : (i += 1) {
        nonce[nonce.len - pn_bytes.len + i] ^= pn_bytes[i];
    }

    return nonce;
}

fn zeroizeTrafficSecret(secret: *TrafficSecret) void {
    switch (secret.*) {
        .sha256 => |*s| std.crypto.secureZero(u8, s[0..]),
        .sha384 => |*s| std.crypto.secureZero(u8, s[0..]),
    }
}

test "initial secrets are deterministic and directional" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const first = deriveInitialSecrets(&dcid);
    const second = deriveInitialSecrets(&dcid);

    try std.testing.expectEqualSlices(u8, &first.client, &second.client);
    try std.testing.expectEqualSlices(u8, &first.server, &second.server);
    try std.testing.expect(!std.mem.eql(u8, &first.client, &first.server));
}

test "initial secret changes with destination connection id" {
    const a = deriveInitialSecrets(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    const b = deriveInitialSecrets(&[_]u8{ 0x01, 0x02, 0x03, 0x05 });
    try std.testing.expect(!std.mem.eql(u8, &a.client, &b.client));
    try std.testing.expect(!std.mem.eql(u8, &a.server, &b.server));
}

test "derive packet protection keys for each supported suite" {
    const initial = deriveInitialSecrets(&[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
    const secret256: TrafficSecret = .{ .sha256 = initial.client };

    const aes128 = try derivePacketProtectionKeys(.tls_aes_128_gcm_sha256, &secret256);
    try std.testing.expectEqual(@as(usize, 16), aes128.key_len);
    try std.testing.expectEqual(@as(usize, 16), aes128.hp_len);

    const chacha = try derivePacketProtectionKeys(.tls_chacha20_poly1305_sha256, &secret256);
    try std.testing.expectEqual(@as(usize, 32), chacha.key_len);
    try std.testing.expectEqual(@as(usize, 32), chacha.hp_len);

    const s384 = keyschedule.extract(.tls_aes_256_gcm_sha384, "salt", "ikm");
    const secret384: TrafficSecret = .{ .sha384 = s384 };
    const aes256 = try derivePacketProtectionKeys(.tls_aes_256_gcm_sha384, &secret384);
    try std.testing.expectEqual(@as(usize, 32), aes256.key_len);
    try std.testing.expectEqual(@as(usize, 32), aes256.hp_len);
}

test "suite and secret mismatches fail closed" {
    const s384 = keyschedule.extract(.tls_aes_256_gcm_sha384, "salt", "ikm");
    try std.testing.expectError(
        error.SecretSuiteMismatch,
        derivePacketProtectionKeys(.tls_aes_128_gcm_sha256, &.{ .sha384 = s384 }),
    );
}

test "quic key update derives deterministic next secret" {
    const initial = deriveInitialSecrets(&[_]u8{ 0x10, 0x20, 0x30, 0x40 });
    const cur: TrafficSecret = .{ .sha256 = initial.server };
    const next_a = try updateTrafficSecret(.tls_aes_128_gcm_sha256, &cur);
    const next_b = try updateTrafficSecret(.tls_aes_128_gcm_sha256, &cur);

    const sec_a = switch (next_a) {
        .sha256 => |v| v,
        .sha384 => unreachable,
    };
    const sec_b = switch (next_b) {
        .sha256 => |v| v,
        .sha384 => unreachable,
    };

    try std.testing.expectEqualSlices(u8, &sec_a, &sec_b);
    try std.testing.expect(!std.mem.eql(u8, &initial.server, &sec_a));
}

test "traffic secret from bytes enforces suite-specific length" {
    const bytes32 = [_]u8{0x11} ** 32;
    const ok = try trafficSecretFromBytes(.tls_chacha20_poly1305_sha256, &bytes32);
    switch (ok) {
        .sha256 => {},
        .sha384 => return error.TestUnexpectedResult,
    }

    try std.testing.expectError(
        error.InvalidSecretLength,
        trafficSecretFromBytes(.tls_aes_256_gcm_sha384, &bytes32),
    );
}

test "quic key update supports sha384 and chacha paths" {
    const s384 = keyschedule.extract(.tls_aes_256_gcm_sha384, "salt384", "ikm384");
    const next384 = try updateTrafficSecret(.tls_aes_256_gcm_sha384, &.{ .sha384 = s384 });
    switch (next384) {
        .sha256 => return error.TestUnexpectedResult,
        .sha384 => |v| try std.testing.expect(!std.mem.eql(u8, &s384, &v)),
    }

    const s256 = keyschedule.extract(.tls_chacha20_poly1305_sha256, "salt256", "ikm256");
    const next256 = try updateTrafficSecret(.tls_chacha20_poly1305_sha256, &.{ .sha256 = s256 });
    switch (next256) {
        .sha256 => |v| try std.testing.expect(!std.mem.eql(u8, &s256, &v)),
        .sha384 => return error.TestUnexpectedResult,
    }
}

test "wrapper helpers decode bytes then derive keys and updates" {
    const s384 = keyschedule.extract(.tls_aes_256_gcm_sha384, "salt384b", "ikm384b");
    const keys = try derivePacketProtectionKeysFromBytes(.tls_aes_256_gcm_sha384, s384[0..]);
    try std.testing.expectEqual(@as(usize, 32), keys.key_len);
    try std.testing.expectEqual(@as(usize, 32), keys.hp_len);

    const updated = try updateTrafficSecretFromBytes(.tls_aes_256_gcm_sha384, s384[0..]);
    switch (updated) {
        .sha256 => return error.TestUnexpectedResult,
        .sha384 => |v| try std.testing.expect(!std.mem.eql(u8, &s384, &v)),
    }
}

test "wrapper helpers reject invalid secret length" {
    const bad_len = [_]u8{0x11} ** 31;
    try std.testing.expectError(
        error.InvalidSecretLength,
        derivePacketProtectionKeysFromBytes(.tls_aes_128_gcm_sha256, &bad_len),
    );
    try std.testing.expectError(
        error.InvalidSecretLength,
        updateTrafficSecretFromBytes(.tls_chacha20_poly1305_sha256, &bad_len),
    );
}

test "packet nonce xor follows right-aligned packet number bytes" {
    const zero_iv = [_]u8{0} ** 12;
    const n1 = buildPacketNonce(zero_iv, 1);
    try std.testing.expectEqual(@as(u8, 1), n1[11]);

    const iv = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const n2 = buildPacketNonce(iv, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u8, 0xff), n2[0]);
    try std.testing.expectEqual(@as(u8, 0x00), n2[11]);
}
