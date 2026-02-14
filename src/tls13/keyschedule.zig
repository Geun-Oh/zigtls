const std = @import("std");
const crypto = std.crypto;

pub const CipherSuite = enum {
    tls_aes_128_gcm_sha256,
    tls_aes_256_gcm_sha384,
    tls_chacha20_poly1305_sha256,
};

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha256 = crypto.kdf.hkdf.Hkdf(HmacSha256);
const HkdfSha384 = crypto.kdf.hkdf.Hkdf(HmacSha384);

pub fn SecretType(comptime suite: CipherSuite) type {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => [HkdfSha256.prk_length]u8,
        .tls_aes_256_gcm_sha384 => [HkdfSha384.prk_length]u8,
    };
}

pub fn extract(comptime suite: CipherSuite, salt: []const u8, ikm: []const u8) SecretType(suite) {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => HkdfSha256.extract(salt, ikm),
        .tls_aes_256_gcm_sha384 => HkdfSha384.extract(salt, ikm),
    };
}

pub fn deriveLabel(
    comptime suite: CipherSuite,
    secret: SecretType(suite),
    label: []const u8,
    context: []const u8,
    comptime len: usize,
) [len]u8 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, context, len),
        .tls_aes_256_gcm_sha384 => crypto.tls.hkdfExpandLabel(HkdfSha384, secret, label, context, len),
    };
}

pub fn digestLen(suite: CipherSuite) usize {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => 32,
        .tls_aes_256_gcm_sha384 => 48,
    };
}

pub fn deriveSecret(comptime suite: CipherSuite, secret: SecretType(suite), label: []const u8, transcript_hash: []const u8) SecretType(suite) {
    return deriveLabel(suite, secret, label, transcript_hash, digestLen(suite));
}

pub fn finishedKey(comptime suite: CipherSuite, base_key: SecretType(suite)) SecretType(suite) {
    return deriveLabel(suite, base_key, "finished", "", digestLen(suite));
}

pub fn finishedVerifyData(comptime suite: CipherSuite, fin_key: SecretType(suite), transcript_hash: []const u8) SecretType(suite) {
    var out: SecretType(suite) = undefined;
    switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => HmacSha256.create(&out, transcript_hash, &fin_key),
        .tls_aes_256_gcm_sha384 => HmacSha384.create(&out, transcript_hash, &fin_key),
    }
    return out;
}

pub fn verifyFinished(
    comptime suite: CipherSuite,
    fin_key: SecretType(suite),
    transcript_hash: []const u8,
    expected: []const u8,
) bool {
    if (expected.len != digestLen(suite)) return false;
    const computed = finishedVerifyData(suite, fin_key, transcript_hash);
    return timingSafeEqual(computed[0..], expected);
}

fn timingSafeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

test "hkdf extract sha256 known vector" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    const secret = extract(.tls_aes_128_gcm_sha256, &salt, &ikm);
    const expected = [_]u8{
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    };
    try std.testing.expectEqualSlices(u8, &expected, &secret);
}

test "derive label output size follows request" {
    const secret = extract(.tls_chacha20_poly1305_sha256, "", "ikm");
    const out = deriveLabel(.tls_chacha20_poly1305_sha256, secret, "key", "ctx", 16);
    try std.testing.expectEqual(@as(usize, 16), out.len);
}

test "sha384 suite digest length" {
    try std.testing.expectEqual(@as(usize, 48), digestLen(.tls_aes_256_gcm_sha384));
}

test "derive secret output size follows suite digest length" {
    const base = extract(.tls_aes_128_gcm_sha256, "salt", "ikm");
    const derived = deriveSecret(.tls_aes_128_gcm_sha256, base, "hs traffic", "thash");
    try std.testing.expectEqual(@as(usize, 32), derived.len);

    const base384 = extract(.tls_aes_256_gcm_sha384, "salt", "ikm");
    const derived384 = deriveSecret(.tls_aes_256_gcm_sha384, base384, "hs traffic", "thash");
    try std.testing.expectEqual(@as(usize, 48), derived384.len);
}

test "finished verify data is deterministic" {
    const base = extract(.tls_chacha20_poly1305_sha256, "salt", "ikm");
    const fin = finishedKey(.tls_chacha20_poly1305_sha256, base);
    const a = finishedVerifyData(.tls_chacha20_poly1305_sha256, fin, "transcript");
    const b = finishedVerifyData(.tls_chacha20_poly1305_sha256, fin, "transcript");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "verify finished accepts match and rejects mismatch" {
    const base = extract(.tls_aes_128_gcm_sha256, "salt", "ikm");
    const fin = finishedKey(.tls_aes_128_gcm_sha256, base);
    const expected = finishedVerifyData(.tls_aes_128_gcm_sha256, fin, "txhash");
    try std.testing.expect(verifyFinished(.tls_aes_128_gcm_sha256, fin, "txhash", &expected));

    var tampered = expected;
    tampered[0] ^= 0x01;
    try std.testing.expect(!verifyFinished(.tls_aes_128_gcm_sha256, fin, "txhash", &tampered));
}
