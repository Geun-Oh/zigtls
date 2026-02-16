const std = @import("std");
const tls13 = @import("tls13.zig");

pub const max_reload_file_bytes: usize = 512 * 1024;

pub const SnapshotView = struct {
    generation: u64,
    cert_pem: []const u8,
    key_pem: []const u8,
};

pub const DerChain = struct {
    certs: [][]u8,

    pub fn deinit(self: *DerChain, allocator: std.mem.Allocator) void {
        for (self.certs) |cert| allocator.free(cert);
        allocator.free(self.certs);
        self.* = undefined;
    }
};

pub const Ed25519ServerCredentialsBundle = struct {
    chain: DerChain,
    key_pair: std.crypto.sign.Ed25519.KeyPair,

    pub fn deinit(self: *Ed25519ServerCredentialsBundle, allocator: std.mem.Allocator) void {
        self.chain.deinit(allocator);
        self.* = undefined;
    }

    pub fn serverCredentials(self: *const Ed25519ServerCredentialsBundle) tls13.session.ServerCredentials {
        return .{
            .cert_chain_der = self.chain.certs,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = signCertificateVerify,
            .signer_userdata = @intFromPtr(self),
        };
    }

    fn signCertificateVerify(
        transcript_hash: []const u8,
        signature_scheme: u16,
        out_signature: []u8,
        userdata: usize,
    ) anyerror!usize {
        if (signature_scheme != 0x0807) return error.UnsupportedSignatureAlgorithm;
        var self: *const Ed25519ServerCredentialsBundle = @ptrFromInt(userdata);
        const sig = try self.key_pair.sign(transcript_hash, null);
        const sig_bytes = sig.toBytes();
        if (out_signature.len < sig_bytes.len) return error.NoSpaceLeft;
        @memcpy(out_signature[0..sig_bytes.len], &sig_bytes);
        return sig_bytes.len;
    }
};

const Snapshot = struct {
    generation: u64,
    cert_pem: []u8,
    key_pem: []u8,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    active: ?Snapshot = null,
    previous: ?Snapshot = null,
    generation_counter: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Store) void {
        if (self.active) |snap| freeSnapshot(self.allocator, snap);
        if (self.previous) |snap| freeSnapshot(self.allocator, snap);
        self.* = undefined;
    }

    pub fn reloadFromFiles(self: *Store, cert_path: []const u8, key_path: []const u8) Error!u64 {
        const cert = try std.fs.cwd().readFileAlloc(self.allocator, cert_path, max_reload_file_bytes);
        errdefer self.allocator.free(cert);
        const key = try std.fs.cwd().readFileAlloc(self.allocator, key_path, max_reload_file_bytes);
        errdefer self.allocator.free(key);

        if (cert.len == 0 or key.len == 0) return error.EmptyCredential;

        self.generation_counter += 1;
        const next = Snapshot{
            .generation = self.generation_counter,
            .cert_pem = cert,
            .key_pem = key,
        };

        if (self.previous) |old_prev| freeSnapshot(self.allocator, old_prev);
        self.previous = self.active;
        self.active = next;
        return next.generation;
    }

    pub fn rollback(self: *Store) Error!void {
        const prev = self.previous orelse return error.NoPreviousSnapshot;
        const cur = self.active;
        self.active = prev;
        self.previous = cur;
    }

    pub fn snapshot(self: Store) ?SnapshotView {
        const active = self.active orelse return null;
        return .{
            .generation = active.generation,
            .cert_pem = active.cert_pem,
            .key_pem = active.key_pem,
        };
    }

    pub fn decodeActiveCertificateChainDer(self: Store, allocator: std.mem.Allocator) Error!DerChain {
        const active = self.active orelse return error.NoActiveSnapshot;
        var certs = std.ArrayList([]u8).empty;
        errdefer {
            for (certs.items) |der| allocator.free(der);
            certs.deinit(allocator);
        }

        try decodePemBlocks(allocator, active.cert_pem, cert_begin_marker, cert_end_marker, &certs);
        if (certs.items.len == 0) return error.NoCertificatePemBlock;
        return .{ .certs = try certs.toOwnedSlice(allocator) };
    }

    pub fn decodeActivePrivateKeyDer(self: Store, allocator: std.mem.Allocator) Error![]u8 {
        const active = self.active orelse return error.NoActiveSnapshot;

        if (try decodeFirstPemBlock(allocator, active.key_pem, pkcs8_begin_marker, pkcs8_end_marker)) |der| return der;
        if (try decodeFirstPemBlock(allocator, active.key_pem, rsa_begin_marker, rsa_end_marker)) |der| return der;
        if (try decodeFirstPemBlock(allocator, active.key_pem, ec_begin_marker, ec_end_marker)) |der| return der;
        return error.NoPrivateKeyPemBlock;
    }

    pub fn loadActiveEd25519Bundle(self: Store, allocator: std.mem.Allocator) Error!Ed25519ServerCredentialsBundle {
        var chain = try self.decodeActiveCertificateChainDer(allocator);
        errdefer chain.deinit(allocator);
        const key_der = try self.decodeActivePrivateKeyDer(allocator);
        defer allocator.free(key_der);

        const seed = try parseEd25519SeedFromPrivateKeyDer(key_der);
        const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidPrivateKeyDer;
        return .{
            .chain = chain,
            .key_pair = key_pair,
        };
    }
};

pub const Error = error{
    EmptyCredential,
    NoPreviousSnapshot,
    NoActiveSnapshot,
    NoCertificatePemBlock,
    NoPrivateKeyPemBlock,
    InvalidPemBlock,
    InvalidPrivateKeyDer,
    UnsupportedPrivateKeyAlgorithm,
} || std.fs.File.OpenError || std.fs.File.ReadError || std.mem.Allocator.Error;

fn freeSnapshot(allocator: std.mem.Allocator, snap: Snapshot) void {
    allocator.free(snap.cert_pem);
    allocator.free(snap.key_pem);
}

const cert_begin_marker = "-----BEGIN CERTIFICATE-----";
const cert_end_marker = "-----END CERTIFICATE-----";
const pkcs8_begin_marker = "-----BEGIN PRIVATE KEY-----";
const pkcs8_end_marker = "-----END PRIVATE KEY-----";
const rsa_begin_marker = "-----BEGIN RSA PRIVATE KEY-----";
const rsa_end_marker = "-----END RSA PRIVATE KEY-----";
const ec_begin_marker = "-----BEGIN EC PRIVATE KEY-----";
const ec_end_marker = "-----END EC PRIVATE KEY-----";

fn decodePemBlocks(
    allocator: std.mem.Allocator,
    pem: []const u8,
    begin_marker: []const u8,
    end_marker: []const u8,
    out: *std.ArrayList([]u8),
) Error!void {
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, pem, cursor, begin_marker)) |begin_pos| {
        const body_start = begin_pos + begin_marker.len;
        const end_pos = std.mem.indexOfPos(u8, pem, body_start, end_marker) orelse return error.InvalidPemBlock;
        const der = try decodePemBodyToDer(allocator, pem[body_start..end_pos]);
        errdefer allocator.free(der);
        try out.append(allocator, der);
        cursor = end_pos + end_marker.len;
    }
}

fn decodeFirstPemBlock(
    allocator: std.mem.Allocator,
    pem: []const u8,
    begin_marker: []const u8,
    end_marker: []const u8,
) Error!?[]u8 {
    const begin_pos = std.mem.indexOf(u8, pem, begin_marker) orelse return null;
    const body_start = begin_pos + begin_marker.len;
    const end_pos = std.mem.indexOfPos(u8, pem, body_start, end_marker) orelse return error.InvalidPemBlock;
    return try decodePemBodyToDer(allocator, pem[body_start..end_pos]);
}

fn decodePemBodyToDer(allocator: std.mem.Allocator, body: []const u8) Error![]u8 {
    const decoder = std.base64.standard.decoderWithIgnore(" \r\n\t");
    const upper_bound = decoder.calcSizeUpperBound(body.len) catch return error.InvalidPemBlock;
    var tmp = try allocator.alloc(u8, upper_bound);
    defer allocator.free(tmp);
    const out_len = decoder.decode(tmp, body) catch return error.InvalidPemBlock;
    const out = try allocator.alloc(u8, out_len);
    @memcpy(out, tmp[0..out_len]);
    return out;
}

const DerTlv = struct {
    tag: u8,
    value: []const u8,
    next: usize,
};

fn parseDerTlv(bytes: []const u8, start: usize) Error!DerTlv {
    if (start + 2 > bytes.len) return error.InvalidPrivateKeyDer;
    const tag = bytes[start];
    const len_octet = bytes[start + 1];
    var value_start = start + 2;
    var value_len: usize = 0;

    if ((len_octet & 0x80) == 0) {
        value_len = len_octet;
    } else {
        const len_len = @as(usize, len_octet & 0x7f);
        if (len_len == 0 or len_len > 4) return error.InvalidPrivateKeyDer;
        if (value_start + len_len > bytes.len) return error.InvalidPrivateKeyDer;
        value_len = 0;
        var i: usize = 0;
        while (i < len_len) : (i += 1) {
            value_len = (value_len << 8) | bytes[value_start + i];
        }
        value_start += len_len;
    }

    if (value_start + value_len > bytes.len) return error.InvalidPrivateKeyDer;
    return .{
        .tag = tag,
        .value = bytes[value_start .. value_start + value_len],
        .next = value_start + value_len,
    };
}

fn parseEd25519SeedFromPrivateKeyDer(der: []const u8) Error![32]u8 {
    const pkcs8 = try parseDerTlv(der, 0);
    if (pkcs8.tag != 0x30 or pkcs8.next != der.len) return error.InvalidPrivateKeyDer;

    var i: usize = 0;
    const version = try parseDerTlv(pkcs8.value, i);
    if (version.tag != 0x02) return error.InvalidPrivateKeyDer;
    i = version.next;

    const algorithm = try parseDerTlv(pkcs8.value, i);
    if (algorithm.tag != 0x30) return error.InvalidPrivateKeyDer;
    if (!isEd25519AlgorithmIdentifier(algorithm.value)) return error.UnsupportedPrivateKeyAlgorithm;
    i = algorithm.next;

    const private_key = try parseDerTlv(pkcs8.value, i);
    if (private_key.tag != 0x04) return error.InvalidPrivateKeyDer;

    var seed_slice = private_key.value;
    if (seed_slice.len > 0) {
        const inner = parseDerTlv(seed_slice, 0) catch null;
        if (inner) |v| {
            if (v.tag == 0x04 and v.next == seed_slice.len) {
                seed_slice = v.value;
            }
        }
    }

    if (seed_slice.len == 64) seed_slice = seed_slice[0..32];
    if (seed_slice.len != 32) return error.InvalidPrivateKeyDer;

    var seed: [32]u8 = undefined;
    @memcpy(&seed, seed_slice[0..32]);
    return seed;
}

fn isEd25519AlgorithmIdentifier(der: []const u8) bool {
    var i: usize = 0;
    const oid = parseDerTlv(der, i) catch return false;
    if (oid.tag != 0x06) return false;
    if (!std.mem.eql(u8, oid.value, &.{ 0x2b, 0x65, 0x70 })) return false;
    i = oid.next;
    if (i == der.len) return true;

    const param = parseDerTlv(der, i) catch return false;
    return param.tag == 0x05 and param.value.len == 0 and param.next == der.len;
}

test "reload updates generation and keeps previous snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const g1 = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqual(@as(u64, 1), g1);
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-B" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-B" });

    const g2 = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqual(@as(u64, 2), g2);
    try std.testing.expectEqualStrings("CERT-B", store.snapshot().?.cert_pem);
    try std.testing.expectEqual(@as(u64, 1), store.previous.?.generation);
}

test "failed reload keeps existing active snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);

    try std.testing.expectError(error.FileNotFound, store.reloadFromFiles("/no/such/cert.pem", key_path));
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);
}

test "rollback restores previous active snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.reloadFromFiles(cert_path, key_path);

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-B" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-B" });
    _ = try store.reloadFromFiles(cert_path, key_path);

    try std.testing.expectEqualStrings("CERT-B", store.snapshot().?.cert_pem);
    try store.rollback();
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);
}

test "rollback requires previous snapshot" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.NoPreviousSnapshot, store.rollback());
}

test "decode active cert and key pem into der artifacts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MAMCAQE=
        \\-----END CERTIFICATE-----
        \\
    ;
    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MAMCAQE=
        \\-----END PRIVATE KEY-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = key_pem });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    var chain = try store.decodeActiveCertificateChainDer(std.testing.allocator);
    defer chain.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), chain.certs.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x03, 0x02, 0x01, 0x01 }, chain.certs[0]);

    const key_der = try store.decodeActivePrivateKeyDer(std.testing.allocator);
    defer std.testing.allocator.free(key_der);
    try std.testing.expectEqualSlices(u8, &.{ 0x30, 0x03, 0x02, 0x01, 0x01 }, key_der);
}

test "decode active cert chain fails when certificate pem block is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MAMCAQE=
        \\-----END PRIVATE KEY-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = key_pem });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectError(error.NoCertificatePemBlock, store.decodeActiveCertificateChainDer(std.testing.allocator));
}

test "decode active private key fails when pem block is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MAMCAQE=
        \\-----END CERTIFICATE-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectError(error.NoPrivateKeyPemBlock, store.decodeActivePrivateKeyDer(std.testing.allocator));
}

test "decode helpers require active snapshot" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(error.NoActiveSnapshot, store.decodeActiveCertificateChainDer(std.testing.allocator));
    try std.testing.expectError(error.NoActiveSnapshot, store.decodeActivePrivateKeyDer(std.testing.allocator));
}

test "load active ed25519 bundle provides signer-backed server credentials" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MAMCAQE=
        \\-----END CERTIFICATE-----
        \\
    ;
    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g
        \\-----END PRIVATE KEY-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = key_pem });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    var bundle = try store.loadActiveEd25519Bundle(std.testing.allocator);
    defer bundle.deinit(std.testing.allocator);

    const creds = bundle.serverCredentials();
    try std.testing.expectEqual(@as(usize, 1), creds.cert_chain_der.len);
    try std.testing.expectEqual(@as(u16, 0x0807), creds.signature_scheme);
    try std.testing.expect(creds.sign_certificate_verify != null);

    var sig_bytes: [128]u8 = undefined;
    const sig_len = try creds.sign_certificate_verify.?(
        "transcript-hash",
        0x0807,
        sig_bytes[0..],
        creds.signer_userdata,
    );
    try std.testing.expectEqual(@as(usize, 64), sig_len);
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
    try sig.verify("transcript-hash", bundle.key_pair.public_key);
}

test "load active ed25519 bundle rejects unsupported private key algorithm oid" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MAMCAQE=
        \\-----END CERTIFICATE-----
        \\
    ;
    const key_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VxBCIEIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g
        \\-----END PRIVATE KEY-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = key_pem });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    try std.testing.expectError(error.UnsupportedPrivateKeyAlgorithm, store.loadActiveEd25519Bundle(std.testing.allocator));
}
