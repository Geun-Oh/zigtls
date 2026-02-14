const std = @import("std");

pub const legacy_version_tls12: u16 = 0x0303;
const hrr_random = [32]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

pub const Extension = struct {
    extension_type: u16,
    data: []u8,

    pub fn clone(self: Extension, allocator: std.mem.Allocator) !Extension {
        return .{
            .extension_type = self.extension_type,
            .data = try allocator.dupe(u8, self.data),
        };
    }

    pub fn deinit(self: *Extension, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }
};

pub const ClientHello = struct {
    random: [32]u8,
    session_id: []u8,
    cipher_suites: []u16,
    compression_methods: []u8,
    extensions: []Extension,

    pub fn deinit(self: *ClientHello, allocator: std.mem.Allocator) void {
        allocator.free(self.session_id);
        allocator.free(self.cipher_suites);
        allocator.free(self.compression_methods);
        for (self.extensions) |*ext| ext.deinit(allocator);
        allocator.free(self.extensions);
        self.* = undefined;
    }

    pub fn encode(self: ClientHello, allocator: std.mem.Allocator) ![]u8 {
        if (self.session_id.len > 32) return error.InvalidSessionIdLength;
        if (self.cipher_suites.len == 0) return error.EmptyCipherSuites;

        var ext_bytes_len: usize = 0;
        for (self.extensions) |ext| {
            ext_bytes_len += 4 + ext.data.len;
        }

        const total_len = 2 + 32 + 1 + self.session_id.len + 2 + (2 * self.cipher_suites.len) + 1 + self.compression_methods.len + 2 + ext_bytes_len;

        var out = try allocator.alloc(u8, total_len);
        var i: usize = 0;

        writeU16(out[i .. i + 2], legacy_version_tls12);
        i += 2;

        @memcpy(out[i .. i + 32], &self.random);
        i += 32;

        out[i] = @as(u8, @intCast(self.session_id.len));
        i += 1;
        @memcpy(out[i .. i + self.session_id.len], self.session_id);
        i += self.session_id.len;

        writeU16(out[i .. i + 2], @as(u16, @intCast(self.cipher_suites.len * 2)));
        i += 2;
        for (self.cipher_suites) |suite| {
            writeU16(out[i .. i + 2], suite);
            i += 2;
        }

        out[i] = @as(u8, @intCast(self.compression_methods.len));
        i += 1;
        @memcpy(out[i .. i + self.compression_methods.len], self.compression_methods);
        i += self.compression_methods.len;

        writeU16(out[i .. i + 2], @as(u16, @intCast(ext_bytes_len)));
        i += 2;
        for (self.extensions) |ext| {
            writeU16(out[i .. i + 2], ext.extension_type);
            i += 2;
            writeU16(out[i .. i + 2], @as(u16, @intCast(ext.data.len)));
            i += 2;
            @memcpy(out[i .. i + ext.data.len], ext.data);
            i += ext.data.len;
        }

        std.debug.assert(i == out.len);
        return out;
    }

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !ClientHello {
        var i: usize = 0;
        if (bytes.len < 2 + 32 + 1 + 2 + 1 + 2) return error.Truncated;

        const version = readU16(bytes[i .. i + 2]);
        if (version != legacy_version_tls12) return error.InvalidLegacyVersion;
        i += 2;

        var random: [32]u8 = undefined;
        @memcpy(&random, bytes[i .. i + 32]);
        i += 32;

        const sid_len = bytes[i];
        i += 1;
        if (sid_len > 32) return error.InvalidSessionIdLength;
        if (i + sid_len > bytes.len) return error.Truncated;
        const session_id = try allocator.dupe(u8, bytes[i .. i + sid_len]);
        errdefer allocator.free(session_id);
        i += sid_len;

        if (i + 2 > bytes.len) return error.Truncated;
        const suites_len = readU16(bytes[i .. i + 2]);
        i += 2;
        if (suites_len == 0 or suites_len % 2 != 0) return error.InvalidCipherSuitesLength;
        if (i + suites_len > bytes.len) return error.Truncated;

        const suite_count = suites_len / 2;
        var cipher_suites = try allocator.alloc(u16, suite_count);
        errdefer allocator.free(cipher_suites);
        for (0..suite_count) |idx| {
            cipher_suites[idx] = readU16(bytes[i .. i + 2]);
            i += 2;
        }

        if (i + 1 > bytes.len) return error.Truncated;
        const comp_len = bytes[i];
        i += 1;
        if (i + comp_len > bytes.len) return error.Truncated;
        const compression_methods = try allocator.dupe(u8, bytes[i .. i + comp_len]);
        errdefer allocator.free(compression_methods);
        i += comp_len;

        if (i + 2 > bytes.len) return error.Truncated;
        const exts_len = readU16(bytes[i .. i + 2]);
        i += 2;
        if (i + exts_len > bytes.len) return error.Truncated;

        var ext_list: std.ArrayList(Extension) = .empty;
        errdefer {
            for (ext_list.items) |*ext| ext.deinit(allocator);
            ext_list.deinit(allocator);
        }

        const exts_end = i + exts_len;
        while (i < exts_end) {
            if (i + 4 > exts_end) return error.Truncated;
            const ext_type = readU16(bytes[i .. i + 2]);
            i += 2;
            const ext_len = readU16(bytes[i .. i + 2]);
            i += 2;
            if (i + ext_len > exts_end) return error.Truncated;
            try ext_list.append(allocator, .{
                .extension_type = ext_type,
                .data = try allocator.dupe(u8, bytes[i .. i + ext_len]),
            });
            i += ext_len;
        }

        if (i != bytes.len) return error.TrailingBytes;

        return .{
            .random = random,
            .session_id = session_id,
            .cipher_suites = cipher_suites,
            .compression_methods = compression_methods,
            .extensions = try ext_list.toOwnedSlice(allocator),
        };
    }
};

pub const ServerHello = struct {
    random: [32]u8,
    session_id_echo: []u8,
    cipher_suite: u16,
    compression_method: u8,
    extensions: []Extension,

    pub fn deinit(self: *ServerHello, allocator: std.mem.Allocator) void {
        allocator.free(self.session_id_echo);
        for (self.extensions) |*ext| ext.deinit(allocator);
        allocator.free(self.extensions);
        self.* = undefined;
    }

    pub fn encode(self: ServerHello, allocator: std.mem.Allocator) ![]u8 {
        if (self.session_id_echo.len > 32) return error.InvalidSessionIdLength;

        var ext_bytes_len: usize = 0;
        for (self.extensions) |ext| ext_bytes_len += 4 + ext.data.len;

        const total_len = 2 + 32 + 1 + self.session_id_echo.len + 2 + 1 + 2 + ext_bytes_len;
        var out = try allocator.alloc(u8, total_len);

        var i: usize = 0;
        writeU16(out[i .. i + 2], legacy_version_tls12);
        i += 2;
        @memcpy(out[i .. i + 32], &self.random);
        i += 32;
        out[i] = @as(u8, @intCast(self.session_id_echo.len));
        i += 1;
        @memcpy(out[i .. i + self.session_id_echo.len], self.session_id_echo);
        i += self.session_id_echo.len;
        writeU16(out[i .. i + 2], self.cipher_suite);
        i += 2;
        out[i] = self.compression_method;
        i += 1;
        writeU16(out[i .. i + 2], @as(u16, @intCast(ext_bytes_len)));
        i += 2;

        for (self.extensions) |ext| {
            writeU16(out[i .. i + 2], ext.extension_type);
            i += 2;
            writeU16(out[i .. i + 2], @as(u16, @intCast(ext.data.len)));
            i += 2;
            @memcpy(out[i .. i + ext.data.len], ext.data);
            i += ext.data.len;
        }

        std.debug.assert(i == out.len);
        return out;
    }

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !ServerHello {
        var i: usize = 0;
        if (bytes.len < 2 + 32 + 1 + 2 + 1 + 2) return error.Truncated;

        const version = readU16(bytes[i .. i + 2]);
        if (version != legacy_version_tls12) return error.InvalidLegacyVersion;
        i += 2;

        var random: [32]u8 = undefined;
        @memcpy(&random, bytes[i .. i + 32]);
        i += 32;

        const sid_len = bytes[i];
        i += 1;
        if (sid_len > 32) return error.InvalidSessionIdLength;
        if (i + sid_len > bytes.len) return error.Truncated;
        const session_id_echo = try allocator.dupe(u8, bytes[i .. i + sid_len]);
        errdefer allocator.free(session_id_echo);
        i += sid_len;

        if (i + 2 + 1 + 2 > bytes.len) return error.Truncated;
        const cipher_suite = readU16(bytes[i .. i + 2]);
        i += 2;
        const compression_method = bytes[i];
        i += 1;
        const exts_len = readU16(bytes[i .. i + 2]);
        i += 2;
        if (i + exts_len > bytes.len) return error.Truncated;

        var ext_list: std.ArrayList(Extension) = .empty;
        errdefer {
            for (ext_list.items) |*ext| ext.deinit(allocator);
            ext_list.deinit(allocator);
        }

        const exts_end = i + exts_len;
        while (i < exts_end) {
            if (i + 4 > exts_end) return error.Truncated;
            const ext_type = readU16(bytes[i .. i + 2]);
            i += 2;
            const ext_len = readU16(bytes[i .. i + 2]);
            i += 2;
            if (i + ext_len > exts_end) return error.Truncated;

            try ext_list.append(allocator, .{
                .extension_type = ext_type,
                .data = try allocator.dupe(u8, bytes[i .. i + ext_len]),
            });
            i += ext_len;
        }

        if (i != bytes.len) return error.TrailingBytes;

        return .{
            .random = random,
            .session_id_echo = session_id_echo,
            .cipher_suite = cipher_suite,
            .compression_method = compression_method,
            .extensions = try ext_list.toOwnedSlice(allocator),
        };
    }
};

pub fn serverHelloHasHrrRandom(bytes: []const u8) bool {
    if (bytes.len < 2 + 32 + 1 + 2 + 1 + 2) return false;
    const version = readU16(bytes[0..2]);
    if (version != legacy_version_tls12) return false;
    return std.mem.eql(u8, bytes[2..34], &hrr_random);
}

pub const CertificateEntry = struct {
    cert_data: []u8,
    extensions: []Extension,

    pub fn deinit(self: *CertificateEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.cert_data);
        for (self.extensions) |*ext| ext.deinit(allocator);
        allocator.free(self.extensions);
        self.* = undefined;
    }
};

pub const CertificateMsg = struct {
    request_context: []u8,
    entries: []CertificateEntry,

    pub fn deinit(self: *CertificateMsg, allocator: std.mem.Allocator) void {
        allocator.free(self.request_context);
        for (self.entries) |*entry| entry.deinit(allocator);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !CertificateMsg {
        var i: usize = 0;
        if (bytes.len < 1 + 3) return error.Truncated;

        const ctx_len = bytes[i];
        i += 1;
        if (i + ctx_len > bytes.len) return error.Truncated;
        const request_context = try allocator.dupe(u8, bytes[i .. i + ctx_len]);
        errdefer allocator.free(request_context);
        i += ctx_len;

        const cert_list_len = readU24(bytes[i .. i + 3]);
        i += 3;
        if (i + cert_list_len > bytes.len) return error.Truncated;
        const cert_list_end = i + cert_list_len;

        var entries: std.ArrayList(CertificateEntry) = .empty;
        errdefer {
            for (entries.items) |*entry| entry.deinit(allocator);
            entries.deinit(allocator);
        }

        while (i < cert_list_end) {
            if (i + 3 > cert_list_end) return error.Truncated;
            const cert_len = readU24(bytes[i .. i + 3]);
            i += 3;
            if (i + cert_len > cert_list_end) return error.Truncated;
            const cert_data = try allocator.dupe(u8, bytes[i .. i + cert_len]);
            i += cert_len;

            if (i + 2 > cert_list_end) {
                allocator.free(cert_data);
                return error.Truncated;
            }
            const ext_len = readU16(bytes[i .. i + 2]);
            i += 2;
            if (i + ext_len > cert_list_end) {
                allocator.free(cert_data);
                return error.Truncated;
            }
            const ext_end = i + ext_len;

            var exts: std.ArrayList(Extension) = .empty;
            errdefer {
                for (exts.items) |*ext| ext.deinit(allocator);
                exts.deinit(allocator);
            }

            while (i < ext_end) {
                if (i + 4 > ext_end) {
                    allocator.free(cert_data);
                    return error.Truncated;
                }
                const ext_type = readU16(bytes[i .. i + 2]);
                i += 2;
                const one_ext_len = readU16(bytes[i .. i + 2]);
                i += 2;
                if (i + one_ext_len > ext_end) {
                    allocator.free(cert_data);
                    return error.Truncated;
                }
                try exts.append(allocator, .{
                    .extension_type = ext_type,
                    .data = try allocator.dupe(u8, bytes[i .. i + one_ext_len]),
                });
                i += one_ext_len;
            }

            try entries.append(allocator, .{
                .cert_data = cert_data,
                .extensions = try exts.toOwnedSlice(allocator),
            });
        }

        if (i != cert_list_end) return error.TrailingBytes;
        if (i != bytes.len) return error.TrailingBytes;

        return .{
            .request_context = request_context,
            .entries = try entries.toOwnedSlice(allocator),
        };
    }
};

pub const CertificateVerifyMsg = struct {
    algorithm: u16,
    signature: []u8,

    pub fn deinit(self: *CertificateVerifyMsg, allocator: std.mem.Allocator) void {
        allocator.free(self.signature);
        self.* = undefined;
    }

    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !CertificateVerifyMsg {
        if (bytes.len < 4) return error.Truncated;
        const algorithm = readU16(bytes[0..2]);
        const sig_len = readU16(bytes[2..4]);
        if (sig_len == 0) return error.EmptySignature;
        if (4 + sig_len != bytes.len) return error.Truncated;

        return .{
            .algorithm = algorithm,
            .signature = try allocator.dupe(u8, bytes[4 .. 4 + sig_len]),
        };
    }
};

test "clienthello encode/decode roundtrip" {
    const allocator = std.testing.allocator;

    var random: [32]u8 = undefined;
    @memset(&random, 0x11);

    var hello = ClientHello{
        .random = random,
        .session_id = try allocator.dupe(u8, "abcd"),
        .cipher_suites = try allocator.dupe(u16, &.{ 0x1301, 0x1302 }),
        .compression_methods = try allocator.dupe(u8, &.{0}),
        .extensions = try allocator.dupe(Extension, &.{.{
            .extension_type = 0x0000,
            .data = try allocator.dupe(u8, "localhost"),
        }}),
    };
    defer hello.deinit(allocator);

    const encoded = try hello.encode(allocator);
    defer allocator.free(encoded);

    var decoded = try ClientHello.decode(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualSlices(u8, hello.session_id, decoded.session_id);
    try std.testing.expectEqualSlices(u16, hello.cipher_suites, decoded.cipher_suites);
    try std.testing.expectEqual(@as(usize, 1), decoded.extensions.len);
}

test "clienthello rejects odd cipher suite length" {
    const allocator = std.testing.allocator;

    // Well-formed up to cipher suites length, then set it to odd number 1.
    var bytes = [_]u8{0} ** 40;
    writeU16(bytes[0..2], legacy_version_tls12);
    bytes[34] = 0; // session id len
    writeU16(bytes[35..37], 1);

    try std.testing.expectError(error.InvalidCipherSuitesLength, ClientHello.decode(allocator, &bytes));
}

test "serverhello encode baseline" {
    const allocator = std.testing.allocator;
    var random: [32]u8 = undefined;
    @memset(&random, 0x42);

    var sh = ServerHello{
        .random = random,
        .session_id_echo = try allocator.dupe(u8, "aa"),
        .cipher_suite = 0x1301,
        .compression_method = 0,
        .extensions = try allocator.dupe(Extension, &.{.{
            .extension_type = 0x002b,
            .data = try allocator.dupe(u8, &.{ 0x03, 0x04 }),
        }}),
    };
    defer sh.deinit(allocator);

    const encoded = try sh.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 38);
}

test "serverhello decode roundtrip" {
    const allocator = std.testing.allocator;
    var random: [32]u8 = undefined;
    @memset(&random, 0x99);

    var sh = ServerHello{
        .random = random,
        .session_id_echo = try allocator.dupe(u8, "id"),
        .cipher_suite = 0x1301,
        .compression_method = 0,
        .extensions = try allocator.dupe(Extension, &.{.{ .extension_type = 0x002b, .data = try allocator.dupe(u8, &.{ 0x03, 0x04 }) }}),
    };
    defer sh.deinit(allocator);

    const encoded = try sh.encode(allocator);
    defer allocator.free(encoded);

    var dec = try ServerHello.decode(allocator, encoded);
    defer dec.deinit(allocator);

    try std.testing.expectEqual(sh.cipher_suite, dec.cipher_suite);
    try std.testing.expectEqualSlices(u8, sh.session_id_echo, dec.session_id_echo);
}

test "certificate decode minimal single entry" {
    const allocator = std.testing.allocator;

    // context_len=0, cert_list_len=6, cert_len=1, cert_data=0xaa, ext_len=0
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xaa, 0x00, 0x00 };
    var msg = try CertificateMsg.decode(allocator, &bytes);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), msg.entries.len);
    try std.testing.expectEqualSlices(u8, &.{0xaa}, msg.entries[0].cert_data);
}

test "certificate verify decode baseline" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0x04, 0x03, 0x00, 0x02, 0xde, 0xad };

    var msg = try CertificateVerifyMsg.decode(allocator, &bytes);
    defer msg.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 0x0403), msg.algorithm);
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, msg.signature);
}

test "certificate verify rejects empty signature" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0x04, 0x03, 0x00, 0x00 };
    try std.testing.expectError(error.EmptySignature, CertificateVerifyMsg.decode(allocator, &bytes));
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16(bytes: []u8, value: u16) void {
    bytes[0] = @intCast((value >> 8) & 0xff);
    bytes[1] = @intCast(value & 0xff);
}

fn readU24(bytes: []const u8) usize {
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | @as(usize, bytes[2]);
}
