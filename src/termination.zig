const std = @import("std");
const rate_limit = @import("rate_limit.zig");
const tls13 = @import("tls13.zig");

pub const Config = struct {
    session: tls13.session.Config,
    on_client_hello: ?ClientHelloCallback = null,
    callback_userdata: usize = 0,
    handshake_rate_limiter: ?*rate_limit.TokenBucket = null,
    now_ns: ?NowNsFn = null,
};

pub const ConnectionContext = struct {
    connection_id: u64 = 0,
};

pub const Error = error{
    NotAccepted,
    OutputBufferTooSmall,
    InvalidConfiguration,
    HandshakeRateLimited,
} || tls13.session.EngineError || std.mem.Allocator.Error;

pub const ClientHelloMetadata = struct {
    server_name: ?[]const u8 = null,
    alpn_protocol: ?[]const u8 = null,
};

pub const ClientHelloCallback = *const fn (meta: ClientHelloMetadata, userdata: usize) void;
pub const NowNsFn = *const fn () u64;

pub const Connection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    engine: tls13.session.Engine,
    accepted: bool = false,
    pending_records: std.ArrayList([]u8),
    pending_plaintext: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, config: Config) Connection {
        return .{
            .allocator = allocator,
            .config = config,
            .engine = tls13.session.Engine.init(allocator, config.session),
            .pending_records = .empty,
            .pending_plaintext = .empty,
        };
    }

    pub fn initChecked(allocator: std.mem.Allocator, config: Config) Error!Connection {
        try validateConfig(config);
        return Connection.init(allocator, config);
    }

    pub fn deinit(self: *Connection) void {
        self.engine.deinit();
        for (self.pending_records.items) |frame| self.allocator.free(frame);
        self.pending_records.deinit(self.allocator);
        self.pending_plaintext.deinit(self.allocator);
    }

    pub fn accept(self: *Connection, _: ConnectionContext) void {
        self.accepted = true;
    }

    pub fn ingest_tls_bytes(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestResult {
        if (!self.accepted) return error.NotAccepted;
        try self.enforceHandshakeRateLimit();
        self.emitClientHelloMetadata(record_bytes);
        const result = try self.engine.ingestRecord(record_bytes);
        try self.collectActions(result);
        return result;
    }

    pub fn ingest_tls_bytes_with_alert(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestWithAlertOutcome {
        if (!self.accepted) return error.NotAccepted;
        try self.enforceHandshakeRateLimit();
        self.emitClientHelloMetadata(record_bytes);
        const out = self.engine.ingestRecordWithAlertIntent(record_bytes);
        switch (out) {
            .ok => |res| {
                try self.collectActions(res);
                return .{ .ok = res };
            },
            .fatal => return out,
        }
    }

    pub fn drain_tls_records(self: *Connection, out: []u8) Error!usize {
        if (self.pending_records.items.len == 0) return 0;

        const first = self.pending_records.items[0];
        if (out.len < first.len) return error.OutputBufferTooSmall;

        @memcpy(out[0..first.len], first);
        self.allocator.free(first);
        _ = self.pending_records.orderedRemove(0);
        return first.len;
    }

    pub fn read_plaintext(self: *Connection, out: []u8) usize {
        if (self.pending_plaintext.items.len == 0 or out.len == 0) return 0;

        const n = @min(out.len, self.pending_plaintext.items.len);
        @memcpy(out[0..n], self.pending_plaintext.items[0..n]);
        if (n == self.pending_plaintext.items.len) {
            self.pending_plaintext.clearRetainingCapacity();
        } else {
            _ = self.pending_plaintext.orderedRemoveRange(0, n);
        }
        return n;
    }

    pub fn write_plaintext(self: *Connection, plaintext: []const u8) Error!usize {
        if (!self.accepted) return error.NotAccepted;
        if (plaintext.len == 0) return 0;

        var written: usize = 0;
        const max_payload = std.math.maxInt(u16);

        while (written < plaintext.len) {
            const remaining = plaintext.len - written;
            const chunk_len = @min(remaining, max_payload);
            const frame = try self.allocator.alloc(u8, 5 + chunk_len);
            errdefer self.allocator.free(frame);

            frame[0] = @intFromEnum(tls13.record.ContentType.application_data);
            std.mem.writeInt(u16, frame[1..3], tls13.record.tls_legacy_record_version, .big);
            std.mem.writeInt(u16, frame[3..5], @as(u16, @intCast(chunk_len)), .big);
            @memcpy(frame[5..], plaintext[written .. written + chunk_len]);
            try self.pending_records.append(self.allocator, frame);
            written += chunk_len;
        }

        return written;
    }

    pub fn shutdown(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        const frame = tls13.session.Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });
        try self.pushPendingRecord(frame[0..]);
        self.engine.machine.markClosed();
    }

    pub fn on_transport_eof(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        try self.engine.onTransportEof();
    }

    pub fn snapshot_metrics(self: Connection) tls13.session.Metrics {
        return self.engine.snapshotMetrics();
    }

    fn collectActions(self: *Connection, result: tls13.session.IngestResult) Error!void {
        var i: usize = 0;
        while (i < result.action_count) : (i += 1) {
            switch (result.actions[i]) {
                .send_alert => |alert| {
                    const frame = tls13.session.Engine.buildAlertRecord(alert);
                    try self.pushPendingRecord(frame[0..]);
                },
                .send_key_update => |req| {
                    const frame = tls13.session.Engine.buildKeyUpdateRecord(req);
                    try self.pushPendingRecord(frame[0..]);
                },
                .application_data => |data| {
                    try self.pending_plaintext.appendSlice(self.allocator, data);
                },
                else => {},
            }
        }
    }

    fn emitClientHelloMetadata(self: *Connection, record_bytes: []const u8) void {
        const cb = self.config.on_client_hello orelse return;
        const parsed = tls13.record.parseRecord(record_bytes) catch return;
        if (parsed.header.content_type != .handshake) return;

        var cursor = parsed.payload;
        while (cursor.len > 0) {
            const hs = tls13.handshake.parseOne(cursor) catch return;
            const frame_len = 4 + @as(usize, @intCast(hs.header.length));
            cursor = cursor[frame_len..];

            if (hs.header.handshake_type != .client_hello) continue;
            var hello = tls13.messages.ClientHello.decode(self.allocator, hs.body) catch return;
            defer hello.deinit(self.allocator);

            const meta = ClientHelloMetadata{
                .server_name = extractServerName(hello.extensions),
                .alpn_protocol = extractFirstAlpn(hello.extensions),
            };
            cb(meta, self.config.callback_userdata);
            return;
        }
    }

    fn pushPendingRecord(self: *Connection, bytes: []const u8) Error!void {
        const frame = try self.allocator.alloc(u8, bytes.len);
        errdefer self.allocator.free(frame);
        @memcpy(frame, bytes);
        try self.pending_records.append(self.allocator, frame);
    }

    fn enforceHandshakeRateLimit(self: *Connection) Error!void {
        if (self.engine.machine.state == .connected) return;
        const limiter = self.config.handshake_rate_limiter orelse return;
        if (!limiter.allowAt(self.nowNs())) return error.HandshakeRateLimited;
    }

    fn nowNs(self: Connection) u64 {
        if (self.config.now_ns) |f| return f();
        return @as(u64, @intCast(std.time.nanoTimestamp()));
    }
};

pub fn validateConfig(config: Config) Error!void {
    if (config.session.early_data.enabled and config.session.early_data.replay_filter == null) {
        return error.InvalidConfiguration;
    }
}

fn findExtension(extensions: []const tls13.messages.Extension, ext_type: u16) ?[]const u8 {
    for (extensions) |ext| {
        if (ext.extension_type == ext_type) return ext.data;
    }
    return null;
}

fn extractServerName(extensions: []const tls13.messages.Extension) ?[]const u8 {
    const data = findExtension(extensions, 0x0000) orelse return null;
    if (data.len < 5) return null;
    const list_len = std.mem.readInt(u16, data[0..2], .big);
    if (list_len + 2 != data.len) return null;
    if (data[2] != 0) return null;
    const name_len = std.mem.readInt(u16, data[3..5], .big);
    if (5 + name_len > data.len) return null;
    return data[5 .. 5 + name_len];
}

fn extractFirstAlpn(extensions: []const tls13.messages.Extension) ?[]const u8 {
    const data = findExtension(extensions, 0x0010) orelse return null;
    if (data.len < 3) return null;
    const list_len = std.mem.readInt(u16, data[0..2], .big);
    if (list_len + 2 != data.len) return null;
    const first_len = data[2];
    if (3 + first_len > data.len) return null;
    return data[3 .. 3 + first_len];
}

const Capture = struct {
    called: bool = false,
    sni: [64]u8 = [_]u8{0} ** 64,
    sni_len: usize = 0,
    alpn: [64]u8 = [_]u8{0} ** 64,
    alpn_len: usize = 0,
};

fn onClientHello(meta: ClientHelloMetadata, userdata: usize) void {
    var c: *Capture = @ptrFromInt(userdata);
    c.called = true;
    if (meta.server_name) |v| {
        c.sni_len = @min(v.len, c.sni.len);
        @memcpy(c.sni[0..c.sni_len], v[0..c.sni_len]);
    }
    if (meta.alpn_protocol) |v| {
        c.alpn_len = @min(v.len, c.alpn.len);
        @memcpy(c.alpn[0..c.alpn_len], v[0..c.alpn_len]);
    }
}

fn buildClientHelloRecord(allocator: std.mem.Allocator) ![]u8 {
    const sni_ext = tls13.messages.Extension{
        .extension_type = 0x0000,
        .data = try allocator.dupe(u8, &.{ 0x00, 0x0e, 0x00, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' }),
    };
    const alpn_ext = tls13.messages.Extension{
        .extension_type = 0x0010,
        .data = try allocator.dupe(u8, &.{ 0x00, 0x03, 0x02, 'h', '2' }),
    };
    var hello = tls13.messages.ClientHello{
        .random = [_]u8{0xaa} ** 32,
        .session_id = try allocator.dupe(u8, ""),
        .cipher_suites = try allocator.dupe(u16, &.{0x1301}),
        .compression_methods = try allocator.dupe(u8, &.{0x00}),
        .extensions = try allocator.dupe(tls13.messages.Extension, &.{ sni_ext, alpn_ext }),
    };
    defer hello.deinit(allocator);

    const body = try hello.encode(allocator);
    defer allocator.free(body);

    const hs_len = 4 + body.len;
    const rec_len = 5 + hs_len;
    const out = try allocator.alloc(u8, rec_len);

    out[0] = @intFromEnum(tls13.record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], tls13.record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(hs_len)), .big);
    out[5] = @intFromEnum(tls13.state.HandshakeType.client_hello);
    const len_u24 = tls13.handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &len_u24);
    @memcpy(out[9..], body);
    return out;
}

test "connection requires accept before ingest" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();

    try std.testing.expectError(error.NotAccepted, conn.ingest_tls_bytes(&.{ 22, 3, 3, 0, 0 }));
}

test "shutdown enqueues close_notify record and can be drained" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 1 });

    try conn.shutdown();

    var out: [16]u8 = undefined;
    const n = try conn.drain_tls_records(&out);
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 21), out[0]);
    try std.testing.expectEqual(@as(u8, 1), out[5]);
    try std.testing.expectEqual(@as(u8, 0), out[6]);
}

test "write plaintext enqueues application data record" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{});

    const written = try conn.write_plaintext("ping");
    try std.testing.expectEqual(@as(usize, 4), written);

    var out: [32]u8 = undefined;
    const n = try conn.drain_tls_records(&out);
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqual(@as(u8, 23), out[0]);
    try std.testing.expectEqual(@as(u16, tls13.record.tls_legacy_record_version), std.mem.readInt(u16, out[1..3], .big));
    try std.testing.expectEqual(@as(u16, 4), std.mem.readInt(u16, out[3..5], .big));
    try std.testing.expectEqualStrings("ping", out[5..9]);
}

test "write plaintext requires accept before use" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();

    try std.testing.expectError(error.NotAccepted, conn.write_plaintext("ping"));
}

test "ingest with alert intent maps invalid record to fatal outcome" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{});

    const out = try conn.ingest_tls_bytes_with_alert(&.{22, 3, 4, 0, 0});
    switch (out) {
        .fatal => |f| {
            try std.testing.expectEqual(error.InvalidLegacyVersion, f.err);
            try std.testing.expectEqual(tls13.alerts.AlertDescription.protocol_version, f.alert.description);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "client hello callback receives sni and alpn metadata" {
    var cap = Capture{};
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .on_client_hello = onClientHello,
        .callback_userdata = @intFromPtr(&cap),
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator);
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes_with_alert(rec);

    try std.testing.expect(cap.called);
    try std.testing.expectEqualStrings("example.com", cap.sni[0..cap.sni_len]);
    try std.testing.expectEqualStrings("h2", cap.alpn[0..cap.alpn_len]);
}

test "validate config rejects early-data without replay filter" {
    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
            .early_data = .{ .enabled = true },
        },
    }));
}

test "initChecked returns explicit config error instead of panic path" {
    try std.testing.expectError(error.InvalidConfiguration, Connection.initChecked(std.testing.allocator, .{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
            .early_data = .{ .enabled = true },
        },
    }));
}

test "ingest enforces handshake rate limiter before connected state" {
    var bucket = try rate_limit.TokenBucket.init(1, 1, 0);
    _ = bucket.allowAt(0); // drain single burst token so next handshake event is denied.
    const Hooks = struct {
        fn nowNs() u64 {
            return 0;
        }
    };

    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .handshake_rate_limiter = &bucket,
        .now_ns = Hooks.nowNs,
    });
    defer conn.deinit();
    conn.accept(.{});

    try std.testing.expectError(error.HandshakeRateLimited, conn.ingest_tls_bytes(&.{ 22, 3, 3, 0, 0 }));
}

test "ingest bypasses handshake rate limiter after connected state" {
    var bucket = try rate_limit.TokenBucket.init(1, 1, 0);
    _ = bucket.allowAt(0); // force limiter deny path if checked.
    const Hooks = struct {
        fn nowNs() u64 {
            return 0;
        }
    };

    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .handshake_rate_limiter = &bucket,
        .now_ns = Hooks.nowNs,
    });
    defer conn.deinit();
    conn.accept(.{});
    conn.engine.machine.state = .connected;

    try std.testing.expectError(error.IncompleteHeader, conn.ingest_tls_bytes(&.{}));
}
