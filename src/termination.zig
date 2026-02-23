const std = @import("std");
const cert_reload = @import("cert_reload.zig");
const metrics = @import("metrics.zig");
const rate_limit = @import("rate_limit.zig");
const tls13 = @import("tls13.zig");

pub const Config = struct {
    session: tls13.session.Config,
    dynamic_server_credentials: ?DynamicServerCredentials = null,
    on_client_hello: ?ClientHelloCallback = null,
    callback_userdata: usize = 0,
    client_hello_policy: ClientHelloPolicy = .{},
    handshake_rate_limiter: ?*rate_limit.TokenBucket = null,
    now_ns: ?NowNsFn = null,
    now_unix: ?NowUnixFn = null,
    cert_store: ?*cert_reload.Store = null,
    ticket_key_manager: ?*tls13.ticket_keys.Manager = null,
    on_log: ?LogCallback = null,
    log_userdata: usize = 0,
};

pub const ConnectionContext = struct {
    connection_id: u64 = 0,
    correlation_id: u64 = 0,
};

pub const Error = error{
    NotAccepted,
    OutputBufferTooSmall,
    InvalidConfiguration,
    HandshakeRateLimited,
    HandshakePolicyRejected,
} || tls13.session.EngineError || cert_reload.Error || std.mem.Allocator.Error;

pub const ClientHelloMetadata = struct {
    server_name: ?[]const u8 = null,
    alpn_protocol: ?[]const u8 = null,
};

pub const ClientHelloPolicy = struct {
    require_server_name: bool = false,
    require_alpn: bool = false,
    allowed_server_names: ?[]const []const u8 = null,
    allowed_alpn_protocols: ?[]const []const u8 = null,
};

pub const ClientHelloCallback = *const fn (meta: ClientHelloMetadata, userdata: usize) void;
pub const NowNsFn = *const fn () u64;
pub const NowUnixFn = *const fn () i64;
pub const LogCallback = *const fn (event: LogEvent, record: LogRecord, userdata: usize) void;

pub const LogEvent = enum {
    accepted,
    handshake_started,
    handshake_succeeded,
    handshake_failed,
    alert_sent,
    alert_received,
    shutdown,
};

pub const LogRecord = struct {
    connection_id: u64,
    correlation_id: u64,
    alert_description: ?tls13.alerts.AlertDescription = null,
};

pub const RuntimeBindings = struct {
    cert_generation: ?u64 = null,
    ticket_key_id: ?u32 = null,
};

pub const DynamicServerCredentials = struct {
    store: *cert_reload.Store,
    signature_scheme: u16 = 0x0807,
    sign_certificate_verify: ?tls13.session.SignCertificateVerifyFn = null,
    signer_userdata: usize = 0,
    auto_sign_from_store_ed25519: bool = false,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    engine: tls13.session.Engine,
    accepted: bool = false,
    pending_records: std.ArrayList([]u8),
    pending_plaintext: std.ArrayList(u8),
    telemetry: metrics.Metrics = .{},
    handshake_started_at_ns: ?u64 = null,
    handshake_finalized: bool = false,
    connection_id: u64 = 0,
    correlation_id: u64 = 0,
    active_cert_generation: ?u64 = null,
    active_ticket_key_id: ?u32 = null,
    observed_server_name: [255]u8 = [_]u8{0} ** 255,
    observed_server_name_len: usize = 0,
    observed_alpn: [255]u8 = [_]u8{0} ** 255,
    observed_alpn_len: usize = 0,
    dynamic_cert_chain: ?cert_reload.DerChain = null,
    dynamic_ed25519_bundle: ?cert_reload.Ed25519ServerCredentialsBundle = null,
    dynamic_cert_generation: ?u64 = null,

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
        if (self.dynamic_cert_chain) |*chain| chain.deinit(self.allocator);
        if (self.dynamic_ed25519_bundle) |*bundle| bundle.deinit(self.allocator);
        self.engine.deinit();
        for (self.pending_records.items) |frame| self.allocator.free(frame);
        self.pending_records.deinit(self.allocator);
        self.pending_plaintext.deinit(self.allocator);
    }

    pub fn accept(self: *Connection, ctx: ConnectionContext) void {
        self.accepted = true;
        self.connection_id = ctx.connection_id;
        self.correlation_id = if (ctx.correlation_id == 0) ctx.connection_id else ctx.correlation_id;
        self.emitLog(.accepted, null);
    }

    pub fn ingest_tls_bytes(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestResult {
        if (!self.accepted) return error.NotAccepted;

        try self.enforceHandshakeRateLimit();
        self.observeHandshakeStartIfNeeded();

        if (try self.inspectClientHelloAndCheckPolicy(record_bytes)) |alert_description| {
            try self.rejectClientHelloPolicy(alert_description);
            self.observeHandshakeFailureIfNeeded();
            return error.HandshakePolicyRejected;
        }

        try self.bindDynamicServerCredentialsIfNeeded();
        const result = self.engine.ingestRecord(record_bytes) catch |err| {
            self.observeHandshakeFailureIfNeeded();
            return err;
        };

        try self.collectActions(result);
        return result;
    }

    pub fn ingest_tls_bytes_with_alert(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestWithAlertOutcome {
        if (!self.accepted) return error.NotAccepted;

        try self.enforceHandshakeRateLimit();
        self.observeHandshakeStartIfNeeded();

        if (try self.inspectClientHelloAndCheckPolicy(record_bytes)) |alert_description| {
            try self.rejectClientHelloPolicy(alert_description);
            self.observeHandshakeFailureIfNeeded();
            return .{
                .fatal = .{
                    .err = error.HandshakePolicyRejected,
                    .alert = .{ .level = .fatal, .description = alert_description },
                },
            };
        }

        try self.bindDynamicServerCredentialsIfNeeded();
        const out = self.engine.ingestRecordWithAlertIntent(record_bytes);
        switch (out) {
            .ok => |res| {
                try self.collectActions(res);
                return .{ .ok = res };
            },
            .fatal => |f| {
                self.telemetry.observeAlert(@intFromEnum(f.alert.description));
                self.emitLog(.alert_received, f.alert.description);
                self.observeHandshakeFailureIfNeeded();
                return out;
            },
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
        const max_payload: usize = tls13.record.max_plaintext - 1;

        while (written < plaintext.len) {
            const remaining = plaintext.len - written;
            const chunk_len = @min(remaining, max_payload);
            const frame = try self.engine.buildApplicationDataRecord(
                self.allocator,
                plaintext[written .. written + chunk_len],
            );
            try self.pushPendingRecordOwned(frame);
            written += chunk_len;
        }

        return written;
    }

    pub fn shutdown(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        const frame = tls13.session.Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });

        try self.pushPendingRecord(frame[0..]);
        self.engine.machine.markClosed();
        self.emitLog(.shutdown, tls13.alerts.AlertDescription.close_notify);
    }

    pub fn on_transport_eof(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        try self.engine.onTransportEof();
    }

    pub fn snapshot_metrics(self: Connection) tls13.session.Metrics {
        return self.engine.snapshotMetrics();
    }

    pub fn snapshot_telemetry(self: Connection) metrics.Metrics {
        return self.telemetry;
    }

    pub fn snapshot_runtime_bindings(self: Connection) RuntimeBindings {
        return .{
            .cert_generation = self.active_cert_generation,
            .ticket_key_id = self.active_ticket_key_id,
        };
    }

    pub fn observedClientHelloServerName(self: *const Connection) ?[]const u8 {
        if (self.observed_server_name_len == 0) return null;
        return self.observed_server_name[0..self.observed_server_name_len];
    }

    pub fn observedClientHelloAlpn(self: *const Connection) ?[]const u8 {
        if (self.observed_alpn_len == 0) return null;
        return self.observed_alpn[0..self.observed_alpn_len];
    }

    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        if (self.engine.negotiated_alpn_len == 0) return null;
        return self.engine.negotiated_alpn[0..self.engine.negotiated_alpn_len];
    }

    fn collectActions(self: *Connection, result: tls13.session.IngestResult) Error!void {
        var i: usize = 0;
        while (i < result.action_count) : (i += 1) {
            switch (result.actions[i]) {
                .send_alert => |alert| {
                    self.telemetry.observeAlert(@intFromEnum(alert.description));
                    self.emitLog(.alert_sent, alert.description);
                    const frame = tls13.session.Engine.buildAlertRecord(alert);
                    try self.pushPendingRecord(frame[0..]);
                },
                .received_alert => |alert| {
                    self.telemetry.observeAlert(@intFromEnum(alert.description));
                    self.emitLog(.alert_received, alert.description);
                },
                .send_key_update => |req| {
                    self.telemetry.observeKeyUpdate();
                    const frame = try self.engine.buildProtectedKeyUpdateRecord(self.allocator, req);
                    try self.pushPendingRecordOwned(frame);
                    self.engine.onKeyUpdateRecordQueued();
                },
                .send_handshake_flight => |count| {
                    var idx: u8 = 0;
                    while (idx < count) : (idx += 1) {
                        const rec = self.engine.popOutboundRecord() orelse break;
                        try self.pushPendingRecordOwned(rec);
                    }
                },
                .key_update => {
                    self.telemetry.observeKeyUpdate();
                },
                .state_changed => |state_now| {
                    if (state_now == .connected) self.observeHandshakeSuccessIfNeeded();
                },
                .application_data => |data| {
                    try self.pending_plaintext.appendSlice(self.allocator, data);
                },
                else => {},
            }
        }
    }

    fn inspectClientHelloAndCheckPolicy(
        self: *Connection,
        record_bytes: []const u8,
    ) Error!?tls13.alerts.AlertDescription {
        const parsed = tls13.record.parseRecord(record_bytes) catch return null;
        if (parsed.header.content_type != .handshake) return null;

        var cursor = parsed.payload;
        while (cursor.len > 0) {
            const hs = tls13.handshake.parseOne(cursor) catch return null;
            const frame_len = 4 + @as(usize, @intCast(hs.header.length));
            cursor = cursor[frame_len..];

            if (hs.header.handshake_type != .client_hello) continue;
            var hello = tls13.messages.ClientHello.decode(self.allocator, hs.body) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                return null;
            };
            defer hello.deinit(self.allocator);

            const meta = ClientHelloMetadata{
                .server_name = extractServerName(hello.extensions),
                .alpn_protocol = extractFirstAlpn(hello.extensions),
            };
            self.captureClientHelloMetadata(meta);
            if (self.config.on_client_hello) |cb| cb(meta, self.config.callback_userdata);
            return self.evaluateClientHelloPolicy(meta);
        }
        return null;
    }

    fn rejectClientHelloPolicy(self: *Connection, alert_description: tls13.alerts.AlertDescription) Error!void {
        self.telemetry.observeAlert(@intFromEnum(alert_description));
        self.emitLog(.alert_sent, alert_description);
        const frame = tls13.session.Engine.buildAlertRecord(.{
            .level = .fatal,
            .description = alert_description,
        });
        try self.pushPendingRecord(frame[0..]);
    }

    fn evaluateClientHelloPolicy(
        self: Connection,
        meta: ClientHelloMetadata,
    ) ?tls13.alerts.AlertDescription {
        const policy = self.config.client_hello_policy;
        if (policy.require_server_name and meta.server_name == null) {
            return .unrecognized_name;
        }

        if (policy.allowed_server_names) |allowed| {
            const observed = meta.server_name orelse return .unrecognized_name;
            if (!containsServerName(allowed, observed)) return .unrecognized_name;
        }

        if (policy.require_alpn and meta.alpn_protocol == null) {
            return .no_application_protocol;
        }

        if (policy.allowed_alpn_protocols) |allowed| {
            const observed = meta.alpn_protocol orelse return .no_application_protocol;
            if (!containsExactProtocol(allowed, observed)) return .no_application_protocol;
        }

        return null;
    }

    fn pushPendingRecord(self: *Connection, bytes: []const u8) Error!void {
        const frame = try self.allocator.alloc(u8, bytes.len);
        errdefer self.allocator.free(frame);
        @memcpy(frame, bytes);
        try self.pending_records.append(self.allocator, frame);
    }

    fn pushPendingRecordOwned(self: *Connection, frame: []u8) Error!void {
        try self.pending_records.append(self.allocator, frame);
    }

    fn enforceHandshakeRateLimit(self: *Connection) Error!void {
        if (self.engine.machine.state == .connected) return;
        const limiter = self.config.handshake_rate_limiter orelse return;

        if (!limiter.allowAt(self.nowNs())) return error.HandshakeRateLimited;
    }

    fn observeHandshakeStartIfNeeded(self: *Connection) void {
        if (self.handshake_started_at_ns != null) return;

        if (self.engine.machine.state == .connected) return;
        self.handshake_started_at_ns = self.nowNs();
        self.telemetry.observeHandshakeStart();
        self.emitLog(.handshake_started, null);
    }

    fn observeHandshakeSuccessIfNeeded(self: *Connection) void {
        if (self.handshake_finalized) return;
        const started = self.handshake_started_at_ns orelse return;
        const now = self.nowNs();
        self.telemetry.observeHandshakeFinished(true, now - started);
        self.handshake_finalized = true;
        self.captureRuntimeBindings();
        self.emitLog(.handshake_succeeded, null);
    }

    fn observeHandshakeFailureIfNeeded(self: *Connection) void {
        if (self.handshake_finalized) return;
        const started = self.handshake_started_at_ns orelse self.nowNs();
        const now = self.nowNs();
        self.telemetry.observeHandshakeFinished(false, now - started);
        self.handshake_finalized = true;
        self.emitLog(.handshake_failed, null);
    }

    fn nowNs(self: Connection) u64 {
        if (self.config.now_ns) |f| return f();
        return @as(u64, @intCast(std.time.nanoTimestamp()));
    }

    fn nowUnix(self: Connection) i64 {
        if (self.config.now_unix) |f| return f();
        return std.time.timestamp();
    }

    fn captureRuntimeBindings(self: *Connection) void {
        // Log activate certificate generation
        if (self.dynamic_cert_generation) |gen| {
            self.active_cert_generation = gen;
        } else if (self.config.cert_store) |store| {
            if (store.snapshot()) |snap| {
                self.active_cert_generation = snap.generation;
            }
        }

        // Log activate ticket key ID
        if (self.config.ticket_key_manager) |manager| {
            const key = manager.currentEncryptKey(self.nowUnix()) catch return;
            self.active_ticket_key_id = key.key_id;
        }
    }

    fn emitLog(self: *Connection, event: LogEvent, alert_description: ?tls13.alerts.AlertDescription) void {
        const cb = self.config.on_log orelse return;
        cb(event, .{
            .connection_id = self.connection_id,
            .correlation_id = self.correlation_id,
            .alert_description = alert_description,
        }, self.config.log_userdata);
    }

    fn bindDynamicServerCredentialsIfNeeded(self: *Connection) Error!void {
        const dyn = self.config.dynamic_server_credentials orelse return;
        if (self.config.session.role != .server) return error.InvalidConfiguration;

        const snap = dyn.store.snapshot() orelse return error.NoActiveSnapshot;
        if (self.dynamic_cert_generation) |gen| {
            // Skip if credential is already latest
            if (gen == snap.generation) return;
        }

        if (self.dynamic_cert_chain) |*chain| {
            chain.deinit(self.allocator);
            self.dynamic_cert_chain = null;
        }
        if (self.dynamic_ed25519_bundle) |*bundle| {
            bundle.deinit(self.allocator);
            self.dynamic_ed25519_bundle = null;
        }

        // Release current cache and load new certification
        self.dynamic_cert_generation = snap.generation;
        if (dyn.auto_sign_from_store_ed25519) {
            const bundle = try dyn.store.loadActiveEd25519Bundle(self.allocator);
            self.dynamic_ed25519_bundle = bundle;
            self.engine.config.server_credentials = self.dynamic_ed25519_bundle.?.serverCredentials();
            return;
        }

        const chain = try dyn.store.decodeActiveCertificateChainDer(self.allocator);
        self.dynamic_cert_chain = chain;
        const sign_fn = dyn.sign_certificate_verify orelse return error.InvalidConfiguration;
        self.engine.config.server_credentials = .{
            .cert_chain_der = self.dynamic_cert_chain.?.certs,
            .signature_scheme = dyn.signature_scheme,
            .sign_certificate_verify = sign_fn,
            .signer_userdata = dyn.signer_userdata,
        };
    }

    fn captureClientHelloMetadata(self: *Connection, meta: ClientHelloMetadata) void {
        self.observed_server_name_len = 0;
        self.observed_alpn_len = 0;

        if (meta.server_name) |name| {
            const n = @min(name.len, self.observed_server_name.len);
            @memcpy(self.observed_server_name[0..n], name[0..n]);
            self.observed_server_name_len = n;
        }
        if (meta.alpn_protocol) |alpn| {
            const n = @min(alpn.len, self.observed_alpn.len);
            @memcpy(self.observed_alpn[0..n], alpn[0..n]);
            self.observed_alpn_len = n;
        }
    }
};

pub fn validateConfig(config: Config) Error!void {
    tls13.session.validateConfig(config.session) catch {
        return error.InvalidConfiguration;
    };
    if (config.dynamic_server_credentials) |dyn| {
        if (config.session.server_credentials != null) return error.InvalidConfiguration;

        if (config.session.role != .server) return error.InvalidConfiguration;

        if (dyn.auto_sign_from_store_ed25519) {
            if (dyn.signature_scheme != 0x0807) return error.InvalidConfiguration;

            if (dyn.sign_certificate_verify != null) return error.InvalidConfiguration;
        } else if (dyn.sign_certificate_verify == null) {
            return error.InvalidConfiguration;
        }
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

fn containsServerName(allowed: []const []const u8, observed: []const u8) bool {
    for (allowed) |name| {
        if (std.ascii.eqlIgnoreCase(name, observed)) return true;
    }
    return false;
}

fn containsExactProtocol(allowed: []const []const u8, observed: []const u8) bool {
    for (allowed) |name| {
        if (std.mem.eql(u8, name, observed)) return true;
    }
    return false;
}

const Capture = struct {
    called: bool = false,
    sni: [64]u8 = [_]u8{0} ** 64,
    sni_len: usize = 0,
    alpn: [64]u8 = [_]u8{0} ** 64,
    alpn_len: usize = 0,
};

const LogCapture = struct {
    seen: [16]LogEvent = undefined,
    seen_count: usize = 0,
    last_record: LogRecord = .{ .connection_id = 0, .correlation_id = 0 },
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

fn onLog(event: LogEvent, record: LogRecord, userdata: usize) void {
    var cap: *LogCapture = @ptrFromInt(userdata);
    if (cap.seen_count < cap.seen.len) {
        cap.seen[cap.seen_count] = event;
        cap.seen_count += 1;
    }
    cap.last_record = record;
}

fn fixedNowUnix() i64 {
    return 10;
}

const ClientHelloBuildOptions = struct {
    include_sni: bool = true,
    include_alpn: bool = true,
    server_name: []const u8 = "example.com",
    alpn: []const u8 = "h2",
};

fn buildClientHelloRecord(allocator: std.mem.Allocator, opts: ClientHelloBuildOptions) ![]u8 {
    var ext_list = std.ArrayList(tls13.messages.Extension).empty;
    defer ext_list.deinit(allocator);

    const versions_data = try allocator.dupe(u8, &.{ 0x02, 0x03, 0x04 });
    try ext_list.append(allocator, .{
        .extension_type = 0x002b,
        .data = versions_data,
    });

    var groups_data = try allocator.alloc(u8, 4);
    std.mem.writeInt(u16, groups_data[0..2], 2, .big);
    std.mem.writeInt(u16, groups_data[2..4], tls13.session.named_group_x25519, .big);
    try ext_list.append(allocator, .{
        .extension_type = 0x000a,
        .data = groups_data,
    });

    const kp = std.crypto.dh.X25519.KeyPair.generate();
    var key_share_data = try allocator.alloc(u8, 2 + 2 + 2 + kp.public_key.len);
    std.mem.writeInt(u16, key_share_data[0..2], @as(u16, @intCast(2 + 2 + kp.public_key.len)), .big);
    std.mem.writeInt(u16, key_share_data[2..4], tls13.session.named_group_x25519, .big);
    std.mem.writeInt(u16, key_share_data[4..6], @as(u16, @intCast(kp.public_key.len)), .big);
    @memcpy(key_share_data[6..], &kp.public_key);
    try ext_list.append(allocator, .{
        .extension_type = 0x0033,
        .data = key_share_data,
    });

    if (opts.include_sni) {
        const sni_data = try allocator.alloc(u8, 5 + opts.server_name.len);
        sni_data[0] = 0;
        sni_data[1] = @as(u8, @intCast(3 + opts.server_name.len));
        sni_data[2] = 0;
        std.mem.writeInt(u16, sni_data[3..5], @as(u16, @intCast(opts.server_name.len)), .big);
        @memcpy(sni_data[5..], opts.server_name);
        try ext_list.append(allocator, .{
            .extension_type = 0x0000,
            .data = sni_data,
        });
    }
    if (opts.include_alpn) {
        const alpn_data = try allocator.alloc(u8, 3 + opts.alpn.len);
        alpn_data[0] = 0;
        alpn_data[1] = @as(u8, @intCast(1 + opts.alpn.len));
        alpn_data[2] = @as(u8, @intCast(opts.alpn.len));
        @memcpy(alpn_data[3..], opts.alpn);
        try ext_list.append(allocator, .{
            .extension_type = 0x0010,
            .data = alpn_data,
        });
    }

    var hello = tls13.messages.ClientHello{
        .random = [_]u8{0xaa} ** 32,
        .session_id = try allocator.dupe(u8, ""),
        .cipher_suites = try allocator.dupe(u16, &.{0x1301}),
        .compression_methods = try allocator.dupe(u8, &.{0x00}),
        .extensions = try ext_list.toOwnedSlice(allocator),
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
    conn.engine.machine.state = .connected;
    // Seed application traffic keys directly so write path does not depend on handshake derivation.
    @memset(conn.engine.app_write_key[0..16], 0x11);
    @memset(conn.engine.app_write_iv[0..12], 0x22);
    conn.engine.app_key_len = 16;
    conn.engine.app_tag_len = 16;

    const written = try conn.write_plaintext("ping");
    try std.testing.expectEqual(@as(usize, 4), written);

    var out: [32]u8 = undefined;
    const n = try conn.drain_tls_records(&out);
    try std.testing.expectEqual(@as(usize, 26), n);
    try std.testing.expectEqual(@as(u8, 23), out[0]);
    try std.testing.expectEqual(@as(u16, tls13.record.tls_legacy_record_version), std.mem.readInt(u16, out[1..3], .big));
    try std.testing.expectEqual(@as(u16, 21), std.mem.readInt(u16, out[3..5], .big));
    try std.testing.expect(!std.mem.eql(u8, out[5..9], "ping"));
}

test "write plaintext before handshake completion is rejected" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{});

    try std.testing.expectError(error.ApplicationCipherNotReady, conn.write_plaintext("ping"));
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

    const out = try conn.ingest_tls_bytes_with_alert(&.{ 22, 3, 4, 0, 0 });
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

    const rec = try buildClientHelloRecord(std.testing.allocator, .{});
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes_with_alert(rec);

    try std.testing.expect(cap.called);
    try std.testing.expectEqualStrings("example.com", cap.sni[0..cap.sni_len]);
    try std.testing.expectEqualStrings("h2", cap.alpn[0..cap.alpn_len]);
}

test "connection exposes observed and negotiated client hello metadata" {
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out_signature: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out_signature.len < ed25519_len) return error.NoSpaceLeft;
            @memset(out_signature[0..ed25519_len], 0x44);
            return ed25519_len;
        }
    };
    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const chain = [_][]const u8{cert_der[0..]};

    var conn = Connection.init(std.testing.allocator, .{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
            .server_credentials = .{
                .cert_chain_der = &chain,
                .signature_scheme = 0x0807,
                .sign_certificate_verify = Hooks.sign,
            },
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    try std.testing.expect(conn.observedClientHelloServerName() == null);
    try std.testing.expect(conn.observedClientHelloAlpn() == null);
    try std.testing.expect(conn.negotiatedAlpn() == null);

    const rec = try buildClientHelloRecord(std.testing.allocator, .{
        .server_name = "api.example.com",
        .alpn = "h2",
    });
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes(rec);

    try std.testing.expectEqualStrings("api.example.com", conn.observedClientHelloServerName().?);
    try std.testing.expectEqualStrings("h2", conn.observedClientHelloAlpn().?);
    try std.testing.expectEqualStrings("h2", conn.negotiatedAlpn().?);
}

test "client hello policy rejects mismatched server name with unrecognized_name alert" {
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .client_hello_policy = .{
            .allowed_server_names = &.{"api.example.com"},
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{
        .server_name = "example.com",
    });
    defer std.testing.allocator.free(rec);

    const out = try conn.ingest_tls_bytes_with_alert(rec);
    switch (out) {
        .fatal => |f| try std.testing.expectEqual(
            tls13.alerts.AlertDescription.unrecognized_name,
            f.alert.description,
        ),
        .ok => return error.TestExpectedFatal,
    }

    var frame: [64]u8 = undefined;
    const n = try conn.drain_tls_records(&frame);
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 21), frame[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls13.alerts.AlertDescription.unrecognized_name)), frame[6]);
}

test "client hello policy rejects mismatched ALPN with no_application_protocol alert" {
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .client_hello_policy = .{
            .allowed_alpn_protocols = &.{"h3"},
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{
        .alpn = "h2",
    });
    defer std.testing.allocator.free(rec);

    const out = try conn.ingest_tls_bytes_with_alert(rec);
    switch (out) {
        .fatal => |f| try std.testing.expectEqual(
            tls13.alerts.AlertDescription.no_application_protocol,
            f.alert.description,
        ),
        .ok => return error.TestExpectedFatal,
    }
}

test "client hello policy enforces required server name" {
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .client_hello_policy = .{
            .require_server_name = true,
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{
        .include_sni = false,
    });
    defer std.testing.allocator.free(rec);

    try std.testing.expectError(error.HandshakePolicyRejected, conn.ingest_tls_bytes(rec));
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

test "validate config rejects debug keylog without callback" {
    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
            .enable_debug_keylog = true,
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

test "handshake telemetry tracks start and failure on ingest error" {
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});

    try std.testing.expectError(error.IncompleteHeader, conn.ingest_tls_bytes(&.{}));
    const snapshot = conn.snapshot_telemetry();
    try std.testing.expectEqual(@as(u64, 1), snapshot.handshake_started);
    try std.testing.expectEqual(@as(u64, 1), snapshot.handshake_fail);
}

test "collect actions counts alerts and keyupdates in telemetry" {
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});

    var res = tls13.session.IngestResult{
        .consumed = 0,
        .actions = undefined,
        .action_count = 3,
    };
    res.actions[0] = .{ .send_alert = .{ .level = .warning, .description = .close_notify } };
    res.actions[1] = .{ .received_alert = .{ .level = .warning, .description = .close_notify } };
    res.actions[2] = .{ .key_update = .update_requested };
    try conn.collectActions(res);

    const snapshot = conn.snapshot_telemetry();
    try std.testing.expectEqual(@as(u64, 2), snapshot.alert_counts[@intFromEnum(tls13.alerts.AlertDescription.close_notify)]);
    try std.testing.expectEqual(@as(u64, 1), snapshot.keyupdate_count);
}

test "logging callback includes correlation id and lifecycle events" {
    var log_cap = LogCapture{};
    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .on_log = onLog,
        .log_userdata = @intFromPtr(&log_cap),
    });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 10, .correlation_id = 77 });

    try std.testing.expectError(error.IncompleteHeader, conn.ingest_tls_bytes(&.{}));
    try conn.shutdown();

    try std.testing.expect(log_cap.seen_count >= 3);
    try std.testing.expectEqual(LogEvent.accepted, log_cap.seen[0]);
    try std.testing.expectEqual(@as(u64, 10), log_cap.last_record.connection_id);
    try std.testing.expectEqual(@as(u64, 77), log_cap.last_record.correlation_id);
}

test "handshake success captures cert generation and ticket key id bindings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-X" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-X" });
    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    var manager = tls13.ticket_keys.Manager.init();
    try manager.rotate(.{
        .key_id = 88,
        .material = [_]u8{0xaa} ** 32,
        .not_before_unix = 0,
        .not_after_unix = 100,
    });

    var conn = Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .cert_store = &store,
        .ticket_key_manager = &manager,
        .now_unix = fixedNowUnix,
    });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 1 });
    conn.handshake_started_at_ns = conn.nowNs();

    var res = tls13.session.IngestResult{
        .consumed = 0,
        .actions = undefined,
        .action_count = 1,
    };
    res.actions[0] = .{ .state_changed = .connected };
    try conn.collectActions(res);

    const bindings = conn.snapshot_runtime_bindings();
    try std.testing.expectEqual(@as(?u64, 1), bindings.cert_generation);
    try std.testing.expectEqual(@as(?u32, 88), bindings.ticket_key_id);
}

test "validate config rejects dynamic credentials for client role" {
    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, _: []u8, _: usize) anyerror!usize {
            return 0;
        }
    };

    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .sign_certificate_verify = Hooks.sign,
        },
    }));
}

test "validate config rejects mixed static and dynamic server credentials" {
    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, _: []u8, _: usize) anyerror!usize {
            return 0;
        }
    };
    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const chain = [_][]const u8{cert_der[0..]};

    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
            .server_credentials = .{
                .cert_chain_der = &chain,
                .signature_scheme = 0x0807,
                .sign_certificate_verify = Hooks.sign,
            },
        },
        .dynamic_server_credentials = .{
            .store = &store,
            .sign_certificate_verify = Hooks.sign,
        },
    }));
}

test "validate config rejects dynamic manual mode without signer callback" {
    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .signature_scheme = 0x0807,
        },
    }));
}

test "validate config rejects dynamic auto ed25519 mode with mismatched signature scheme" {
    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .signature_scheme = 0x0804,
            .auto_sign_from_store_ed25519 = true,
        },
    }));
}

test "dynamic server credentials bind active cert store snapshot before server handshake" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MAMCAQE=
        \\-----END CERTIFICATE-----
        \\
    ;
    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = cert_pem });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-X" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out_signature: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out_signature.len < ed25519_len) return error.NoSpaceLeft;
            @memset(out_signature[0..ed25519_len], 0x45);
            return ed25519_len;
        }
    };

    var conn = try Connection.initChecked(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = Hooks.sign,
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{});
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes(rec);

    try std.testing.expectEqual(@as(?u64, 1), conn.dynamic_cert_generation);
    try std.testing.expect(conn.engine.config.server_credentials != null);
}

test "dynamic server credentials fail closed when active snapshot is missing" {
    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();

    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out_signature: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out_signature.len < ed25519_len) return error.NoSpaceLeft;
            @memset(out_signature[0..ed25519_len], 0x46);
            return ed25519_len;
        }
    };

    var conn = try Connection.initChecked(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = Hooks.sign,
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{});
    defer std.testing.allocator.free(rec);
    try std.testing.expectError(error.NoActiveSnapshot, conn.ingest_tls_bytes(rec));
}

test "dynamic auto ed25519 mode binds signer bundle from store" {
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

    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path);

    var conn = try Connection.initChecked(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .auto_sign_from_store_ed25519 = true,
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{});
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes(rec);

    try std.testing.expect(conn.dynamic_ed25519_bundle != null);
    const creds = conn.engine.config.server_credentials orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 0x0807), creds.signature_scheme);
    const sign_fn = creds.sign_certificate_verify orelse return error.TestUnexpectedResult;
    var sig: [128]u8 = undefined;
    const sig_len = try sign_fn("th", 0x0807, sig[0..], creds.signer_userdata);
    try std.testing.expectEqual(@as(usize, 64), sig_len);
}

test "runtime bindings pin dynamic cert generation used by connection" {
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

    var store = cert_reload.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cert_path, key_path); // generation=1

    var conn = try Connection.initChecked(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
        .dynamic_server_credentials = .{
            .store = &store,
            .auto_sign_from_store_ed25519 = true,
        },
    });
    defer conn.deinit();
    conn.accept(.{});

    const rec = try buildClientHelloRecord(std.testing.allocator, .{});
    defer std.testing.allocator.free(rec);
    _ = try conn.ingest_tls_bytes(rec);
    try std.testing.expectEqual(@as(?u64, 1), conn.dynamic_cert_generation);

    // Rotate store after this connection already bound generation=1.
    _ = try store.reloadFromFiles(cert_path, key_path); // generation=2

    conn.handshake_started_at_ns = conn.nowNs();
    var res = tls13.session.IngestResult{
        .consumed = 0,
        .actions = undefined,
        .action_count = 1,
    };
    res.actions[0] = .{ .state_changed = .connected };
    try conn.collectActions(res);

    const bindings = conn.snapshot_runtime_bindings();
    try std.testing.expectEqual(@as(?u64, 1), bindings.cert_generation);
}
