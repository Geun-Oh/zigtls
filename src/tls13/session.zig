const std = @import("std");
const builtin = @import("builtin");
const alerts = @import("alerts.zig");
const early_data = @import("early_data.zig");
const handshake = @import("handshake.zig");
const keyschedule = @import("keyschedule.zig");
const messages = @import("messages.zig");
const record = @import("record.zig");
const state = @import("state.zig");

pub const default_signature_algorithms = [_]u16{
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0807, // ed25519
};

pub const KeyLogCallback = *const fn (label: []const u8, secret: []const u8, userdata: usize) void;

pub const Config = struct {
    role: state.Role,
    suite: keyschedule.CipherSuite,
    early_data: EarlyDataConfig = .{},
    allowed_signature_algorithms: []const u16 = &default_signature_algorithms,
    enable_debug_keylog: bool = false,
    keylog_callback: ?KeyLogCallback = null,
    keylog_userdata: usize = 0,
};

pub const EarlyDataConfig = struct {
    enabled: bool = false,
    replay_filter: ?*early_data.ReplayFilter = null,
    replay_node_id: u32 = 0,
    replay_epoch: u64 = 0,
    max_ticket_age_sec: u64 = 600,
    max_ticket_len: usize = 4096,
};

pub const Metrics = struct {
    handshake_messages: u64 = 0,
    alerts_received: u64 = 0,
    keyupdate_messages: u64 = 0,
    connected_transitions: u64 = 0,
    truncation_events: u64 = 0,
};

pub const Action = union(enum) {
    handshake: state.HandshakeType,
    hello_retry_request: void,
    key_update: handshake.KeyUpdateRequest,
    send_key_update: handshake.KeyUpdateRequest,
    received_alert: alerts.Alert,
    send_alert: alerts.Alert,
    state_changed: state.ConnectionState,
    application_data: []const u8,
};

pub const IngestResult = struct {
    consumed: usize,
    actions: [8]Action,
    action_count: usize,

    fn init(consumed: usize) IngestResult {
        return .{
            .consumed = consumed,
            .actions = undefined,
            .action_count = 0,
        };
    }

    fn push(self: *IngestResult, action: Action) !void {
        if (self.action_count >= self.actions.len) return error.TooManyActions;
        self.actions[self.action_count] = action;
        self.action_count += 1;
    }
};

pub const FatalFailure = struct {
    err: anyerror,
    alert: alerts.Alert,
};

pub const IngestWithAlertOutcome = union(enum) {
    ok: IngestResult,
    fatal: FatalFailure,
};

pub const EngineError = error{
    TooManyActions,
    UnsupportedRecordType,
    EarlyDataRejected,
    MissingReplayFilter,
    EarlyDataTicketExpired,
    EarlyDataTicketTooLarge,
    TruncationDetected,
    InvalidHelloMessage,
    InvalidCertificateMessage,
    InvalidCertificateVerifyMessage,
    InvalidFinishedMessage,
    InvalidEncryptedExtensionsMessage,
    InvalidNewSessionTicketMessage,
    MissingRequiredClientHelloExtension,
    MissingRequiredServerHelloExtension,
    MissingRequiredHrrExtension,
    UnexpectedServerHelloExtension,
    UnexpectedHrrExtension,
    ConfiguredCipherSuiteMismatch,
    InvalidSupportedVersionExtension,
    InvalidCompressionMethod,
    MissingPskKeyExchangeModes,
    InvalidPskKeyExchangeModes,
    MissingPskDheKeyExchangeMode,
    InvalidPskBinder,
    InvalidPskBinderLength,
    PskBinderCountMismatch,
    DowngradeDetected,
    UnsupportedSignatureAlgorithm,
} || record.ParseError || handshake.ParseError || handshake.KeyUpdateError || state.TransitionError || alerts.DecodeError;

const ext_server_name: u16 = 0x0000;
const ext_supported_groups: u16 = 0x000a;
const ext_alpn: u16 = 0x0010;
const ext_supported_versions: u16 = 0x002b;
const ext_cookie: u16 = 0x002c;
const ext_key_share: u16 = 0x0033;
const ext_pre_shared_key: u16 = 0x0029;
const ext_psk_key_exchange_modes: u16 = 0x002d;

const Transcript = union(enum) {
    sha256: std.crypto.hash.sha2.Sha256,
    sha384: std.crypto.hash.sha2.Sha384,

    fn init(suite: keyschedule.CipherSuite) Transcript {
        return switch (suite) {
            .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => .{ .sha256 = std.crypto.hash.sha2.Sha256.init(.{}) },
            .tls_aes_256_gcm_sha384 => .{ .sha384 = std.crypto.hash.sha2.Sha384.init(.{}) },
        };
    }

    fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.*) {
            .sha256 => |*h| h.update(bytes),
            .sha384 => |*h| h.update(bytes),
        }
    }
};

pub const TrafficSecret = union(enum) {
    sha256: [32]u8,
    sha384: [48]u8,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    config: Config,
    machine: state.Machine,
    transcript: Transcript,
    latest_secret: ?TrafficSecret = null,
    early_data_idempotent: bool = false,
    early_data_within_window: bool = true,
    early_data_ticket: ?[]u8 = null,
    saw_close_notify: bool = false,
    metrics: Metrics = .{},

    pub fn init(allocator: std.mem.Allocator, config: Config) Engine {
        if (config.early_data.enabled and config.early_data.replay_filter == null) {
            @panic("0-RTT enabled but replay filter is not configured");
        }
        return .{
            .allocator = allocator,
            .config = config,
            .machine = state.Machine.init(config.role),
            .transcript = Transcript.init(config.suite),
        };
    }

    pub fn deinit(self: *Engine) void {
        self.zeroizeLatestSecret();
        self.clearEarlyDataTicket();
    }

    pub fn beginEarlyData(self: *Engine, ticket: []const u8, idempotent: bool) !void {
        if (ticket.len > self.config.early_data.max_ticket_len) return error.EarlyDataTicketTooLarge;
        self.clearEarlyDataTicket();
        self.early_data_ticket = try self.allocator.alloc(u8, ticket.len);
        @memcpy(self.early_data_ticket.?, ticket);
        self.early_data_idempotent = idempotent;
        self.early_data_within_window = true;
    }

    pub fn beginEarlyDataWithTimes(
        self: *Engine,
        ticket: []const u8,
        idempotent: bool,
        issued_at_sec: i64,
        now_sec: i64,
    ) !void {
        if (issued_at_sec > now_sec) return error.EarlyDataTicketExpired;
        const age = @as(u64, @intCast(now_sec - issued_at_sec));
        if (age > self.config.early_data.max_ticket_age_sec) return error.EarlyDataTicketExpired;
        try self.beginEarlyData(ticket, idempotent);
    }

    pub fn onTransportEof(self: *Engine) EngineError!void {
        if (!self.saw_close_notify) {
            self.metrics.truncation_events += 1;
            return error.TruncationDetected;
        }
        self.machine.markClosed();
    }

    pub fn snapshotMetrics(self: Engine) Metrics {
        return self.metrics;
    }

    pub fn ingestRecord(self: *Engine, record_bytes: []const u8) EngineError!IngestResult {
        const parsed = try record.parseRecord(record_bytes);
        var result = IngestResult.init(5 + parsed.payload.len);

        switch (parsed.header.content_type) {
            .handshake => {
                var cursor = parsed.payload;
                while (cursor.len > 0) {
                    const frame = try handshake.parseOne(cursor);
                    const frame_len = 4 + @as(usize, @intCast(frame.header.length));
                    self.transcript.update(cursor[0..frame_len]);
                    try self.validateHandshakeBody(frame.header.handshake_type, frame.body);
                    self.metrics.handshake_messages += 1;

                    const prev_state = self.machine.state;
                    const event = handshake.classifyEvent(frame);
                    try self.machine.onEvent(event);
                    try result.push(.{ .handshake = frame.header.handshake_type });
                    if (event == .hello_retry_request) {
                        try result.push(.{ .hello_retry_request = {} });
                    }
                    if (frame.header.handshake_type == .key_update) {
                        self.metrics.keyupdate_messages += 1;
                        const req = try handshake.parseKeyUpdateRequest(frame.body);
                        self.ratchetLatestTrafficSecret();
                        try result.push(.{ .key_update = req });
                        if (req == .update_requested) {
                            try result.push(.{ .send_key_update = .update_not_requested });
                        }
                    }
                    try result.push(.{ .state_changed = self.machine.state });

                    if (prev_state != .connected and self.machine.state == .connected) {
                        self.metrics.connected_transitions += 1;
                        self.latest_secret = self.deriveApplicationTrafficSecret();
                        self.emitDebugKeyLog(self.keylogInitialLabel());
                    }
                    cursor = frame.rest;
                }
            },
            .alert => {
                const alert = try alerts.Alert.decode(parsed.payload);
                self.metrics.alerts_received += 1;
                try result.push(.{ .received_alert = alert });
                if (alert.description == .close_notify) {
                    self.saw_close_notify = true;
                    self.machine.markClosed();
                } else {
                    self.machine.markClosing();
                }
                try result.push(.{ .state_changed = self.machine.state });
            },
            .application_data => {
                if (self.machine.state != .connected) {
                    if (!self.config.early_data.enabled) return error.EarlyDataRejected;
                    if (!self.early_data_idempotent) return error.EarlyDataRejected;
                    if (!self.early_data_within_window) return error.EarlyDataTicketExpired;
                    const replay_filter = self.config.early_data.replay_filter orelse return error.MissingReplayFilter;
                    const ticket = self.early_data_ticket orelse return error.EarlyDataRejected;
                    const scope: early_data.ReplayScopeKey = .{
                        .node_id = self.config.early_data.replay_node_id,
                        .epoch = self.config.early_data.replay_epoch,
                    };
                    if (replay_filter.seenOrInsertScoped(scope, ticket)) return error.EarlyDataRejected;
                }
                try result.push(.{ .application_data = parsed.payload });
            },
            else => return error.UnsupportedRecordType,
        }

        return result;
    }

    pub fn ingestRecordWithAlertIntent(self: *Engine, record_bytes: []const u8) IngestWithAlertOutcome {
        const result = self.ingestRecord(record_bytes) catch |err| {
            self.machine.markClosing();
            return .{
                .fatal = .{
                    .err = err,
                    .alert = classifyErrorAlert(err),
                },
            };
        };
        return .{ .ok = result };
    }

    pub fn buildAlertRecord(alert: alerts.Alert) [7]u8 {
        const payload = alert.encode();
        const header = record.Header{
            .content_type = .alert,
            .legacy_version = record.tls_legacy_record_version,
            .length = payload.len,
        };

        var frame: [7]u8 = undefined;
        const encoded = header.encode();
        @memcpy(frame[0..5], &encoded);
        @memcpy(frame[5..7], &payload);
        return frame;
    }

    pub fn buildKeyUpdateRecord(request: handshake.KeyUpdateRequest) [10]u8 {
        var frame: [10]u8 = undefined;
        frame[0] = @intFromEnum(record.ContentType.handshake);
        frame[1] = 0x03;
        frame[2] = 0x03;
        std.mem.writeInt(u16, frame[3..5], 5, .big);
        frame[5] = @intFromEnum(state.HandshakeType.key_update);
        const len = handshake.writeU24(1);
        @memcpy(frame[6..9], &len);
        frame[9] = @intFromEnum(request);
        return frame;
    }

    fn deriveApplicationTrafficSecret(self: *Engine) TrafficSecret {
        return switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => blk: {
                const hasher = switch (self.transcript) {
                    .sha256 => |h| h,
                    .sha384 => unreachable,
                };
                var digest: [32]u8 = undefined;
                var h = hasher;
                h.final(&digest);
                const secret = keyschedule.extract(.tls_aes_128_gcm_sha256, "", &digest);
                break :blk .{ .sha256 = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, secret, "c ap traffic", &digest, 32) };
            },
            .tls_chacha20_poly1305_sha256 => blk: {
                const hasher = switch (self.transcript) {
                    .sha256 => |h| h,
                    .sha384 => unreachable,
                };
                var digest: [32]u8 = undefined;
                var h = hasher;
                h.final(&digest);
                const secret = keyschedule.extract(.tls_chacha20_poly1305_sha256, "", &digest);
                break :blk .{ .sha256 = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, secret, "c ap traffic", &digest, 32) };
            },
            .tls_aes_256_gcm_sha384 => blk: {
                const hasher = switch (self.transcript) {
                    .sha256 => unreachable,
                    .sha384 => |h| h,
                };
                var digest: [48]u8 = undefined;
                var h = hasher;
                h.final(&digest);
                const secret = keyschedule.extract(.tls_aes_256_gcm_sha384, "", &digest);
                break :blk .{ .sha384 = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, secret, "c ap traffic", &digest, 48) };
            },
        };
    }

    fn ratchetLatestTrafficSecret(self: *Engine) void {
        const cur = self.latest_secret orelse return;
        self.latest_secret = switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => switch (cur) {
                .sha256 => |secret| .{ .sha256 = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, secret, "traffic upd", "", 32) },
                .sha384 => unreachable,
            },
            .tls_chacha20_poly1305_sha256 => switch (cur) {
                .sha256 => |secret| .{ .sha256 = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, secret, "traffic upd", "", 32) },
                .sha384 => unreachable,
            },
            .tls_aes_256_gcm_sha384 => switch (cur) {
                .sha256 => unreachable,
                .sha384 => |secret| .{ .sha384 = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, secret, "traffic upd", "", 48) },
            },
        };
        self.emitDebugKeyLog(self.keylogNextLabel());
    }

    fn keylogInitialLabel(self: Engine) []const u8 {
        return switch (self.config.role) {
            .client => "CLIENT_TRAFFIC_SECRET_0",
            .server => "SERVER_TRAFFIC_SECRET_0",
        };
    }

    fn keylogNextLabel(self: Engine) []const u8 {
        return switch (self.config.role) {
            .client => "CLIENT_TRAFFIC_SECRET_N",
            .server => "SERVER_TRAFFIC_SECRET_N",
        };
    }

    fn emitDebugKeyLog(self: *Engine, label: []const u8) void {
        if (builtin.mode != .Debug) return;
        if (!self.config.enable_debug_keylog) return;
        const cb = self.config.keylog_callback orelse return;
        const secret = self.latest_secret orelse return;
        switch (secret) {
            .sha256 => |s| cb(label, s[0..], self.config.keylog_userdata),
            .sha384 => |s| cb(label, s[0..], self.config.keylog_userdata),
        }
    }

    fn clearEarlyDataTicket(self: *Engine) void {
        if (self.early_data_ticket) |ticket| {
            std.crypto.secureZero(u8, ticket);
            self.allocator.free(ticket);
            self.early_data_ticket = null;
        }
    }

    fn zeroizeLatestSecret(self: *Engine) void {
        if (self.latest_secret) |*secret| {
            switch (secret.*) {
                .sha256 => |*s| std.crypto.secureZero(u8, s[0..]),
                .sha384 => |*s| std.crypto.secureZero(u8, s[0..]),
            }
            self.latest_secret = null;
        }
    }

    fn validateHandshakeBody(self: *Engine, handshake_type: state.HandshakeType, body: []const u8) EngineError!void {
        switch (handshake_type) {
            .server_hello => {
                var sh = messages.ServerHello.decode(self.allocator, body) catch return error.InvalidHelloMessage;
                defer sh.deinit(self.allocator);
                if (self.config.role == .client and hasDowngradeMarker(sh.random)) {
                    return error.DowngradeDetected;
                }
                if (self.config.role == .client) {
                    if (sh.compression_method != 0x00) return error.InvalidCompressionMethod;
                    if (sh.cipher_suite != configuredCipherSuiteCodepoint(self.config.suite)) {
                        return error.ConfiguredCipherSuiteMismatch;
                    }
                    if (messages.serverHelloHasHrrRandom(body)) {
                        try self.requireHrrExtensions(sh.extensions);
                    } else {
                        try self.requireServerHelloExtensions(sh.extensions);
                    }
                }
            },
            .client_hello => {
                var ch = messages.ClientHello.decode(self.allocator, body) catch return error.InvalidHelloMessage;
                defer ch.deinit(self.allocator);
                if (self.config.role == .server) {
                    if (!containsCipherSuite(ch.cipher_suites, configuredCipherSuiteCodepoint(self.config.suite))) {
                        return error.ConfiguredCipherSuiteMismatch;
                    }
                    try self.requireClientHelloExtensions(ch.compression_methods, ch.extensions);
                }
            },
            .certificate => {
                var cert = messages.CertificateMsg.decode(self.allocator, body) catch return error.InvalidCertificateMessage;
                defer cert.deinit(self.allocator);
            },
            .certificate_verify => {
                var cert_verify = messages.CertificateVerifyMsg.decode(self.allocator, body) catch return error.InvalidCertificateVerifyMessage;
                defer cert_verify.deinit(self.allocator);
                if (!self.isAllowedSignatureAlgorithm(cert_verify.algorithm)) {
                    return error.UnsupportedSignatureAlgorithm;
                }
            },
            .finished => {
                if (body.len != keyschedule.digestLen(self.config.suite)) {
                    return error.InvalidFinishedMessage;
                }
            },
            .encrypted_extensions => {
                var ee = messages.EncryptedExtensions.decode(self.allocator, body) catch return error.InvalidEncryptedExtensionsMessage;
                defer ee.deinit(self.allocator);
            },
            .new_session_ticket => {
                var nst = messages.NewSessionTicketMsg.decode(self.allocator, body) catch return error.InvalidNewSessionTicketMessage;
                defer nst.deinit(self.allocator);
            },
            else => {},
        }
    }

    fn isAllowedSignatureAlgorithm(self: Engine, algorithm: u16) bool {
        for (self.config.allowed_signature_algorithms) |allowed| {
            if (allowed == algorithm) return true;
        }
        return false;
    }

    fn requireClientHelloExtensions(self: Engine, compression_methods: []const u8, extensions: []const messages.Extension) EngineError!void {
        const supported_versions = findExtensionData(extensions, ext_supported_versions) orelse return error.MissingRequiredClientHelloExtension;
        if (!clientHelloSupportedVersionsContainTls13(supported_versions)) return error.InvalidSupportedVersionExtension;
        if (!hasExtension(extensions, ext_server_name)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_supported_groups)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_key_share)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_alpn)) return error.MissingRequiredClientHelloExtension;
        if (!isStrictTls13LegacyCompressionVector(compression_methods)) return error.InvalidCompressionMethod;
        try validatePskOfferExtensions(extensions, self.config.suite);
    }

    fn requireServerHelloExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        _ = self;
        try requireAllowedExtensions(extensions, &.{ ext_supported_versions, ext_key_share, ext_pre_shared_key }, error.UnexpectedServerHelloExtension);
        const supported_versions = findExtensionData(extensions, ext_supported_versions) orelse return error.MissingRequiredServerHelloExtension;
        if (!serverHelloSupportedVersionIsTls13(supported_versions)) return error.InvalidSupportedVersionExtension;
        if (!hasExtension(extensions, ext_key_share)) return error.MissingRequiredServerHelloExtension;
    }

    fn requireHrrExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        _ = self;
        try requireAllowedExtensions(extensions, &.{ ext_supported_versions, ext_key_share, ext_cookie }, error.UnexpectedHrrExtension);
        const supported_versions = findExtensionData(extensions, ext_supported_versions) orelse return error.MissingRequiredHrrExtension;
        if (!serverHelloSupportedVersionIsTls13(supported_versions)) return error.InvalidSupportedVersionExtension;
        if (!hasExtension(extensions, ext_key_share)) return error.MissingRequiredHrrExtension;
    }
};

pub fn estimatedConnectionMemoryCeiling(config: Config) usize {
    const ticket_cap: usize = if (config.early_data.enabled) config.early_data.max_ticket_len else 0;
    return @sizeOf(Engine) + ticket_cap;
}

pub fn classifyErrorAlert(err: anyerror) alerts.Alert {
    const description: alerts.AlertDescription = switch (err) {
        error.IllegalTransition, error.UnsupportedRecordType => .unexpected_message,

        error.MissingRequiredClientHelloExtension,
        error.MissingRequiredServerHelloExtension,
        error.MissingRequiredHrrExtension,
        => .missing_extension,

        error.InvalidLegacyVersion => .protocol_version,
        error.RecordOverflow => .record_overflow,

        error.DowngradeDetected,
        error.ConfiguredCipherSuiteMismatch,
        error.InvalidSupportedVersionExtension,
        error.UnexpectedServerHelloExtension,
        error.UnexpectedHrrExtension,
        error.InvalidCompressionMethod,
        error.MissingPskKeyExchangeModes,
        error.InvalidPskKeyExchangeModes,
        error.MissingPskDheKeyExchangeMode,
        error.InvalidPskBinder,
        error.PskBinderCountMismatch,
        error.UnsupportedSignatureAlgorithm,
        error.InvalidRequest,
        => .illegal_parameter,

        error.EarlyDataRejected,
        error.MissingReplayFilter,
        error.EarlyDataTicketExpired,
        error.EarlyDataTicketTooLarge,
        => .handshake_failure,

        error.InvalidDescription,
        error.InvalidLevel,
        error.InvalidContentType,
        error.IncompleteHeader,
        error.IncompletePayload,
        error.InvalidHandshakeType,
        error.MessageTooLarge,
        error.IncompleteBody,
        error.InvalidLength,
        error.InvalidHelloMessage,
        error.InvalidCertificateMessage,
        error.InvalidCertificateVerifyMessage,
        error.InvalidFinishedMessage,
        error.InvalidEncryptedExtensionsMessage,
        error.InvalidNewSessionTicketMessage,
        => .decode_error,

        else => .internal_error,
    };

    return .{ .level = .fatal, .description = description };
}

fn hasExtension(extensions: []const messages.Extension, extension_type: u16) bool {
    for (extensions) |ext| {
        if (ext.extension_type == extension_type) return true;
    }
    return false;
}

fn requireAllowedExtensions(
    extensions: []const messages.Extension,
    allowed: []const u16,
    comptime unexpected_err: anytype,
) EngineError!void {
    for (extensions) |ext| {
        if (!containsU16(allowed, ext.extension_type)) return unexpected_err;
    }
}

fn containsU16(values: []const u16, wanted: u16) bool {
    for (values) |value| {
        if (value == wanted) return true;
    }
    return false;
}

fn configuredCipherSuiteCodepoint(suite: keyschedule.CipherSuite) u16 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => 0x1301,
        .tls_aes_256_gcm_sha384 => 0x1302,
        .tls_chacha20_poly1305_sha256 => 0x1303,
    };
}

fn containsCipherSuite(cipher_suites: []const u16, wanted: u16) bool {
    for (cipher_suites) |suite| {
        if (suite == wanted) return true;
    }
    return false;
}

fn isStrictTls13LegacyCompressionVector(compression_methods: []const u8) bool {
    return compression_methods.len == 1 and compression_methods[0] == 0x00;
}

fn serverHelloSupportedVersionIsTls13(data: []const u8) bool {
    return data.len == 2 and data[0] == 0x03 and data[1] == 0x04;
}

fn clientHelloSupportedVersionsContainTls13(data: []const u8) bool {
    if (data.len < 3) return false;
    const list_len = data[0];
    if (list_len == 0 or list_len % 2 != 0) return false;
    if (1 + list_len != data.len) return false;

    var i: usize = 1;
    const end = 1 + list_len;
    while (i < end) : (i += 2) {
        if (data[i] == 0x03 and data[i + 1] == 0x04) return true;
    }
    return false;
}

fn hasDowngradeMarker(random: [32]u8) bool {
    const tls12_marker = [_]u8{ 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01 }; // "DOWNGRD\x01"
    const tls11_marker = [_]u8{ 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00 }; // "DOWNGRD\x00"
    const tail = random[24..32];
    return std.mem.eql(u8, tail, &tls12_marker) or std.mem.eql(u8, tail, &tls11_marker);
}

test "zeroize latest secret clears secret bytes and resets option" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const secret = [_]u8{0xaa} ** 32;
    engine.latest_secret = .{ .sha256 = secret };
    engine.zeroizeLatestSecret();

    try std.testing.expect(engine.latest_secret == null);
}

test "clear early data ticket zeroes and clears pointer" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try engine.beginEarlyData("ticket-z", true);
    try std.testing.expect(engine.early_data_ticket != null);
    engine.clearEarlyDataTicket();
    try std.testing.expect(engine.early_data_ticket == null);
}

test "debug keylog callback fires when enabled in debug mode" {
    const Tracker = struct {
        called: bool = false,
        label_ok: bool = false,
        len: usize = 0,
    };
    const Hooks = struct {
        fn onKeyLog(label: []const u8, secret: []const u8, userdata: usize) void {
            const tracker: *Tracker = @as(*Tracker, @ptrFromInt(userdata));
            tracker.called = true;
            tracker.label_ok = std.mem.eql(u8, label, "CLIENT_TRAFFIC_SECRET_0");
            tracker.len = secret.len;
        }
    };

    var tracker = Tracker{};
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .enable_debug_keylog = true,
        .keylog_callback = Hooks.onKeyLog,
        .keylog_userdata = @intFromPtr(&tracker),
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    if (builtin.mode == .Debug) {
        try std.testing.expect(tracker.called);
        try std.testing.expect(tracker.label_ok);
        try std.testing.expectEqual(@as(usize, 32), tracker.len);
    } else {
        try std.testing.expect(!tracker.called);
    }
}

test "debug keylog callback is suppressed when disabled" {
    const Tracker = struct {
        called: bool = false,
    };
    const Hooks = struct {
        fn onKeyLog(_: []const u8, _: []const u8, userdata: usize) void {
            const tracker: *Tracker = @as(*Tracker, @ptrFromInt(userdata));
            tracker.called = true;
        }
    };

    var tracker = Tracker{};
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .enable_debug_keylog = false,
        .keylog_callback = Hooks.onKeyLog,
        .keylog_userdata = @intFromPtr(&tracker),
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expect(!tracker.called);
}

test "debug keylog callback uses server label in server role" {
    const Tracker = struct {
        called: bool = false,
        label_ok: bool = false,
    };
    const Hooks = struct {
        fn onKeyLog(label: []const u8, _: []const u8, userdata: usize) void {
            const tracker: *Tracker = @as(*Tracker, @ptrFromInt(userdata));
            tracker.called = true;
            tracker.label_ok = std.mem.eql(u8, label, "SERVER_TRAFFIC_SECRET_0");
        }
    };

    var tracker = Tracker{};
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .enable_debug_keylog = true,
        .keylog_callback = Hooks.onKeyLog,
        .keylog_userdata = @intFromPtr(&tracker),
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    if (builtin.mode == .Debug) {
        try std.testing.expect(tracker.called);
        try std.testing.expect(tracker.label_ok);
    } else {
        try std.testing.expect(!tracker.called);
    }
}

fn validatePskOfferExtensions(extensions: []const messages.Extension, suite: keyschedule.CipherSuite) EngineError!void {
    const psk = findExtensionData(extensions, ext_pre_shared_key) orelse return;
    const psk_modes = findExtensionData(extensions, ext_psk_key_exchange_modes) orelse return error.MissingPskKeyExchangeModes;
    const modes = try validatePskKeyExchangeModes(psk_modes);
    if (!modes.has_psk_dhe_ke) return error.MissingPskDheKeyExchangeMode;
    const counts = parsePskBinderVector(psk, keyschedule.digestLen(suite)) catch return error.InvalidPskBinder;
    if (counts.identity_count != counts.binder_count) return error.PskBinderCountMismatch;
    if (!counts.binder_len_ok) return error.InvalidPskBinderLength;
}

const PskModes = struct {
    has_psk_dhe_ke: bool,
};

fn validatePskKeyExchangeModes(data: []const u8) EngineError!PskModes {
    if (data.len < 2) return error.InvalidPskKeyExchangeModes;
    const list_len = data[0];
    if (list_len == 0) return error.InvalidPskKeyExchangeModes;
    if (list_len + 1 != data.len) return error.InvalidPskKeyExchangeModes;

    var has_psk_dhe_ke = false;
    var i: usize = 1;
    while (i < data.len) : (i += 1) {
        const mode = data[i];
        if (mode == 1) {
            has_psk_dhe_ke = true;
            continue;
        }
        if (mode != 0) return error.InvalidPskKeyExchangeModes;
    }
    return .{ .has_psk_dhe_ke = has_psk_dhe_ke };
}

fn findExtensionData(extensions: []const messages.Extension, extension_type: u16) ?[]const u8 {
    for (extensions) |ext| {
        if (ext.extension_type == extension_type) return ext.data;
    }
    return null;
}

const PskCounts = struct {
    identity_count: usize,
    binder_count: usize,
    binder_len_ok: bool,
};

fn parsePskBinderVector(bytes: []const u8, expected_binder_len: usize) !PskCounts {
    // pre_shared_key (CH): identities<7..2^16-1> + binders<33..2^16-1>
    var i: usize = 0;
    if (bytes.len < 2 + 2) return error.Truncated;

    const identities_len = readU16(bytes[i .. i + 2]);
    i += 2;
    if (identities_len == 0) return error.InvalidLength;
    if (i + identities_len + 2 > bytes.len) return error.Truncated;
    const identities_end = i + identities_len;
    var identity_count: usize = 0;
    while (i < identities_end) {
        if (i + 2 > identities_end) return error.Truncated;
        const id_len = readU16(bytes[i .. i + 2]);
        i += 2;
        if (id_len == 0) return error.InvalidLength;
        if (i + id_len + 4 > identities_end) return error.Truncated;
        i += id_len + 4; // identity + obfuscated_ticket_age
        identity_count += 1;
    }
    if (i != identities_end) return error.Truncated;

    const binders_len = readU16(bytes[i .. i + 2]);
    i += 2;
    if (binders_len == 0) return error.InvalidLength;
    if (i + binders_len != bytes.len) return error.Truncated;
    const binders_end = i + binders_len;
    var binder_count: usize = 0;
    var binder_len_ok = true;
    while (i < binders_end) {
        if (i + 1 > binders_end) return error.Truncated;
        const binder_len = bytes[i];
        i += 1;
        if (binder_len == 0) return error.InvalidLength;
        if (binder_len != expected_binder_len) binder_len_ok = false;
        if (i + binder_len > binders_end) return error.Truncated;
        i += binder_len;
        binder_count += 1;
    }
    if (identity_count == 0 or binder_count == 0 or i != binders_end) return error.InvalidLength;
    return .{
        .identity_count = identity_count,
        .binder_count = binder_count,
        .binder_len_ok = binder_len_ok,
    };
}

fn readU16(bytes: []const u8) usize {
    return (@as(usize, bytes[0]) << 8) | @as(usize, bytes[1]);
}

fn handshakeRecord(comptime ty: state.HandshakeType) [9]u8 {
    var frame: [9]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    frame[3] = 0x00;
    frame[4] = 0x04;
    frame[5] = @intFromEnum(ty);
    frame[6] = 0x00;
    frame[7] = 0x00;
    frame[8] = 0x00;
    return frame;
}

fn serverHelloRecord() [63]u8 {
    var frame: [63]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 54 + 4, .big);
    frame[5] = @intFromEnum(state.HandshakeType.server_hello);
    const hs_len = handshake.writeU24(54);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x03;
    frame[10] = 0x03;
    @memset(frame[11..43], 0x11);
    frame[43] = 0x00; // session id len
    frame[44] = 0x13;
    frame[45] = 0x01; // cipher suite low byte (0x1301)
    frame[46] = 0x00; // compression method
    frame[47] = 0x00; // exts len hi
    frame[48] = 0x0e; // exts len lo (14)
    // supported_versions: type=0x002b len=2 val=0x0304
    frame[49] = 0x00;
    frame[50] = 0x2b;
    frame[51] = 0x00;
    frame[52] = 0x02;
    frame[53] = 0x03;
    frame[54] = 0x04;
    // key_share: type=0x0033 len=4 group=x25519 key_exchange_len=0
    frame[55] = 0x00;
    frame[56] = 0x33;
    frame[57] = 0x00;
    frame[58] = 0x04;
    frame[59] = 0x00;
    frame[60] = 0x1d;
    frame[61] = 0x00;
    frame[62] = 0x00;
    return frame;
}

fn clientHelloRecord() [101]u8 {
    // ClientHello body length:
    // base(43) + extensions(49) = 92
    var frame: [101]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 4 + 92, .big);
    frame[5] = @intFromEnum(state.HandshakeType.client_hello);
    const hs_len = handshake.writeU24(92);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x03;
    frame[10] = 0x03;
    @memset(frame[11..43], 0x22);
    frame[43] = 0x00; // sid len
    frame[44] = 0x00;
    frame[45] = 0x02; // suites len
    frame[46] = 0x13;
    frame[47] = 0x01; // TLS_AES_128_GCM_SHA256
    frame[48] = 0x01; // comp len
    frame[49] = 0x00; // null compression
    frame[50] = 0x00;
    frame[51] = 0x31; // exts len (49)
    // server_name: type=0x0000 len=10 list_len=8 name_type=0 host_len=5 "a.com"
    frame[52] = 0x00;
    frame[53] = 0x00;
    frame[54] = 0x00;
    frame[55] = 0x0a;
    frame[56] = 0x00;
    frame[57] = 0x08;
    frame[58] = 0x00;
    frame[59] = 0x00;
    frame[60] = 0x05;
    frame[61] = 'a';
    frame[62] = '.';
    frame[63] = 'c';
    frame[64] = 'o';
    frame[65] = 'm';
    // supported_versions: type=0x002b len=3 list_len=2 v=0x0304
    frame[66] = 0x00;
    frame[67] = 0x2b;
    frame[68] = 0x00;
    frame[69] = 0x03;
    frame[70] = 0x02;
    frame[71] = 0x03;
    frame[72] = 0x04;
    // supported_groups: type=0x000a len=4 list_len=2 group=x25519
    frame[73] = 0x00;
    frame[74] = 0x0a;
    frame[75] = 0x00;
    frame[76] = 0x04;
    frame[77] = 0x00;
    frame[78] = 0x02;
    frame[79] = 0x00;
    frame[80] = 0x1d;
    // key_share: type=0x0033 len=7 vec_len=5 group=x25519 key_len=1 key=0xaa
    frame[81] = 0x00;
    frame[82] = 0x33;
    frame[83] = 0x00;
    frame[84] = 0x07;
    frame[85] = 0x00;
    frame[86] = 0x05;
    frame[87] = 0x00;
    frame[88] = 0x1d;
    frame[89] = 0x00;
    frame[90] = 0x01;
    frame[91] = 0xaa;
    // alpn: type=0x0010 len=5 protocol_name_list_len=3 name_len=2 "h2"
    frame[92] = 0x00;
    frame[93] = 0x10;
    frame[94] = 0x00;
    frame[95] = 0x05;
    frame[96] = 0x00;
    frame[97] = 0x03;
    frame[98] = 0x02;
    frame[99] = 'h';
    frame[100] = '2';
    return frame;
}

fn serverHelloRecordWithoutKeyShare() [63]u8 {
    var frame = serverHelloRecord();
    frame[55] = 0x00;
    frame[56] = 0x29;
    return frame;
}

fn serverHelloRecordWithBadSupportedVersion() [63]u8 {
    var frame = serverHelloRecord();
    frame[53] = 0x03;
    frame[54] = 0x03;
    return frame;
}

fn serverHelloRecordWithNonZeroCompression() [63]u8 {
    var frame = serverHelloRecord();
    frame[46] = 0x01;
    return frame;
}

fn serverHelloRecordWithCipherSuite(suite: u16) [63]u8 {
    var frame = serverHelloRecord();
    frame[44] = @intCast((suite >> 8) & 0xff);
    frame[45] = @intCast(suite & 0xff);
    return frame;
}

fn serverHelloRecordWithUnexpectedExtension() [67]u8 {
    var frame: [67]u8 = undefined;
    const base = serverHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 62, .big);
    const hs_len = handshake.writeU24(58);
    @memcpy(frame[6..9], &hs_len);
    frame[47] = 0x00;
    frame[48] = 0x12; // extension bytes: 18
    frame[63] = 0x00;
    frame[64] = 0x10; // ALPN not legal in ServerHello
    frame[65] = 0x00;
    frame[66] = 0x00;
    return frame;
}

fn serverHelloRecordWithDowngradeMarker() [63]u8 {
    var frame = serverHelloRecord();
    // ServerHello.random tail sentinel "DOWNGRD\x01"
    frame[35] = 0x44;
    frame[36] = 0x4f;
    frame[37] = 0x57;
    frame[38] = 0x4e;
    frame[39] = 0x47;
    frame[40] = 0x52;
    frame[41] = 0x44;
    frame[42] = 0x01;
    return frame;
}

fn serverHelloRecordWithLegacyDowngradeMarker() [63]u8 {
    var frame = serverHelloRecord();
    // ServerHello.random tail sentinel "DOWNGRD\x00"
    frame[35] = 0x44;
    frame[36] = 0x4f;
    frame[37] = 0x57;
    frame[38] = 0x4e;
    frame[39] = 0x47;
    frame[40] = 0x52;
    frame[41] = 0x44;
    frame[42] = 0x00;
    return frame;
}

fn clientHelloRecordWithoutAlpn() [101]u8 {
    var frame = clientHelloRecord();
    frame[92] = 0xff;
    frame[93] = 0xfe;
    return frame;
}

fn clientHelloRecordWithoutNullCompression() [101]u8 {
    var frame = clientHelloRecord();
    frame[49] = 0x01;
    return frame;
}

fn clientHelloRecordWithExtraCompressionMethod() [102]u8 {
    var frame: [102]u8 = undefined;
    const base = clientHelloRecord();
    @memcpy(frame[0..50], base[0..50]);
    @memcpy(frame[51..], base[50..]);
    std.mem.writeInt(u16, frame[3..5], 97, .big);
    const hs_len = handshake.writeU24(93);
    @memcpy(frame[6..9], &hs_len);
    frame[48] = 0x02; // comp len
    frame[49] = 0x00; // null compression
    frame[50] = 0x01; // illegal extra method in TLS1.3
    return frame;
}

fn clientHelloRecordWithoutTls13SupportedVersion() [101]u8 {
    var frame = clientHelloRecord();
    frame[72] = 0x03;
    return frame;
}

fn clientHelloRecordWithPskWithoutModes() [109]u8 {
    var frame: [109]u8 = undefined;
    const base = clientHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 104, .big);
    const hs_len = handshake.writeU24(100);
    @memcpy(frame[6..9], &hs_len);
    frame[50] = 0x00;
    frame[51] = 0x39; // 49 + 8
    // pre_shared_key with malformed minimal payload; absence of modes must fail first.
    frame[101] = 0x00;
    frame[102] = 0x29;
    frame[103] = 0x00;
    frame[104] = 0x04;
    frame[105] = 0x00;
    frame[106] = 0x00;
    frame[107] = 0x00;
    frame[108] = 0x00;
    return frame;
}

fn clientHelloRecordWithMalformedPskBinder() [115]u8 {
    var frame: [115]u8 = undefined;
    const base = clientHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 110, .big);
    const hs_len = handshake.writeU24(106);
    @memcpy(frame[6..9], &hs_len);
    frame[50] = 0x00;
    frame[51] = 0x3f; // 49 + 6 + 8
    // psk_key_exchange_modes extension (valid shape)
    frame[101] = 0x00;
    frame[102] = 0x2d;
    frame[103] = 0x00;
    frame[104] = 0x02;
    frame[105] = 0x01;
    frame[106] = 0x01;
    // pre_shared_key with invalid identities/binders layout
    frame[107] = 0x00;
    frame[108] = 0x29;
    frame[109] = 0x00;
    frame[110] = 0x04;
    frame[111] = 0x00;
    frame[112] = 0x00;
    frame[113] = 0x00;
    frame[114] = 0x00;
    return frame;
}

fn clientHelloRecordWithInvalidPskModesLength() [115]u8 {
    var frame = clientHelloRecordWithMalformedPskBinder();
    // psk_key_exchange_modes extension: declared list length=2 but only one mode byte.
    frame[105] = 0x02;
    return frame;
}

fn clientHelloRecordWithUnknownPskMode() [115]u8 {
    var frame = clientHelloRecordWithMalformedPskBinder();
    // psk_key_exchange_modes extension: one mode byte with unknown value.
    frame[106] = 0x07;
    return frame;
}

fn clientHelloRecordWithPskKeOnlyMode() [126]u8 {
    var frame = clientHelloRecordWithPskBinderCountMismatch();
    // psk_key_exchange_modes extension: one mode byte set to psk_ke(0) only.
    frame[106] = 0x00;
    return frame;
}

fn clientHelloRecordWithPskBinderCountMismatch() [126]u8 {
    var frame: [126]u8 = undefined;
    const base = clientHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 121, .big);
    const hs_len = handshake.writeU24(117);
    @memcpy(frame[6..9], &hs_len);
    frame[50] = 0x00;
    frame[51] = 0x4a; // exts: 49 + psk_modes(6) + psk(19)
    // psk_key_exchange_modes extension
    frame[101] = 0x00;
    frame[102] = 0x2d;
    frame[103] = 0x00;
    frame[104] = 0x02;
    frame[105] = 0x01;
    frame[106] = 0x01;
    // pre_shared_key extension:
    // identities_len=7, one identity(len=1,data=0xaa,age=0)
    // binders_len=4, two binders of len=1 each -> count mismatch (1 identity, 2 binders)
    frame[107] = 0x00;
    frame[108] = 0x29;
    frame[109] = 0x00;
    frame[110] = 0x0f;
    frame[111] = 0x00;
    frame[112] = 0x07;
    frame[113] = 0x00;
    frame[114] = 0x01;
    frame[115] = 0xaa;
    frame[116] = 0x00;
    frame[117] = 0x00;
    frame[118] = 0x00;
    frame[119] = 0x00;
    frame[120] = 0x00;
    frame[121] = 0x04;
    frame[122] = 0x01;
    frame[123] = 0x01;
    frame[124] = 0x01;
    frame[125] = 0x02;
    return frame;
}

fn clientHelloRecordWithPskInvalidBinderLength() [124]u8 {
    var frame: [124]u8 = undefined;
    const base = clientHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 119, .big);
    const hs_len = handshake.writeU24(115);
    @memcpy(frame[6..9], &hs_len);
    frame[50] = 0x00;
    frame[51] = 0x48; // exts: 49 + psk_modes(6) + psk(17)
    // psk_key_exchange_modes extension
    frame[101] = 0x00;
    frame[102] = 0x2d;
    frame[103] = 0x00;
    frame[104] = 0x02;
    frame[105] = 0x01;
    frame[106] = 0x01;
    // pre_shared_key extension with binder len=1 (invalid for SHA256 suites)
    frame[107] = 0x00;
    frame[108] = 0x29;
    frame[109] = 0x00;
    frame[110] = 0x0d;
    frame[111] = 0x00;
    frame[112] = 0x07;
    frame[113] = 0x00;
    frame[114] = 0x01;
    frame[115] = 0xaa;
    frame[116] = 0x00;
    frame[117] = 0x00;
    frame[118] = 0x00;
    frame[119] = 0x00;
    frame[120] = 0x00;
    frame[121] = 0x02;
    frame[122] = 0x01;
    frame[123] = 0x01;
    return frame;
}

fn hrrServerHelloRecord() [61]u8 {
    var frame: [61]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 56, .big);
    frame[5] = @intFromEnum(state.HandshakeType.server_hello);
    const len = handshake.writeU24(52);
    @memcpy(frame[6..9], &len);
    frame[9] = 0x03;
    frame[10] = 0x03;
    @memcpy(frame[11..43], &handshake.hello_retry_request_random);
    frame[43] = 0x00; // session id len
    frame[44] = 0x13;
    frame[45] = 0x01; // cipher suite
    frame[46] = 0x00; // compression
    frame[47] = 0x00;
    frame[48] = 0x0c; // extensions len
    // supported_versions: type=0x002b len=2 val=0x0304
    frame[49] = 0x00;
    frame[50] = 0x2b;
    frame[51] = 0x00;
    frame[52] = 0x02;
    frame[53] = 0x03;
    frame[54] = 0x04;
    // key_share (selected_group): type=0x0033 len=2 group=x25519
    frame[55] = 0x00;
    frame[56] = 0x33;
    frame[57] = 0x00;
    frame[58] = 0x02;
    frame[59] = 0x00;
    frame[60] = 0x1d;
    return frame;
}

fn hrrServerHelloRecordWithoutKeyShare() [61]u8 {
    var frame = hrrServerHelloRecord();
    frame[55] = 0x00;
    frame[56] = 0x2c;
    return frame;
}

fn hrrServerHelloRecordWithBadSupportedVersion() [61]u8 {
    var frame = hrrServerHelloRecord();
    frame[53] = 0x03;
    frame[54] = 0x03;
    return frame;
}

fn hrrServerHelloRecordWithUnexpectedExtension() [65]u8 {
    var frame: [65]u8 = undefined;
    const base = hrrServerHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 60, .big);
    const hs_len = handshake.writeU24(56);
    @memcpy(frame[6..9], &hs_len);
    frame[47] = 0x00;
    frame[48] = 0x10; // extension bytes: 16
    frame[61] = 0x00;
    frame[62] = 0x10; // ALPN not legal in HRR
    frame[63] = 0x00;
    frame[64] = 0x00;
    return frame;
}

fn keyUpdateRecord(request: handshake.KeyUpdateRequest) [10]u8 {
    return Engine.buildKeyUpdateRecord(request);
}

fn encryptedExtensionsRecord() [11]u8 {
    // EncryptedExtensions body: extensions_len(2)=0
    var frame: [11]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 6, .big);
    frame[5] = @intFromEnum(state.HandshakeType.encrypted_extensions);
    const hs_len = handshake.writeU24(2);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x00;
    frame[10] = 0x00;
    return frame;
}

fn newSessionTicketRecord() [25]u8 {
    // lifetime(4), age_add(4), nonce_len(1)=1, nonce(1), ticket_len(2)=2, ticket(2), ext_len(2)=0
    var frame: [25]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 20, .big);
    frame[5] = @intFromEnum(state.HandshakeType.new_session_ticket);
    const hs_len = handshake.writeU24(16);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x00;
    frame[10] = 0x00;
    frame[11] = 0x0e;
    frame[12] = 0x10;
    frame[13] = 0x11;
    frame[14] = 0x22;
    frame[15] = 0x33;
    frame[16] = 0x44;
    frame[17] = 0x01;
    frame[18] = 0xaa;
    frame[19] = 0x00;
    frame[20] = 0x02;
    frame[21] = 0xbe;
    frame[22] = 0xef;
    frame[23] = 0x00;
    frame[24] = 0x00;
    return frame;
}

fn appDataRecord(comptime data: []const u8) [5 + data.len]u8 {
    var frame: [5 + data.len]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.application_data);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], data.len, .big);
    @memcpy(frame[5..], data);
    return frame;
}

fn certificateRecord() [19]u8 {
    // Certificate body: context_len(1)=0, list_len(3)=6, cert_len(3)=1, cert_data(1), ext_len(2)=0
    var frame: [19]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 14, .big);
    frame[5] = @intFromEnum(state.HandshakeType.certificate);
    const hs_len = handshake.writeU24(10);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x00;
    frame[10] = 0x00;
    frame[11] = 0x00;
    frame[12] = 0x06;
    frame[13] = 0x00;
    frame[14] = 0x00;
    frame[15] = 0x01;
    frame[16] = 0xaa;
    frame[17] = 0x00;
    frame[18] = 0x00;
    return frame;
}

fn certificateVerifyRecord() [14]u8 {
    // algorithm=0x0403, sig_len=1, sig=0x5a
    var frame: [14]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 9, .big);
    frame[5] = @intFromEnum(state.HandshakeType.certificate_verify);
    const hs_len = handshake.writeU24(5);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x04;
    frame[10] = 0x03;
    frame[11] = 0x00;
    frame[12] = 0x01;
    frame[13] = 0x5a;
    return frame;
}

fn certificateVerifyRecordWithAlgorithm(algorithm: u16) [14]u8 {
    var frame = certificateVerifyRecord();
    frame[9] = @intCast((algorithm >> 8) & 0xff);
    frame[10] = @intCast(algorithm & 0xff);
    return frame;
}

fn finishedRecord() [41]u8 {
    var frame: [41]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 36, .big);
    frame[5] = @intFromEnum(state.HandshakeType.finished);
    const hs_len = handshake.writeU24(32);
    @memcpy(frame[6..9], &hs_len);
    @memset(frame[9..41], 0x5c);
    return frame;
}

fn finishedRecordSha384() [57]u8 {
    var frame: [57]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 52, .big);
    frame[5] = @intFromEnum(state.HandshakeType.finished);
    const hs_len = handshake.writeU24(48);
    @memcpy(frame[6..9], &hs_len);
    @memset(frame[9..57], 0x6d);
    return frame;
}

test "client side handshake flow reaches connected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    try std.testing.expect(engine.latest_secret != null);
}

test "client side handshake flow reaches connected for chacha20 suite" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_chacha20_poly1305_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecordWithCipherSuite(0x1303));
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    switch (engine.latest_secret orelse return error.TestUnexpectedResult) {
        .sha256 => {},
        .sha384 => return error.TestUnexpectedResult,
    }
}

test "client side handshake flow reaches connected for aes256 suite" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_256_gcm_sha384,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecordWithCipherSuite(0x1302));
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecordSha384());

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    switch (engine.latest_secret orelse return error.TestUnexpectedResult) {
        .sha256 => return error.TestUnexpectedResult,
        .sha384 => {},
    }
}

test "unexpected handshake fails with illegal transition" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.IllegalTransition, engine.ingestRecord(&finishedRecord()));
}

test "invalid finished body length is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    try std.testing.expectError(error.InvalidFinishedMessage, engine.ingestRecord(&handshakeRecord(.finished)));
}

test "close_notify transitions to closed" {
    var frame = Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });

    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_chacha20_poly1305_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&frame);
    try std.testing.expectEqual(state.ConnectionState.closed, engine.machine.state);
}

test "client accepts hrr then server hello" {
    const hrr = hrrServerHelloRecord();
    const second_sh = serverHelloRecord();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const res_hrr = try engine.ingestRecord(&hrr);
    try std.testing.expectEqual(state.ConnectionState.wait_server_hello, engine.machine.state);
    try std.testing.expectEqual(@as(usize, 3), res_hrr.action_count);
    switch (res_hrr.actions[1]) {
        .hello_retry_request => {},
        else => return error.TestUnexpectedResult,
    }

    _ = try engine.ingestRecord(&second_sh);
    try std.testing.expectEqual(state.ConnectionState.wait_encrypted_extensions, engine.machine.state);
}

test "client rejects hrr missing required extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithoutKeyShare();
    try std.testing.expectError(error.MissingRequiredHrrExtension, engine.ingestRecord(&hrr));
}

test "client rejects hrr with invalid supported version extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithBadSupportedVersion();
    try std.testing.expectError(error.InvalidSupportedVersionExtension, engine.ingestRecord(&hrr));
}

test "client rejects hrr with unexpected extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithUnexpectedExtension();
    try std.testing.expectError(error.UnexpectedHrrExtension, engine.ingestRecord(&hrr));
}

test "keyupdate request is surfaced in action" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    const before = engine.latest_secret orelse return error.TestUnexpectedResult;

    const ku = keyUpdateRecord(.update_requested);
    const res = try engine.ingestRecord(&ku);

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    try std.testing.expectEqual(@as(usize, 4), res.action_count);
    switch (res.actions[1]) {
        .key_update => |req| try std.testing.expectEqual(handshake.KeyUpdateRequest.update_requested, req),
        else => return error.TestUnexpectedResult,
    }
    switch (res.actions[2]) {
        .send_key_update => |req| try std.testing.expectEqual(handshake.KeyUpdateRequest.update_not_requested, req),
        else => return error.TestUnexpectedResult,
    }

    const after = engine.latest_secret orelse return error.TestUnexpectedResult;
    switch (before) {
        .sha256 => |b| switch (after) {
            .sha256 => |a| try std.testing.expect(!std.mem.eql(u8, &b, &a)),
            else => return error.TestUnexpectedResult,
        },
        .sha384 => |b| switch (after) {
            .sha384 => |a| try std.testing.expect(!std.mem.eql(u8, &b, &a)),
            else => return error.TestUnexpectedResult,
        },
    }
}

test "early data is rejected by default" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = appDataRecord("hello");
    try std.testing.expectError(error.EarlyDataRejected, engine.ingestRecord(&rec));
}

test "early data ticket length limit is enforced" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .max_ticket_len = 8,
        },
    });
    defer engine.deinit();

    try std.testing.expectError(error.EarlyDataTicketTooLarge, engine.beginEarlyData("ticket-too-long", true));
}

test "estimated connection memory ceiling includes early data ticket cap when enabled" {
    const disabled = estimatedConnectionMemoryCeiling(.{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    const enabled = estimatedConnectionMemoryCeiling(.{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .max_ticket_len = 2048,
        },
    });
    try std.testing.expectEqual(@as(usize, @sizeOf(Engine)), disabled);
    try std.testing.expectEqual(@as(usize, @sizeOf(Engine) + 2048), enabled);
}

test "early data requires idempotent mark and anti-replay" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{ .enabled = true, .replay_filter = &replay },
    });
    defer engine.deinit();

    const rec = appDataRecord("hello");

    try std.testing.expectError(error.EarlyDataRejected, engine.ingestRecord(&rec));

    try engine.beginEarlyData("ticket-1", true);
    _ = try engine.ingestRecord(&rec);

    // Same replay token is rejected on subsequent early-data records.
    try std.testing.expectError(error.EarlyDataRejected, engine.ingestRecord(&rec));
}

test "early data replay scope isolates duplicate tickets across node and epoch" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    const rec = appDataRecord("hello");

    var node_a = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .replay_node_id = 1,
            .replay_epoch = 10,
        },
    });
    defer node_a.deinit();

    var node_b = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .replay_node_id = 2,
            .replay_epoch = 11,
        },
    });
    defer node_b.deinit();

    try node_a.beginEarlyData("ticket-shared", true);
    _ = try node_a.ingestRecord(&rec);

    try node_b.beginEarlyData("ticket-shared", true);
    _ = try node_b.ingestRecord(&rec);
}

test "early data ticket freshness window rejects stale ticket" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .max_ticket_age_sec = 60,
        },
    });
    defer engine.deinit();

    try std.testing.expectError(error.EarlyDataTicketExpired, engine.beginEarlyDataWithTimes("ticket-2", true, 1_700_000_000, 1_700_000_061));
}

test "early data ticket freshness window accepts boundary age" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .max_ticket_age_sec = 60,
        },
    });
    defer engine.deinit();

    try engine.beginEarlyDataWithTimes("ticket-3", true, 1_700_000_000, 1_700_000_060);
    const rec = appDataRecord("hello");
    _ = try engine.ingestRecord(&rec);
}

test "transport eof without close_notify is truncation" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.TruncationDetected, engine.onTransportEof());
}

test "transport eof after close_notify is clean close" {
    var frame = Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&frame);
    try engine.onTransportEof();
    try std.testing.expectEqual(state.ConnectionState.closed, engine.machine.state);
}

test "invalid server hello body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.InvalidHelloMessage, engine.ingestRecord(&handshakeRecord(.server_hello)));
}

test "invalid client hello body is rejected for server role" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.InvalidHelloMessage, engine.ingestRecord(&handshakeRecord(.client_hello)));
}

test "client rejects server hello without required extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithoutKeyShare();
    try std.testing.expectError(error.MissingRequiredServerHelloExtension, engine.ingestRecord(&rec));
}

test "client rejects server hello with invalid supported version extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithBadSupportedVersion();
    try std.testing.expectError(error.InvalidSupportedVersionExtension, engine.ingestRecord(&rec));
}

test "client rejects server hello with unexpected extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithUnexpectedExtension();
    try std.testing.expectError(error.UnexpectedServerHelloExtension, engine.ingestRecord(&rec));
}

test "client rejects server hello with configured cipher suite mismatch" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_chacha20_poly1305_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithCipherSuite(0x1301);
    try std.testing.expectError(error.ConfiguredCipherSuiteMismatch, engine.ingestRecord(&rec));
}

test "client rejects server hello with non-zero compression method" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithNonZeroCompression();
    try std.testing.expectError(error.InvalidCompressionMethod, engine.ingestRecord(&rec));
}

test "client rejects server hello with downgrade marker" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithDowngradeMarker();
    try std.testing.expectError(error.DowngradeDetected, engine.ingestRecord(&rec));
}

test "client rejects server hello with legacy downgrade marker" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithLegacyDowngradeMarker();
    try std.testing.expectError(error.DowngradeDetected, engine.ingestRecord(&rec));
}

test "server rejects client hello without required extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithoutAlpn();
    try std.testing.expectError(error.MissingRequiredClientHelloExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello without tls13 supported version" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithoutTls13SupportedVersion();
    try std.testing.expectError(error.InvalidSupportedVersionExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello without null compression method" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithoutNullCompression();
    try std.testing.expectError(error.InvalidCompressionMethod, engine.ingestRecord(&rec));
}

test "server rejects client hello with extra compression methods" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithExtraCompressionMethod();
    try std.testing.expectError(error.InvalidCompressionMethod, engine.ingestRecord(&rec));
}

test "server rejects psk offer without psk key exchange modes" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithPskWithoutModes();
    try std.testing.expectError(error.MissingPskKeyExchangeModes, engine.ingestRecord(&rec));
}

test "server rejects malformed psk binder vector" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithMalformedPskBinder();
    try std.testing.expectError(error.InvalidPskBinder, engine.ingestRecord(&rec));
}

test "server rejects malformed psk key exchange modes length" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithInvalidPskModesLength();
    try std.testing.expectError(error.InvalidPskKeyExchangeModes, engine.ingestRecord(&rec));
}

test "server rejects unknown psk key exchange mode value" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithUnknownPskMode();
    try std.testing.expectError(error.InvalidPskKeyExchangeModes, engine.ingestRecord(&rec));
}

test "server rejects psk offer without psk_dhe_ke mode" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithPskKeOnlyMode();
    try std.testing.expectError(error.MissingPskDheKeyExchangeMode, engine.ingestRecord(&rec));
}

test "server rejects psk identity and binder count mismatch" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithPskBinderCountMismatch();
    try std.testing.expectError(error.PskBinderCountMismatch, engine.ingestRecord(&rec));
}

test "server rejects psk binder length mismatch for configured suite" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithPskInvalidBinderLength();
    try std.testing.expectError(error.InvalidPskBinderLength, engine.ingestRecord(&rec));
}

test "valid client hello body is accepted for server role" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    try std.testing.expectEqual(state.ConnectionState.wait_client_certificate_or_finished, engine.machine.state);
}

test "server rejects client hello without configured cipher suite offer" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_chacha20_poly1305_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecord();
    try std.testing.expectError(error.ConfiguredCipherSuiteMismatch, engine.ingestRecord(&rec));
}

test "metrics counters reflect handshake and alert activity" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    _ = try engine.ingestRecord(&keyUpdateRecord(.update_not_requested));
    _ = try engine.ingestRecord(&Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify }));

    const m = engine.snapshotMetrics();
    try std.testing.expectEqual(@as(u64, 4), m.handshake_messages);
    try std.testing.expectEqual(@as(u64, 1), m.keyupdate_messages);
    try std.testing.expectEqual(@as(u64, 1), m.connected_transitions);
    try std.testing.expectEqual(@as(u64, 1), m.alerts_received);
}

test "metrics counts truncation events" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.TruncationDetected, engine.onTransportEof());
    const m = engine.snapshotMetrics();
    try std.testing.expectEqual(@as(u64, 1), m.truncation_events);
}

test "classify error alert maps representative protocol errors" {
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .unexpected_message },
        classifyErrorAlert(error.IllegalTransition),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .missing_extension },
        classifyErrorAlert(error.MissingRequiredServerHelloExtension),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .protocol_version },
        classifyErrorAlert(error.InvalidLegacyVersion),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .record_overflow },
        classifyErrorAlert(error.RecordOverflow),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .illegal_parameter },
        classifyErrorAlert(error.InvalidSupportedVersionExtension),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .decode_error },
        classifyErrorAlert(error.InvalidHelloMessage),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .handshake_failure },
        classifyErrorAlert(error.EarlyDataRejected),
    );
}

test "classify error alert falls back to internal_error for unknown errors" {
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .internal_error },
        classifyErrorAlert(error.OutOfMemory),
    );
}

test "ingest wrapper returns ok outcome on success" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const out = engine.ingestRecordWithAlertIntent(&serverHelloRecord());
    switch (out) {
        .ok => |res| {
            try std.testing.expectEqual(@as(usize, 2), res.action_count);
            try std.testing.expectEqual(state.ConnectionState.wait_encrypted_extensions, engine.machine.state);
        },
        .fatal => return error.TestUnexpectedResult,
    }
}

test "ingest wrapper returns fatal alert intent on decode failure" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const out = engine.ingestRecordWithAlertIntent(&handshakeRecord(.server_hello));
    switch (out) {
        .ok => return error.TestUnexpectedResult,
        .fatal => |failure| {
            try std.testing.expectEqual(error.InvalidHelloMessage, failure.err);
            try std.testing.expectEqual(alerts.AlertLevel.fatal, failure.alert.level);
            try std.testing.expectEqual(alerts.AlertDescription.decode_error, failure.alert.description);
            try std.testing.expectEqual(state.ConnectionState.closing, engine.machine.state);
        },
    }
}

test "build keyupdate record is parseable" {
    const frame = Engine.buildKeyUpdateRecord(.update_requested);
    const parsed = try record.parseRecord(&frame);
    try std.testing.expectEqual(record.ContentType.handshake, parsed.header.content_type);

    const hs = try handshake.parseOne(parsed.payload);
    try std.testing.expectEqual(state.HandshakeType.key_update, hs.header.handshake_type);
    const req = try handshake.parseKeyUpdateRequest(hs.body);
    try std.testing.expectEqual(handshake.KeyUpdateRequest.update_requested, req);
}

test "invalid certificate body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    try std.testing.expectError(error.InvalidCertificateMessage, engine.ingestRecord(&handshakeRecord(.certificate)));
}

test "certificate path valid bodies progress state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    _ = try engine.ingestRecord(&certificateVerifyRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "invalid certificate_verify body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, engine.ingestRecord(&handshakeRecord(.certificate_verify)));
}

test "unsupported certificate_verify algorithm is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, engine.ingestRecord(&certificateVerifyRecordWithAlgorithm(0xeeee)));
}

test "server role certificate path valid bodies progress state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    _ = try engine.ingestRecord(&certificateVerifyRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "server role invalid certificate body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    try std.testing.expectError(error.InvalidCertificateMessage, engine.ingestRecord(&handshakeRecord(.certificate)));
}

test "server role invalid certificate_verify body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, engine.ingestRecord(&handshakeRecord(.certificate_verify)));
}

test "invalid encrypted_extensions body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    try std.testing.expectError(error.InvalidEncryptedExtensionsMessage, engine.ingestRecord(&handshakeRecord(.encrypted_extensions)));
}

test "new_session_ticket body is validated in connected state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    _ = try engine.ingestRecord(&newSessionTicketRecord());
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "invalid new_session_ticket body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectError(error.InvalidNewSessionTicketMessage, engine.ingestRecord(&handshakeRecord(.new_session_ticket)));
}
