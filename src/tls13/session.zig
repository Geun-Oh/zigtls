const std = @import("std");
const builtin = @import("builtin");
const alerts = @import("alerts.zig");
const certificate_validation = @import("certificate_validation.zig");
const early_data = @import("early_data.zig");
const handshake = @import("handshake.zig");
const keyschedule = @import("keyschedule.zig");
const messages = @import("messages.zig");
const ocsp = @import("ocsp.zig");
const record = @import("record.zig");
const state = @import("state.zig");
const trust_store = @import("trust_store.zig");

pub const default_signature_algorithms = [_]u16{
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0807, // ed25519
};

pub const named_group_x25519: u16 = 0x001d;
// Provisional X25519MLKEM768 NamedGroup codepoint integration path.
// Keep policy-gated because draft/final allocation can evolve.
pub const named_group_x25519_mlkem768: u16 = 0x11ec;
pub const default_named_groups = [_]u16{
    named_group_x25519,
};

pub const GroupPolicy = struct {
    allowed_named_groups: []const u16 = &default_named_groups,
    allow_hybrid_kex: bool = false,
    hybrid_named_groups: []const u16 = &.{named_group_x25519_mlkem768},
};

pub const KeyLogCallback = *const fn (label: []const u8, secret: []const u8, userdata: usize) void;
pub const NowUnixFn = *const fn () i64;

pub const SignCertificateVerifyFn = *const fn (
    transcript_hash: []const u8,
    signature_scheme: u16,
    out_signature: []u8,
    userdata: usize,
) anyerror!usize;

pub const ServerCredentials = struct {
    cert_chain_der: []const []const u8 = &.{},
    signature_scheme: u16 = 0x0807, // ed25519
    sign_certificate_verify: ?SignCertificateVerifyFn = null,
    signer_userdata: usize = 0,
};

pub const PeerValidationConfig = struct {
    enforce_certificate_verify: bool = true,
    require_peer_certificate: bool = false,
    expected_server_name: ?[]const u8 = null,
    trust_store: ?*const trust_store.TrustStore = null,
    now_unix: ?NowUnixFn = null,
    enforce_ocsp: bool = false,
    allow_soft_fail_ocsp: bool = false,
    stapled_ocsp: ?ocsp.ResponseView = null,
};

pub const Config = struct {
    role: state.Role,
    suite: keyschedule.CipherSuite,
    early_data: EarlyDataConfig = .{},
    group_policy: GroupPolicy = .{},
    allowed_signature_algorithms: []const u16 = &default_signature_algorithms,
    server_credentials: ?ServerCredentials = null,
    peer_validation: PeerValidationConfig = .{},
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

pub const InitError = error{
    InvalidConfiguration,
};

pub fn validateConfig(config: Config) InitError!void {
    if (config.early_data.enabled and config.early_data.replay_filter == null) {
        return error.InvalidConfiguration;
    }

    if (config.enable_debug_keylog and config.keylog_callback == null) {
        return error.InvalidConfiguration;
    }

    if (config.server_credentials) |creds| {
        if (creds.cert_chain_der.len == 0) return error.InvalidConfiguration;

        if (creds.sign_certificate_verify == null) return error.InvalidConfiguration;

        if (!containsU16(config.allowed_signature_algorithms, creds.signature_scheme)) {
            return error.InvalidConfiguration;
        }
    }

    if (config.peer_validation.expected_server_name) |name| {
        if (name.len == 0) return error.InvalidConfiguration;
    }

    if (config.role != .client and config.peer_validation.expected_server_name != null) {
        return error.InvalidConfiguration;
    }
}

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
    send_handshake_flight: u8,
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
    InvalidServerNameExtension,
    InvalidAlpnExtension,
    InvalidSupportedGroupsExtension,
    InvalidKeyShareExtension,
    InvalidCookieExtension,
    InvalidPreSharedKeyExtension,
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
    InvalidPreSharedKeyPlacement,
    InvalidPskBinder,
    InvalidPskBinderLength,
    PskBinderCountMismatch,
    DowngradeDetected,
    UnsupportedSignatureAlgorithm,
    MissingServerCredentials,
    MissingKeyExchangeSecret,
    MissingPeerCertificate,
    PeerCertificateValidationFailed,
    ApplicationCipherNotReady,
    DecryptFailed,
    InvalidInnerContentType,
    SequenceOverflow,
} || record.ParseError || handshake.ParseError || handshake.KeyUpdateError || state.TransitionError || alerts.DecodeError || std.mem.Allocator.Error;

const ext_server_name: u16 = 0x0000;
const ext_supported_groups: u16 = 0x000a;
const ext_alpn: u16 = 0x0010;
const ext_supported_versions: u16 = 0x002b;
const ext_cookie: u16 = 0x002c;
const ext_key_share: u16 = 0x0033;
const ext_pre_shared_key: u16 = 0x0029;
const ext_psk_key_exchange_modes: u16 = 0x002d;
const max_peer_chain_depth: usize = 8;

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
    early_secret: ?TrafficSecret = null,
    handshake_read_secret: ?TrafficSecret = null,
    handshake_write_secret: ?TrafficSecret = null,
    key_exchange_secret: ?[32]u8 = null,
    client_x25519_secret_key: ?[32]u8 = null,
    negotiated_alpn: [255]u8 = [_]u8{0} ** 255,
    negotiated_alpn_len: usize = 0,
    peer_leaf_certificate_der: ?[]u8 = null,
    saw_peer_certificate: bool = false,
    master_secret: ?TrafficSecret = null,
    latest_secret: ?TrafficSecret = null,
    early_data_idempotent: bool = false,
    early_data_within_window: bool = true,
    early_data_admitted: bool = false,
    early_data_ticket: ?[]u8 = null,
    saw_close_notify: bool = false,
    metrics: Metrics = .{},
    outbound_records: std.ArrayList([]u8),
    app_read_secret: ?TrafficSecret = null,
    app_write_secret: ?TrafficSecret = null,
    hs_read_key: [32]u8 = [_]u8{0} ** 32,
    hs_write_key: [32]u8 = [_]u8{0} ** 32,
    hs_read_iv: [12]u8 = [_]u8{0} ** 12,
    hs_write_iv: [12]u8 = [_]u8{0} ** 12,
    hs_key_len: usize = 0,
    hs_tag_len: usize = 16,
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    app_read_key: [32]u8 = [_]u8{0} ** 32,
    app_write_key: [32]u8 = [_]u8{0} ** 32,
    app_read_iv: [12]u8 = [_]u8{0} ** 12,
    app_write_iv: [12]u8 = [_]u8{0} ** 12,
    app_key_len: usize = 0,
    app_tag_len: usize = 16,
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    app_data_scratch: [record.max_plaintext]u8 = [_]u8{0} ** record.max_plaintext,

    pub fn init(allocator: std.mem.Allocator, config: Config) Engine {
        return .{
            .allocator = allocator,
            .config = config,
            .machine = state.Machine.init(config.role),
            .transcript = Transcript.init(config.suite),
            .outbound_records = .empty,
        };
    }

    pub fn initChecked(allocator: std.mem.Allocator, config: Config) InitError!Engine {
        try validateConfig(config);
        return init(allocator, config);
    }

    pub fn deinit(self: *Engine) void {
        self.zeroizeLatestSecret();
        self.zeroizeStagedSecrets();
        self.zeroizeKeyExchangeSecret();
        self.zeroizeClientEphemeralState();
        self.clearPeerLeafCertificate();
        self.clearEarlyDataTicket();
        self.zeroizeHandshakeTrafficState();
        self.zeroizeApplicationTrafficState();
        while (self.outbound_records.items.len > 0) {
            const rec = self.outbound_records.orderedRemove(0);
            self.allocator.free(rec);
        }
        self.outbound_records.deinit(self.allocator);
    }

    pub fn popOutboundRecord(self: *Engine) ?[]u8 {
        if (self.outbound_records.items.len == 0) return null;
        return self.outbound_records.orderedRemove(0);
    }

    pub fn beginEarlyData(self: *Engine, ticket: []const u8, idempotent: bool) !void {
        if (ticket.len > self.config.early_data.max_ticket_len) return error.EarlyDataTicketTooLarge;
        self.clearEarlyDataTicket();
        self.early_data_ticket = try self.allocator.alloc(u8, ticket.len);
        @memcpy(self.early_data_ticket.?, ticket);
        self.early_data_idempotent = idempotent;
        self.early_data_within_window = true;
        self.early_data_admitted = false;
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

    pub fn setClientX25519SecretKey(self: *Engine, secret_key: [32]u8) EngineError!void {
        if (self.config.role != .client) return error.IllegalTransition;
        self.zeroizeClientEphemeralState();
        self.client_x25519_secret_key = secret_key;
    }

    pub fn generateClientX25519KeyShare(self: *Engine) EngineError![32]u8 {
        if (self.config.role != .client) return error.IllegalTransition;
        self.zeroizeClientEphemeralState();
        const kp = std.crypto.dh.X25519.KeyPair.generate();
        self.client_x25519_secret_key = kp.secret_key;
        return kp.public_key;
    }

    pub fn ingestRecord(self: *Engine, record_bytes: []const u8) EngineError!IngestResult {
        const parsed = try record.parseRecord(record_bytes);
        var result = IngestResult.init(5 + parsed.payload.len);

        switch (parsed.header.content_type) {
            .handshake => {
                try self.ingestHandshakePayload(parsed.payload, &result);
            },
            .change_cipher_spec => {
                if (!isIgnorableTls13ChangeCipherSpec(parsed.payload)) return error.UnsupportedRecordType;
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
                if (self.machine.state == .connected) {
                    try self.decryptConnectedApplicationData(parsed.header, parsed.payload, &result);
                } else {
                    if (self.hs_key_len != 0) {
                        try self.decryptHandshakeApplicationData(parsed.header, parsed.payload, &result);
                    } else {
                        if (self.config.role != .server) return error.EarlyDataRejected;
                        if (!self.config.early_data.enabled) return error.EarlyDataRejected;
                        if (!self.early_data_idempotent) return error.EarlyDataRejected;
                        if (!self.early_data_within_window) return error.EarlyDataTicketExpired;
                        if (!self.early_data_admitted) {
                            const replay_filter = self.config.early_data.replay_filter orelse return error.MissingReplayFilter;
                            const ticket = self.early_data_ticket orelse return error.EarlyDataRejected;
                            const scope: early_data.ReplayScopeKey = .{
                                .node_id = self.config.early_data.replay_node_id,
                                .epoch = self.config.early_data.replay_epoch,
                            };

                            if (replay_filter.seenOrInsertScoped(scope, ticket)) return error.EarlyDataRejected;
                            self.early_data_admitted = true;
                        }
                        try result.push(.{ .application_data = parsed.payload });
                    }
                }
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

    pub fn buildProtectedKeyUpdateRecord(
        self: *Engine,
        allocator: std.mem.Allocator,
        request: handshake.KeyUpdateRequest,
    ) (EngineError || std.mem.Allocator.Error)![]u8 {
        try self.ensureApplicationTrafficReady();

        const hs_payload_len: usize = 5;
        const inner_len = hs_payload_len + 1;
        if (inner_len > record.max_plaintext) return error.RecordOverflow;
        const rec_len = 5 + inner_len + self.app_tag_len;

        var frame = try allocator.alloc(u8, rec_len);
        errdefer allocator.free(frame);

        frame[0] = @intFromEnum(record.ContentType.application_data);
        std.mem.writeInt(u16, frame[1..3], record.tls_legacy_record_version, .big);
        std.mem.writeInt(u16, frame[3..5], @as(u16, @intCast(inner_len + self.app_tag_len)), .big);

        var clear: [record.max_plaintext]u8 = undefined;
        clear[0] = @intFromEnum(state.HandshakeType.key_update);
        const len = handshake.writeU24(1);
        @memcpy(clear[1..4], &len);
        clear[4] = @intFromEnum(request);
        clear[5] = @intFromEnum(record.ContentType.handshake);

        const nonce = buildTls13Nonce(self.app_write_iv, self.app_write_seq);
        var tag: [16]u8 = undefined;
        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const key = self.app_write_key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_aes_256_gcm_sha384 => {
                const key = self.app_write_key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_chacha20_poly1305_sha256 => {
                const key = self.app_write_key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
        }
        @memcpy(frame[5 + inner_len ..], &tag);
        self.app_write_seq = std.math.add(u64, self.app_write_seq, 1) catch return error.SequenceOverflow;
        return frame;
    }

    pub fn onKeyUpdateRecordQueued(self: *Engine) void {
        self.ratchetWriteTrafficSecret();
    }

    pub fn buildApplicationDataRecord(
        self: *Engine,
        allocator: std.mem.Allocator,
        plaintext: []const u8,
    ) (EngineError || std.mem.Allocator.Error)![]u8 {
        if (plaintext.len == 0) return allocator.alloc(u8, 0);
        if (plaintext.len + 1 > record.max_plaintext) return error.RecordOverflow;
        try self.ensureApplicationTrafficReady();

        const inner_len = plaintext.len + 1;
        const rec_len = 5 + inner_len + self.app_tag_len;
        var frame = try allocator.alloc(u8, rec_len);
        errdefer allocator.free(frame);

        frame[0] = @intFromEnum(record.ContentType.application_data);
        std.mem.writeInt(u16, frame[1..3], record.tls_legacy_record_version, .big);
        std.mem.writeInt(u16, frame[3..5], @as(u16, @intCast(inner_len + self.app_tag_len)), .big);

        var clear: [record.max_plaintext]u8 = undefined;
        @memcpy(clear[0..plaintext.len], plaintext);
        clear[plaintext.len] = @intFromEnum(record.ContentType.application_data);
        const nonce = buildTls13Nonce(self.app_write_iv, self.app_write_seq);
        var tag: [16]u8 = undefined;

        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const key = self.app_write_key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_aes_256_gcm_sha384 => {
                const key = self.app_write_key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_chacha20_poly1305_sha256 => {
                const key = self.app_write_key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
        }
        @memcpy(frame[5 + inner_len ..], &tag);
        self.app_write_seq = std.math.add(u64, self.app_write_seq, 1) catch return error.SequenceOverflow;
        return frame;
    }

    fn ingestHandshakePayload(self: *Engine, payload: []const u8, result: *IngestResult) EngineError!void {
        var cursor = payload;
        while (cursor.len > 0) {
            const frame = try handshake.parseOne(cursor);
            const frame_len = 4 + @as(usize, @intCast(frame.header.length));

            try self.validateHandshakeBody(frame.header.handshake_type, frame.body);
            self.transcript.update(cursor[0..frame_len]);
            self.metrics.handshake_messages += 1;

            const prev_state = self.machine.state;
            const event = handshake.classifyEvent(frame);

            try self.machine.onEvent(event);

            try result.push(.{ .handshake = frame.header.handshake_type });

            if (event == .hello_retry_request) {
                try result.push(.{ .hello_retry_request = {} });
            }

            if (self.config.role == .client and
                event == .server_hello and
                self.machine.state == .wait_encrypted_extensions)
            {
                try self.derivePreApplicationKeyScheduleStages();
            }

            if (self.config.role == .server and frame.header.handshake_type == .client_hello and prev_state == .start) {
                const queued = try self.queueServerHandshakeFlight(frame.body);

                if (queued > 0) {
                    try result.push(.{ .send_handshake_flight = queued });
                }
            }

            if (frame.header.handshake_type == .key_update) {
                self.metrics.keyupdate_messages += 1;
                const req = try handshake.parseKeyUpdateRequest(frame.body);
                self.ratchetReadTrafficSecret();
                self.ratchetLatestTrafficSecret();

                try result.push(.{ .key_update = req });

                if (req == .update_requested) {
                    try result.push(.{ .send_key_update = .update_not_requested });
                }
            }
            try result.push(.{ .state_changed = self.machine.state });

            if (prev_state != .connected and self.machine.state == .connected) {
                self.metrics.connected_transitions += 1;

                if (!(self.config.role == .server and self.app_key_len != 0)) {
                    try self.deriveConnectedKeyScheduleStages();
                }
                self.emitDebugKeyLog(self.keylogInitialLabel());
            }
            cursor = frame.rest;
        }
    }

    fn decryptConnectedApplicationData(
        self: *Engine,
        header: record.Header,
        payload: []const u8,
        result: *IngestResult,
    ) EngineError!void {
        try self.ensureApplicationTrafficReady();

        if (payload.len < self.app_tag_len + 1) return error.DecryptFailed;
        const ciphertext_len = payload.len - self.app_tag_len;

        if (ciphertext_len > self.app_data_scratch.len) return error.RecordOverflow;
        const ciphertext = payload[0..ciphertext_len];
        var tag: [16]u8 = undefined;
        @memcpy(&tag, payload[ciphertext_len..]);
        const nonce = buildTls13Nonce(self.app_read_iv, self.app_read_seq);
        const ad = header.encode();

        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const key = self.app_read_key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
            .tls_aes_256_gcm_sha384 => {
                const key = self.app_read_key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
            .tls_chacha20_poly1305_sha256 => {
                const key = self.app_read_key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
        }

        self.app_read_seq = std.math.add(u64, self.app_read_seq, 1) catch return error.SequenceOverflow;
        const inner = std.mem.trimRight(u8, self.app_data_scratch[0..ciphertext_len], "\x00");

        if (inner.len == 0) return error.InvalidInnerContentType;
        const inner_type = std.meta.intToEnum(record.ContentType, inner[inner.len - 1]) catch return error.InvalidInnerContentType;
        const clear = inner[0 .. inner.len - 1];

        switch (inner_type) {
            .application_data => {
                try result.push(.{ .application_data = clear });
            },
            .alert => {
                const alert = try alerts.Alert.decode(clear);
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
            .handshake => try self.ingestHandshakePayload(clear, result),
            else => return error.InvalidInnerContentType,
        }
    }

    fn decryptHandshakeApplicationData(
        self: *Engine,
        header: record.Header,
        payload: []const u8,
        result: *IngestResult,
    ) EngineError!void {
        if (payload.len < self.hs_tag_len + 1) return error.DecryptFailed;
        const ciphertext_len = payload.len - self.hs_tag_len;
        if (ciphertext_len > self.app_data_scratch.len) return error.RecordOverflow;
        const ciphertext = payload[0..ciphertext_len];
        var tag: [16]u8 = undefined;
        @memcpy(&tag, payload[ciphertext_len..]);
        const nonce = buildTls13Nonce(self.hs_read_iv, self.hs_read_seq);
        const ad = header.encode();

        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const key = self.hs_read_key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
            .tls_aes_256_gcm_sha384 => {
                const key = self.hs_read_key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
            .tls_chacha20_poly1305_sha256 => {
                const key = self.hs_read_key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(self.app_data_scratch[0..ciphertext_len], ciphertext, tag, &ad, nonce, key) catch return error.DecryptFailed;
            },
        }

        self.hs_read_seq = std.math.add(u64, self.hs_read_seq, 1) catch return error.SequenceOverflow;
        const inner = std.mem.trimRight(u8, self.app_data_scratch[0..ciphertext_len], "\x00");
        if (inner.len == 0) return error.InvalidInnerContentType;
        const inner_type = std.meta.intToEnum(record.ContentType, inner[inner.len - 1]) catch return error.InvalidInnerContentType;
        const clear = inner[0 .. inner.len - 1];
        switch (inner_type) {
            .handshake => try self.ingestHandshakePayload(clear, result),
            .alert => {
                const alert = try alerts.Alert.decode(clear);
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
            else => return error.InvalidInnerContentType,
        }
    }

    fn queueServerHandshakeFlight(self: *Engine, client_hello_body: []const u8) EngineError!u8 {
        const creds = self.config.server_credentials orelse return error.MissingServerCredentials;
        _ = creds.sign_certificate_verify orelse return error.MissingServerCredentials;

        var hello = messages.ClientHello.decode(self.allocator, client_hello_body) catch return error.InvalidHelloMessage;
        defer hello.deinit(self.allocator);
        const client_pub = extractClientHelloX25519Public(hello.extensions) catch return error.InvalidKeyShareExtension;
        const server_kp = std.crypto.dh.X25519.KeyPair.generate();
        const shared = std.crypto.dh.X25519.scalarmult(server_kp.secret_key, client_pub) catch return error.InvalidKeyShareExtension;
        self.key_exchange_secret = shared;
        try self.captureClientHelloAlpnSelection(hello.extensions);

        var count: u8 = 0;
        const sh = try self.buildServerHelloBody(hello, server_kp.public_key);
        try self.enqueueHandshakeRecord(.server_hello, sh);
        count += 1;
        try self.derivePreApplicationKeyScheduleStages();

        const ee = try self.buildEncryptedExtensionsBody();
        try self.enqueueEncryptedHandshakeRecord(.encrypted_extensions, ee);
        count += 1;

        const cert = try self.buildCertificateBody(creds);
        try self.enqueueEncryptedHandshakeRecord(.certificate, cert);
        count += 1;

        const cert_verify = try self.buildCertificateVerifyBody(creds);
        try self.enqueueEncryptedHandshakeRecord(.certificate_verify, cert_verify);
        count += 1;

        const fin = try self.buildFinishedBody();
        try self.enqueueEncryptedHandshakeRecord(.finished, fin);
        count += 1;
        try self.deriveConnectedKeyScheduleStages();

        return count;
    }

    fn buildServerHelloBody(self: *Engine, hello: messages.ClientHello, server_pub: [32]u8) EngineError![]u8 {
        const ext_version = try self.allocator.dupe(u8, &.{ 0x03, 0x04 });
        errdefer self.allocator.free(ext_version);
        var ext_key_share_data = try self.allocator.alloc(u8, 2 + 2 + server_pub.len);
        errdefer self.allocator.free(ext_key_share_data);
        std.mem.writeInt(u16, ext_key_share_data[0..2], named_group_x25519, .big);
        std.mem.writeInt(u16, ext_key_share_data[2..4], @as(u16, @intCast(server_pub.len)), .big);
        @memcpy(ext_key_share_data[4..], &server_pub);
        var ext_list = try self.allocator.alloc(messages.Extension, 2);
        errdefer self.allocator.free(ext_list);
        ext_list[0] = .{ .extension_type = ext_supported_versions, .data = ext_version };
        ext_list[1] = .{ .extension_type = ext_key_share, .data = ext_key_share_data };

        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);

        var sh = messages.ServerHello{
            .random = random,
            .session_id_echo = try self.allocator.dupe(u8, hello.session_id),
            .cipher_suite = configuredCipherSuiteCodepoint(self.config.suite),
            .compression_method = 0x00,
            .extensions = ext_list,
        };
        defer sh.deinit(self.allocator);
        return sh.encode(self.allocator) catch return error.InvalidHelloMessage;
    }

    fn buildEncryptedExtensionsBody(self: *Engine) EngineError![]u8 {
        if (self.negotiated_alpn_len == 0) {
            const out = try self.allocator.alloc(u8, 2);
            out[0] = 0x00;
            out[1] = 0x00;
            return out;
        }

        const protocol_len = self.negotiated_alpn_len;
        const list_len = 1 + protocol_len;
        const ext_data_len = 2 + list_len;
        const ext_len = 4 + ext_data_len;
        const out_len = 2 + ext_len;
        var out = try self.allocator.alloc(u8, out_len);
        std.mem.writeInt(u16, out[0..2], @as(u16, @intCast(ext_len)), .big);
        std.mem.writeInt(u16, out[2..4], ext_alpn, .big);
        std.mem.writeInt(u16, out[4..6], @as(u16, @intCast(ext_data_len)), .big);
        std.mem.writeInt(u16, out[6..8], @as(u16, @intCast(list_len)), .big);
        out[8] = @as(u8, @intCast(protocol_len));
        @memcpy(out[9 .. 9 + protocol_len], self.negotiated_alpn[0..protocol_len]);
        return out;
    }

    fn captureClientHelloAlpnSelection(self: *Engine, extensions: []const messages.Extension) EngineError!void {
        self.negotiated_alpn_len = 0;
        const alpn = findExtensionData(extensions, ext_alpn) orelse return;
        const selected = try firstClientHelloAlpnProtocol(alpn);
        if (selected.len > self.negotiated_alpn.len) return error.InvalidAlpnExtension;
        @memcpy(self.negotiated_alpn[0..selected.len], selected);
        self.negotiated_alpn_len = selected.len;
    }

    fn buildCertificateBody(self: *Engine, creds: ServerCredentials) EngineError![]u8 {
        var cert_list_len: usize = 0;
        for (creds.cert_chain_der) |cert_der| {
            cert_list_len += 3 + cert_der.len + 2;
        }
        const body_len = 1 + 3 + cert_list_len;
        var out = try self.allocator.alloc(u8, body_len);
        var i: usize = 0;
        out[i] = 0x00; // request context len
        i += 1;
        const list_u24 = handshake.writeU24(@as(u24, @intCast(cert_list_len)));
        @memcpy(out[i .. i + 3], &list_u24);
        i += 3;
        for (creds.cert_chain_der) |cert_der| {
            const cert_len_u24 = handshake.writeU24(@as(u24, @intCast(cert_der.len)));
            @memcpy(out[i .. i + 3], &cert_len_u24);
            i += 3;
            @memcpy(out[i .. i + cert_der.len], cert_der);
            i += cert_der.len;
            out[i] = 0x00;
            out[i + 1] = 0x00;
            i += 2;
        }
        return out;
    }

    fn buildCertificateVerifyBody(self: *Engine, creds: ServerCredentials) EngineError![]u8 {
        const signer = creds.sign_certificate_verify orelse return error.MissingServerCredentials;
        if (!self.isAllowedSignatureAlgorithm(creds.signature_scheme)) {
            return error.UnsupportedSignatureAlgorithm;
        }
        const verify_payload = try self.buildCertificateVerifyPayload(.local);
        defer self.allocator.free(verify_payload);
        var sig_tmp: [1024]u8 = undefined;
        const sig_len = signer(
            verify_payload,
            creds.signature_scheme,
            sig_tmp[0..],
            creds.signer_userdata,
        ) catch return error.MissingServerCredentials;
        if (sig_len == 0 or sig_len > sig_tmp.len or sig_len > std.math.maxInt(u16)) {
            return error.InvalidInnerContentType;
        }
        if (creds.signature_scheme == 0x0807 and sig_len != std.crypto.sign.Ed25519.Signature.encoded_length) {
            return error.InvalidCertificateVerifyMessage;
        }

        const out = try self.allocator.alloc(u8, 4 + sig_len);
        std.mem.writeInt(u16, out[0..2], creds.signature_scheme, .big);
        std.mem.writeInt(u16, out[2..4], @as(u16, @intCast(sig_len)), .big);
        @memcpy(out[4..], sig_tmp[0..sig_len]);
        return out;
    }

    fn buildFinishedBody(self: *Engine) EngineError![]u8 {
        const secret_to_use: TrafficSecret = self.handshake_write_secret orelse return error.MissingKeyExchangeSecret;
        switch (secret_to_use) {
            .sha256 => |secret| {
                const transcript_hash = self.transcriptDigestSha256();
                const fin_key = keyschedule.finishedKey(.tls_aes_128_gcm_sha256, secret);
                const verify = keyschedule.finishedVerifyData(.tls_aes_128_gcm_sha256, fin_key, &transcript_hash);
                return try self.allocator.dupe(u8, &verify);
            },
            .sha384 => |secret| {
                const transcript_hash = self.transcriptDigestSha384();
                const fin_key = keyschedule.finishedKey(.tls_aes_256_gcm_sha384, secret);
                const verify = keyschedule.finishedVerifyData(.tls_aes_256_gcm_sha384, fin_key, &transcript_hash);
                return try self.allocator.dupe(u8, &verify);
            },
        }
    }

    fn enqueueHandshakeRecord(self: *Engine, hs_type: state.HandshakeType, body: []const u8) EngineError!void {
        const hs_len_u24 = handshake.writeU24(@as(u24, @intCast(body.len)));
        var frame = try self.allocator.alloc(u8, 5 + 4 + body.len);
        errdefer self.allocator.free(frame);

        frame[0] = @intFromEnum(record.ContentType.handshake);
        std.mem.writeInt(u16, frame[1..3], record.tls_legacy_record_version, .big);
        std.mem.writeInt(u16, frame[3..5], @as(u16, @intCast(4 + body.len)), .big);
        frame[5] = @intFromEnum(hs_type);
        @memcpy(frame[6..9], &hs_len_u24);
        @memcpy(frame[9..], body);
        self.transcript.update(frame[5..]);
        try self.outbound_records.append(self.allocator, frame);
        self.allocator.free(@constCast(body));
    }

    fn enqueueEncryptedHandshakeRecord(self: *Engine, hs_type: state.HandshakeType, body: []const u8) EngineError!void {
        if (self.hs_key_len == 0) return error.MissingKeyExchangeSecret;
        const hs_payload_len = 4 + body.len;
        const inner_len = hs_payload_len + 1;
        if (inner_len > record.max_plaintext) return error.RecordOverflow;
        const rec_len = 5 + inner_len + self.hs_tag_len;

        var frame = try self.allocator.alloc(u8, rec_len);
        errdefer self.allocator.free(frame);

        frame[0] = @intFromEnum(record.ContentType.application_data);
        std.mem.writeInt(u16, frame[1..3], record.tls_legacy_record_version, .big);
        std.mem.writeInt(u16, frame[3..5], @as(u16, @intCast(inner_len + self.hs_tag_len)), .big);

        var clear: [record.max_plaintext]u8 = undefined;
        clear[0] = @intFromEnum(hs_type);
        const hs_len_u24 = handshake.writeU24(@as(u24, @intCast(body.len)));
        @memcpy(clear[1..4], &hs_len_u24);
        @memcpy(clear[4 .. 4 + body.len], body);
        clear[hs_payload_len] = @intFromEnum(record.ContentType.handshake);

        const nonce = buildTls13Nonce(self.hs_write_iv, self.hs_write_seq);
        var tag: [16]u8 = undefined;
        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const key = self.hs_write_key[0..16].*;
                std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_aes_256_gcm_sha384 => {
                const key = self.hs_write_key[0..32].*;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
            .tls_chacha20_poly1305_sha256 => {
                const key = self.hs_write_key[0..32].*;
                std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(frame[5 .. 5 + inner_len], &tag, clear[0..inner_len], frame[0..5], nonce, key);
            },
        }
        @memcpy(frame[5 + inner_len ..], &tag);
        self.hs_write_seq = std.math.add(u64, self.hs_write_seq, 1) catch return error.SequenceOverflow;

        self.transcript.update(clear[0..hs_payload_len]);
        try self.outbound_records.append(self.allocator, frame);
        self.allocator.free(@constCast(body));
    }

    fn deriveConnectedKeyScheduleStages(self: *Engine) EngineError!void {
        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const digest = self.transcriptDigestSha256();
                const empty_digest = emptyTranscriptHashSha256();
                const zeros = [_]u8{0} ** 32;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_aes_128_gcm_sha256, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_aes_128_gcm_sha256, &derived, ikm);
                const master_derived = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, hs_base, "derived", &empty_digest);
                const master = keyschedule.extract(.tls_aes_128_gcm_sha256, &master_derived, &zeros);
                const client_ap = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, master, "c ap traffic", &digest);
                const server_ap = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, master, "s ap traffic", &digest);
                self.early_secret = .{ .sha256 = early };
                self.master_secret = .{ .sha256 = master };
                self.installApplicationSecrets(
                    .{ .sha256 = client_ap },
                    .{ .sha256 = server_ap },
                );
            },
            .tls_chacha20_poly1305_sha256 => {
                const digest = self.transcriptDigestSha256();
                const empty_digest = emptyTranscriptHashSha256();
                const zeros = [_]u8{0} ** 32;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_chacha20_poly1305_sha256, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_chacha20_poly1305_sha256, &derived, ikm);
                const master_derived = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, hs_base, "derived", &empty_digest);
                const master = keyschedule.extract(.tls_chacha20_poly1305_sha256, &master_derived, &zeros);
                const client_ap = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, master, "c ap traffic", &digest);
                const server_ap = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, master, "s ap traffic", &digest);
                self.early_secret = .{ .sha256 = early };
                self.master_secret = .{ .sha256 = master };
                self.installApplicationSecrets(
                    .{ .sha256 = client_ap },
                    .{ .sha256 = server_ap },
                );
            },
            .tls_aes_256_gcm_sha384 => {
                const digest = self.transcriptDigestSha384();
                const empty_digest = emptyTranscriptHashSha384();
                const zeros = [_]u8{0} ** 48;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_aes_256_gcm_sha384, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_aes_256_gcm_sha384, &derived, ikm);
                const master_derived = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, hs_base, "derived", &empty_digest);
                const master = keyschedule.extract(.tls_aes_256_gcm_sha384, &master_derived, &zeros);
                const client_ap = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, master, "c ap traffic", &digest);
                const server_ap = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, master, "s ap traffic", &digest);
                self.early_secret = .{ .sha384 = early };
                self.master_secret = .{ .sha384 = master };
                self.installApplicationSecrets(
                    .{ .sha384 = client_ap },
                    .{ .sha384 = server_ap },
                );
            },
        }
    }

    fn derivePreApplicationKeyScheduleStages(self: *Engine) EngineError!void {
        return switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => blk: {
                const digest = self.transcriptDigestSha256();
                const empty_digest = emptyTranscriptHashSha256();
                const zeros = [_]u8{0} ** 32;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_aes_128_gcm_sha256, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_aes_128_gcm_sha256, &derived, ikm);
                const client_hs_traffic = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, hs_base, "c hs traffic", &digest);
                const server_hs_traffic = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, hs_base, "s hs traffic", &digest);
                self.early_secret = .{ .sha256 = early };
                self.installHandshakeTrafficSecrets(
                    .{ .sha256 = client_hs_traffic },
                    .{ .sha256 = server_hs_traffic },
                );
                break :blk;
            },
            .tls_chacha20_poly1305_sha256 => blk: {
                const digest = self.transcriptDigestSha256();
                const empty_digest = emptyTranscriptHashSha256();
                const zeros = [_]u8{0} ** 32;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_chacha20_poly1305_sha256, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_chacha20_poly1305_sha256, &derived, ikm);
                const client_hs_traffic = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, hs_base, "c hs traffic", &digest);
                const server_hs_traffic = keyschedule.deriveSecret(.tls_chacha20_poly1305_sha256, hs_base, "s hs traffic", &digest);
                self.early_secret = .{ .sha256 = early };
                self.installHandshakeTrafficSecrets(
                    .{ .sha256 = client_hs_traffic },
                    .{ .sha256 = server_hs_traffic },
                );
                break :blk;
            },
            .tls_aes_256_gcm_sha384 => blk: {
                const digest = self.transcriptDigestSha384();
                const empty_digest = emptyTranscriptHashSha384();
                const zeros = [_]u8{0} ** 48;
                const ikm = try self.keyExchangeIkm();
                const early = keyschedule.extract(.tls_aes_256_gcm_sha384, &zeros, &zeros);
                const derived = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, early, "derived", &empty_digest);
                const hs_base = keyschedule.extract(.tls_aes_256_gcm_sha384, &derived, ikm);
                const client_hs_traffic = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, hs_base, "c hs traffic", &digest);
                const server_hs_traffic = keyschedule.deriveSecret(.tls_aes_256_gcm_sha384, hs_base, "s hs traffic", &digest);
                self.early_secret = .{ .sha384 = early };
                self.installHandshakeTrafficSecrets(
                    .{ .sha384 = client_hs_traffic },
                    .{ .sha384 = server_hs_traffic },
                );
                break :blk;
            },
        };
    }

    fn installHandshakeTrafficSecrets(self: *Engine, client_secret: TrafficSecret, server_secret: TrafficSecret) void {
        if (self.config.role == .client) {
            self.handshake_write_secret = client_secret;
            self.handshake_read_secret = server_secret;
        } else {
            self.handshake_write_secret = server_secret;
            self.handshake_read_secret = client_secret;
        }

        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const write_secret = switch (self.handshake_write_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const read_secret = switch (self.handshake_read_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const w_key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, write_secret, "key", "", 16);
                const r_key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, read_secret, "key", "", 16);
                const w_iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, read_secret, "iv", "", 12);
                @memset(self.hs_write_key[0..], 0);
                @memset(self.hs_read_key[0..], 0);
                @memcpy(self.hs_write_key[0..16], &w_key);
                @memcpy(self.hs_read_key[0..16], &r_key);
                @memcpy(self.hs_write_iv[0..], &w_iv);
                @memcpy(self.hs_read_iv[0..], &r_iv);
                self.hs_key_len = 16;
            },
            .tls_aes_256_gcm_sha384 => {
                const write_secret = switch (self.handshake_write_secret.?) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const read_secret = switch (self.handshake_read_secret.?) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const w_key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, write_secret, "key", "", 32);
                const r_key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, read_secret, "key", "", 32);
                const w_iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, read_secret, "iv", "", 12);
                @memcpy(self.hs_write_key[0..32], &w_key);
                @memcpy(self.hs_read_key[0..32], &r_key);
                @memcpy(self.hs_write_iv[0..], &w_iv);
                @memcpy(self.hs_read_iv[0..], &r_iv);
                self.hs_key_len = 32;
            },
            .tls_chacha20_poly1305_sha256 => {
                const write_secret = switch (self.handshake_write_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const read_secret = switch (self.handshake_read_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const w_key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, write_secret, "key", "", 32);
                const r_key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, read_secret, "key", "", 32);
                const w_iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, read_secret, "iv", "", 12);
                @memcpy(self.hs_write_key[0..32], &w_key);
                @memcpy(self.hs_read_key[0..32], &r_key);
                @memcpy(self.hs_write_iv[0..], &w_iv);
                @memcpy(self.hs_read_iv[0..], &r_iv);
                self.hs_key_len = 32;
            },
        }
        self.hs_tag_len = 16;
        self.hs_write_seq = 0;
        self.hs_read_seq = 0;
    }

    fn keyExchangeIkm(self: *Engine) EngineError![]const u8 {
        if (self.key_exchange_secret) |*secret| return secret[0..];
        return error.MissingKeyExchangeSecret;
    }

    fn ensureApplicationTrafficReady(self: *Engine) EngineError!void {
        if (self.machine.state != .connected) return error.ApplicationCipherNotReady;
        if (self.app_key_len != 0) return;
        try self.deriveConnectedKeyScheduleStages();
        if (self.app_key_len == 0) return error.ApplicationCipherNotReady;
    }

    fn installApplicationSecrets(self: *Engine, client_secret: TrafficSecret, server_secret: TrafficSecret) void {
        if (self.config.role == .client) {
            self.app_write_secret = client_secret;
            self.app_read_secret = server_secret;
        } else {
            self.app_write_secret = server_secret;
            self.app_read_secret = client_secret;
        }

        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const write_secret = switch (self.app_write_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const read_secret = switch (self.app_read_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const w_key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, write_secret, "key", "", 16);
                const r_key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, read_secret, "key", "", 16);
                const w_iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, read_secret, "iv", "", 12);
                @memset(self.app_write_key[0..], 0);
                @memset(self.app_read_key[0..], 0);
                @memcpy(self.app_write_key[0..16], &w_key);
                @memcpy(self.app_read_key[0..16], &r_key);
                @memcpy(self.app_write_iv[0..], &w_iv);
                @memcpy(self.app_read_iv[0..], &r_iv);
                self.app_key_len = 16;
                self.latest_secret = self.app_write_secret;
            },
            .tls_aes_256_gcm_sha384 => {
                const write_secret = switch (self.app_write_secret.?) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const read_secret = switch (self.app_read_secret.?) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const w_key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, write_secret, "key", "", 32);
                const r_key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, read_secret, "key", "", 32);
                const w_iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, read_secret, "iv", "", 12);
                @memcpy(self.app_write_key[0..32], &w_key);
                @memcpy(self.app_read_key[0..32], &r_key);
                @memcpy(self.app_write_iv[0..], &w_iv);
                @memcpy(self.app_read_iv[0..], &r_iv);
                self.app_key_len = 32;
                self.latest_secret = self.app_write_secret;
            },
            .tls_chacha20_poly1305_sha256 => {
                const write_secret = switch (self.app_write_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const read_secret = switch (self.app_read_secret.?) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const w_key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, write_secret, "key", "", 32);
                const r_key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, read_secret, "key", "", 32);
                const w_iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, write_secret, "iv", "", 12);
                const r_iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, read_secret, "iv", "", 12);
                @memcpy(self.app_write_key[0..32], &w_key);
                @memcpy(self.app_read_key[0..32], &r_key);
                @memcpy(self.app_write_iv[0..], &w_iv);
                @memcpy(self.app_read_iv[0..], &r_iv);
                self.app_key_len = 32;
                self.latest_secret = self.app_write_secret;
            },
        }
        self.app_tag_len = 16;
        self.app_write_seq = 0;
        self.app_read_seq = 0;
    }

    fn ratchetReadTrafficSecret(self: *Engine) void {
        const cur = self.app_read_secret orelse return;
        self.app_read_secret = switch (self.config.suite) {
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
        const read = self.app_read_secret.?;
        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const sec = switch (read) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, sec, "key", "", 16);
                const iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, sec, "iv", "", 12);
                @memcpy(self.app_read_key[0..16], &key);
                @memcpy(self.app_read_iv[0..], &iv);
            },
            .tls_aes_256_gcm_sha384 => {
                const sec = switch (read) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, sec, "key", "", 32);
                const iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, sec, "iv", "", 12);
                @memcpy(self.app_read_key[0..32], &key);
                @memcpy(self.app_read_iv[0..], &iv);
            },
            .tls_chacha20_poly1305_sha256 => {
                const sec = switch (read) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, sec, "key", "", 32);
                const iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, sec, "iv", "", 12);
                @memcpy(self.app_read_key[0..32], &key);
                @memcpy(self.app_read_iv[0..], &iv);
            },
        }
        self.app_read_seq = 0;
    }

    fn ratchetWriteTrafficSecret(self: *Engine) void {
        const cur = self.app_write_secret orelse return;
        self.app_write_secret = switch (self.config.suite) {
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
        const write = self.app_write_secret.?;
        switch (self.config.suite) {
            .tls_aes_128_gcm_sha256 => {
                const sec = switch (write) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const key = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, sec, "key", "", 16);
                const iv = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, sec, "iv", "", 12);
                @memcpy(self.app_write_key[0..16], &key);
                @memcpy(self.app_write_iv[0..], &iv);
            },
            .tls_aes_256_gcm_sha384 => {
                const sec = switch (write) {
                    .sha256 => unreachable,
                    .sha384 => |s| s,
                };
                const key = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, sec, "key", "", 32);
                const iv = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, sec, "iv", "", 12);
                @memcpy(self.app_write_key[0..32], &key);
                @memcpy(self.app_write_iv[0..], &iv);
            },
            .tls_chacha20_poly1305_sha256 => {
                const sec = switch (write) {
                    .sha256 => |s| s,
                    .sha384 => unreachable,
                };
                const key = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, sec, "key", "", 32);
                const iv = keyschedule.deriveLabel(.tls_chacha20_poly1305_sha256, sec, "iv", "", 12);
                @memcpy(self.app_write_key[0..32], &key);
                @memcpy(self.app_write_iv[0..], &iv);
            },
        }
        self.app_write_seq = 0;
        self.latest_secret = self.app_write_secret;
        self.emitDebugKeyLog(self.keylogNextLabel());
    }

    fn zeroizeApplicationTrafficState(self: *Engine) void {
        std.crypto.secureZero(u8, self.app_write_key[0..]);
        std.crypto.secureZero(u8, self.app_read_key[0..]);
        std.crypto.secureZero(u8, self.app_write_iv[0..]);
        std.crypto.secureZero(u8, self.app_read_iv[0..]);
        self.app_write_secret = null;
        self.app_read_secret = null;
        self.app_key_len = 0;
        self.app_tag_len = 16;
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn zeroizeHandshakeTrafficState(self: *Engine) void {
        std.crypto.secureZero(u8, self.hs_write_key[0..]);
        std.crypto.secureZero(u8, self.hs_read_key[0..]);
        std.crypto.secureZero(u8, self.hs_write_iv[0..]);
        std.crypto.secureZero(u8, self.hs_read_iv[0..]);
        self.hs_key_len = 0;
        self.hs_tag_len = 16;
        self.hs_write_seq = 0;
        self.hs_read_seq = 0;
    }

    fn transcriptDigestSha256(self: *Engine) [32]u8 {
        const hasher = switch (self.transcript) {
            .sha256 => |h| h,
            .sha384 => unreachable,
        };
        var digest: [32]u8 = undefined;
        var h = hasher;
        h.final(&digest);
        return digest;
    }

    fn transcriptDigestSha384(self: *Engine) [48]u8 {
        const hasher = switch (self.transcript) {
            .sha256 => unreachable,
            .sha384 => |h| h,
        };
        var digest: [48]u8 = undefined;
        var h = hasher;
        h.final(&digest);
        return digest;
    }

    fn emptyTranscriptHashSha256() [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("", &digest, .{});
        return digest;
    }

    fn emptyTranscriptHashSha384() [48]u8 {
        var digest: [48]u8 = undefined;
        std.crypto.hash.sha2.Sha384.hash("", &digest, .{});
        return digest;
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
        self.early_data_admitted = false;
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

    fn zeroizeStagedSecrets(self: *Engine) void {
        self.zeroizeSecretSlot(&self.early_secret);
        self.zeroizeSecretSlot(&self.handshake_read_secret);
        self.zeroizeSecretSlot(&self.handshake_write_secret);
        self.zeroizeSecretSlot(&self.master_secret);
    }

    fn zeroizeKeyExchangeSecret(self: *Engine) void {
        if (self.key_exchange_secret) |*secret| {
            std.crypto.secureZero(u8, secret[0..]);
            self.key_exchange_secret = null;
        }
    }

    fn zeroizeClientEphemeralState(self: *Engine) void {
        if (self.client_x25519_secret_key) |*secret| {
            std.crypto.secureZero(u8, secret[0..]);
            self.client_x25519_secret_key = null;
        }
    }

    fn clearPeerLeafCertificate(self: *Engine) void {
        if (self.peer_leaf_certificate_der) |der| {
            std.crypto.secureZero(u8, der);
            self.allocator.free(der);
            self.peer_leaf_certificate_der = null;
        }
        self.saw_peer_certificate = false;
    }

    fn nowUnix(self: Engine) i64 {
        if (self.config.peer_validation.now_unix) |f| return f();
        return std.time.timestamp();
    }

    fn zeroizeSecretSlot(self: *Engine, slot: *?TrafficSecret) void {
        _ = self;
        if (slot.*) |*secret| {
            switch (secret.*) {
                .sha256 => |*s| std.crypto.secureZero(u8, s[0..]),
                .sha384 => |*s| std.crypto.secureZero(u8, s[0..]),
            }
            slot.* = null;
        }
    }

    fn capturePeerLeafCertificate(self: *Engine, cert: messages.CertificateMsg) EngineError!void {
        if (cert.entries.len == 0) return error.InvalidCertificateMessage;
        self.clearPeerLeafCertificate();
        self.peer_leaf_certificate_der = try self.allocator.dupe(u8, cert.entries[0].cert_data);
        self.saw_peer_certificate = true;
    }

    fn validatePeerCertificatePolicy(self: *Engine, cert_msg: messages.CertificateMsg) EngineError!void {
        const has_name_policy = self.config.role == .client and self.config.peer_validation.expected_server_name != null;
        const has_trust_policy = self.config.peer_validation.trust_store != null;
        const has_ocsp_policy = self.config.peer_validation.enforce_ocsp;
        if (!has_name_policy and !has_trust_policy and !has_ocsp_policy) return;

        if (cert_msg.entries.len == 0) return error.MissingPeerCertificate;
        if (cert_msg.entries.len > max_peer_chain_depth) return error.PeerCertificateValidationFailed;

        var parsed_chain: [max_peer_chain_depth]std.crypto.Certificate.Parsed = undefined;
        var cert_chain: [max_peer_chain_depth]std.crypto.Certificate = undefined;
        for (cert_msg.entries, 0..) |entry, i| {
            if (!isLikelyDerSequence(entry.cert_data)) return error.PeerCertificateValidationFailed;
            cert_chain[i] = .{ .buffer = entry.cert_data, .index = 0 };
            parsed_chain[i] = cert_chain[i].parse() catch return error.PeerCertificateValidationFailed;
        }

        const now = self.nowUnix();
        if (cert_msg.entries.len > 1) {
            var idx: usize = 0;
            while (idx + 1 < cert_msg.entries.len) : (idx += 1) {
                parsed_chain[idx].verify(parsed_chain[idx + 1], now) catch return error.PeerCertificateValidationFailed;
            }
        }

        if (self.config.peer_validation.expected_server_name) |expected_server_name| {
            parsed_chain[0].verifyHostName(expected_server_name) catch return error.PeerCertificateValidationFailed;
        }
        if (self.config.peer_validation.trust_store) |store| {
            var trusted = false;
            var rev_index = cert_msg.entries.len;
            while (rev_index > 0) : (rev_index -= 1) {
                const parsed = parsed_chain[rev_index - 1];
                store.verifyParsed(parsed, now) catch continue;
                trusted = true;
                break;
            }
            if (!trusted) return error.PeerCertificateValidationFailed;
        }
        if (self.config.peer_validation.enforce_ocsp) {
            _ = certificate_validation.validateStapledOcsp(
                self.config.peer_validation.stapled_ocsp,
                now,
                .{
                    .allow_soft_fail_ocsp = self.config.peer_validation.allow_soft_fail_ocsp,
                },
            ) catch return error.PeerCertificateValidationFailed;
        }
    }

    fn peerCertificateIsRequired(self: Engine) bool {
        if (self.config.peer_validation.require_peer_certificate) return true;
        if (self.config.peer_validation.trust_store != null) return true;
        if (self.config.peer_validation.enforce_ocsp) return true;
        return false;
    }

    fn verifyPeerCertificateVerify(self: *Engine, algorithm: u16, signature: []const u8) EngineError!void {
        const leaf_der = self.peer_leaf_certificate_der orelse return error.MissingPeerCertificate;
        if (!isLikelyDerSequence(leaf_der)) return error.InvalidCertificateVerifyMessage;
        const cert: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
        const parsed = cert.parse() catch return error.InvalidCertificateVerifyMessage;
        const payload = try self.buildCertificateVerifyPayload(.peer);
        defer self.allocator.free(payload);

        switch (algorithm) {
            0x0403, 0x0503 => try self.verifyEcdsaCertificateVerify(parsed, payload, signature, algorithm),
            0x0804, 0x0805, 0x0806 => try self.verifyRsaPssCertificateVerify(parsed, payload, signature, algorithm),
            0x0807 => try self.verifyEd25519CertificateVerify(parsed, payload, signature),
            else => return error.UnsupportedSignatureAlgorithm,
        }
    }

    const CertificateVerifyPerspective = enum {
        local,
        peer,
    };

    fn buildCertificateVerifyPayload(self: *Engine, perspective: CertificateVerifyPerspective) EngineError![]u8 {
        const local_context = switch (self.config.role) {
            .client => "TLS 1.3, client CertificateVerify",
            .server => "TLS 1.3, server CertificateVerify",
        };
        const peer_context = switch (self.config.role) {
            .client => "TLS 1.3, server CertificateVerify",
            .server => "TLS 1.3, client CertificateVerify",
        };
        const context = switch (perspective) {
            .local => local_context,
            .peer => peer_context,
        };

        var digest_256: [32]u8 = undefined;
        var digest_384: [48]u8 = undefined;
        const digest = switch (self.config.suite) {
            .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => blk: {
                digest_256 = self.transcriptDigestSha256();
                break :blk digest_256[0..];
            },
            .tls_aes_256_gcm_sha384 => blk: {
                digest_384 = self.transcriptDigestSha384();
                break :blk digest_384[0..];
            },
        };

        const out_len = 64 + context.len + 1 + digest.len;
        var out = try self.allocator.alloc(u8, out_len);
        @memset(out[0..64], 0x20);
        @memcpy(out[64 .. 64 + context.len], context);
        out[64 + context.len] = 0x00;
        @memcpy(out[65 + context.len ..], digest);
        return out;
    }

    fn verifyEd25519CertificateVerify(
        self: *Engine,
        parsed: std.crypto.Certificate.Parsed,
        payload: []const u8,
        signature: []const u8,
    ) EngineError!void {
        _ = self;
        const Ed25519 = std.crypto.sign.Ed25519;
        if (parsed.pub_key_algo != .curveEd25519) return error.UnsupportedSignatureAlgorithm;
        if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidCertificateVerifyMessage;
        const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
        const peer_pub = parsed.pubKey();
        if (peer_pub.len != Ed25519.PublicKey.encoded_length) return error.InvalidCertificateVerifyMessage;
        const pub_key = Ed25519.PublicKey.fromBytes(peer_pub[0..Ed25519.PublicKey.encoded_length].*) catch {
            return error.InvalidCertificateVerifyMessage;
        };
        sig.verify(payload, pub_key) catch return error.InvalidCertificateVerifyMessage;
    }

    fn verifyEcdsaCertificateVerify(
        self: *Engine,
        parsed: std.crypto.Certificate.Parsed,
        payload: []const u8,
        signature: []const u8,
        algorithm: u16,
    ) EngineError!void {
        _ = self;
        const curve = switch (parsed.pub_key_algo) {
            .X9_62_id_ecPublicKey => |c| c,
            else => return error.UnsupportedSignatureAlgorithm,
        };
        const pub_key_bytes = parsed.pubKey();

        switch (algorithm) {
            0x0403 => {
                if (curve != .X9_62_prime256v1) return error.UnsupportedSignatureAlgorithm;
                const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256);
                const sig = Ecdsa.Signature.fromDer(signature) catch return error.InvalidCertificateVerifyMessage;
                const pub_key = Ecdsa.PublicKey.fromSec1(pub_key_bytes) catch return error.InvalidCertificateVerifyMessage;
                var verifier = sig.verifier(pub_key) catch return error.InvalidCertificateVerifyMessage;
                verifier.update(payload);
                verifier.verify() catch return error.InvalidCertificateVerifyMessage;
            },
            0x0503 => {
                if (curve != .secp384r1) return error.UnsupportedSignatureAlgorithm;
                const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384);
                const sig = Ecdsa.Signature.fromDer(signature) catch return error.InvalidCertificateVerifyMessage;
                const pub_key = Ecdsa.PublicKey.fromSec1(pub_key_bytes) catch return error.InvalidCertificateVerifyMessage;
                var verifier = sig.verifier(pub_key) catch return error.InvalidCertificateVerifyMessage;
                verifier.update(payload);
                verifier.verify() catch return error.InvalidCertificateVerifyMessage;
            },
            else => return error.UnsupportedSignatureAlgorithm,
        }
    }

    fn verifyRsaPssCertificateVerify(
        self: *Engine,
        parsed: std.crypto.Certificate.Parsed,
        payload: []const u8,
        signature: []const u8,
        algorithm: u16,
    ) EngineError!void {
        _ = self;
        switch (parsed.pub_key_algo) {
            .rsaEncryption, .rsassa_pss => {},
            else => return error.UnsupportedSignatureAlgorithm,
        }

        const Rsa = std.crypto.Certificate.rsa;
        const components = Rsa.PublicKey.parseDer(parsed.pubKey()) catch return error.InvalidCertificateVerifyMessage;
        const key = Rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch return error.InvalidCertificateVerifyMessage;

        switch (components.modulus.len) {
            inline 128, 256, 384, 512 => |modulus_len| {
                if (signature.len != modulus_len) return error.InvalidCertificateVerifyMessage;
                const sig = Rsa.PSSSignature.fromBytes(modulus_len, signature);
                switch (algorithm) {
                    0x0804 => Rsa.PSSSignature.concatVerify(modulus_len, sig, &.{payload}, key, std.crypto.hash.sha2.Sha256) catch return error.InvalidCertificateVerifyMessage,
                    0x0805 => Rsa.PSSSignature.concatVerify(modulus_len, sig, &.{payload}, key, std.crypto.hash.sha2.Sha384) catch return error.InvalidCertificateVerifyMessage,
                    0x0806 => Rsa.PSSSignature.concatVerify(modulus_len, sig, &.{payload}, key, std.crypto.hash.sha2.Sha512) catch return error.InvalidCertificateVerifyMessage,
                    else => return error.UnsupportedSignatureAlgorithm,
                }
            },
            else => return error.InvalidCertificateVerifyMessage,
        }
    }

    fn isLikelyDerSequence(der: []const u8) bool {
        if (der.len < 2) return false;
        if (der[0] != 0x30) return false;
        const len_octet = der[1];
        if ((len_octet & 0x80) == 0) {
            return der.len == 2 + @as(usize, len_octet);
        }
        const len_len = len_octet & 0x7f;
        if (len_len == 0 or len_len > 4) return false;
        const len_len_usize = @as(usize, len_len);
        if (der.len < 2 + len_len_usize) return false;
        var declared_len: usize = 0;
        var i: usize = 0;
        while (i < len_len_usize) : (i += 1) {
            declared_len = (declared_len << 8) | der[2 + i];
        }
        return der.len == 2 + len_len_usize + declared_len;
    }

    fn validateHandshakeBody(self: *Engine, handshake_type: state.HandshakeType, body: []const u8) EngineError!void {
        switch (handshake_type) {
            .server_hello => {
                // Validate Body
                var sh = messages.ServerHello.decode(self.allocator, body) catch return error.InvalidHelloMessage;
                defer sh.deinit(self.allocator);

                // Detect Downgrade
                if (self.config.role == .client and hasDowngradeMarker(sh.random)) {
                    return error.DowngradeDetected;
                }

                if (self.config.role == .client) {
                    if (sh.compression_method != 0x00) return error.InvalidCompressionMethod;

                    // Validate CipherSuite (Extension Structure)
                    if (sh.cipher_suite != configuredCipherSuiteCodepoint(self.config.suite)) {
                        return error.ConfiguredCipherSuiteMismatch;
                    }

                    if (messages.serverHelloHasHrrRandom(body)) {
                        try self.requireHrrExtensions(sh.extensions);
                    } else {
                        try self.requireServerHelloExtensions(sh.extensions);
                        try self.bindClientKeyExchangeSecret(sh.extensions);
                    }
                }
            },
            .client_hello => {
                var ch = messages.ClientHello.decode(self.allocator, body) catch return error.InvalidHelloMessage;
                defer ch.deinit(self.allocator);

                if (self.config.role == .server) {
                    // Validate all the mandatory extension (SNI, key_share, supported_versions...etc)
                    if (!containsCipherSuite(ch.cipher_suites, configuredCipherSuiteCodepoint(self.config.suite))) {
                        return error.ConfiguredCipherSuiteMismatch;
                    }

                    try self.requireClientHelloExtensions(ch.compression_methods, ch.extensions);
                }
            },
            .certificate => {
                var cert = messages.CertificateMsg.decode(self.allocator, body) catch return error.InvalidCertificateMessage;
                defer cert.deinit(self.allocator);

                try self.capturePeerLeafCertificate(cert);

                // Validate validation pollicy
                try self.validatePeerCertificatePolicy(cert);
            },
            .certificate_verify => {
                var cert_verify = messages.CertificateVerifyMsg.decode(self.allocator, body) catch return error.InvalidCertificateVerifyMessage;
                defer cert_verify.deinit(self.allocator);

                if (!self.isAllowedSignatureAlgorithm(cert_verify.algorithm)) {
                    return error.UnsupportedSignatureAlgorithm;
                }

                if (self.config.peer_validation.enforce_certificate_verify) {
                    try self.verifyPeerCertificateVerify(cert_verify.algorithm, cert_verify.signature);
                }
            },
            .finished => {
                // Validate Finished MAC length + HMAC validation
                if (body.len != keyschedule.digestLen(self.config.suite)) {
                    return error.InvalidFinishedMessage;
                }

                if (self.config.role == .server and self.peerCertificateIsRequired() and !self.saw_peer_certificate) {
                    return error.MissingPeerCertificate;
                }

                if (self.config.role == .server and self.config.server_credentials != null and self.handshake_read_secret != null) {
                    const hs_secret = self.handshake_read_secret.?;
                    const ok = switch (self.config.suite) {
                        .tls_aes_128_gcm_sha256 => switch (hs_secret) {
                            .sha256 => |secret| blk: {
                                const transcript_hash = self.transcriptDigestSha256();
                                const fin_key = keyschedule.finishedKey(.tls_aes_128_gcm_sha256, secret);
                                break :blk keyschedule.verifyFinished(.tls_aes_128_gcm_sha256, fin_key, &transcript_hash, body);
                            },
                            .sha384 => false,
                        },
                        .tls_chacha20_poly1305_sha256 => switch (hs_secret) {
                            .sha256 => |secret| blk: {
                                const transcript_hash = self.transcriptDigestSha256();
                                const fin_key = keyschedule.finishedKey(.tls_chacha20_poly1305_sha256, secret);
                                break :blk keyschedule.verifyFinished(.tls_chacha20_poly1305_sha256, fin_key, &transcript_hash, body);
                            },
                            .sha384 => false,
                        },
                        .tls_aes_256_gcm_sha384 => switch (hs_secret) {
                            .sha256 => false,
                            .sha384 => |secret| blk: {
                                const transcript_hash = self.transcriptDigestSha384();
                                const fin_key = keyschedule.finishedKey(.tls_aes_256_gcm_sha384, secret);
                                break :blk keyschedule.verifyFinished(.tls_aes_256_gcm_sha384, fin_key, &transcript_hash, body);
                            },
                        },
                    };

                    if (!ok) return error.InvalidFinishedMessage;
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
        const server_name = findExtensionData(extensions, ext_server_name) orelse return error.MissingRequiredClientHelloExtension;
        try validateClientHelloServerNameExtension(server_name);
        const supported_groups = findExtensionData(extensions, ext_supported_groups) orelse return error.MissingRequiredClientHelloExtension;
        try validateClientHelloSupportedGroupsExtension(supported_groups, self.config.group_policy);
        const key_share = findExtensionData(extensions, ext_key_share) orelse return error.MissingRequiredClientHelloExtension;
        try validateClientHelloKeyShareExtension(key_share);
        try validateClientHelloKeyShareGroupsSubset(key_share, supported_groups, self.config.group_policy);
        if (findExtensionData(extensions, ext_alpn)) |alpn| {
            try validateClientHelloAlpnExtension(alpn);
        }
        if (!isStrictTls13LegacyCompressionVector(compression_methods)) return error.InvalidCompressionMethod;
        try validatePskOfferExtensions(extensions, self.config.suite);
    }

    fn requireServerHelloExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        try requireAllowedExtensions(extensions, &.{ ext_supported_versions, ext_key_share, ext_pre_shared_key }, error.UnexpectedServerHelloExtension);
        const supported_versions = findExtensionData(extensions, ext_supported_versions) orelse return error.MissingRequiredServerHelloExtension;
        if (!serverHelloSupportedVersionIsTls13(supported_versions)) return error.InvalidSupportedVersionExtension;
        const key_share = findExtensionData(extensions, ext_key_share) orelse return error.MissingRequiredServerHelloExtension;
        try validateServerHelloKeyShareExtension(key_share, self.config.group_policy);
        if (findExtensionData(extensions, ext_pre_shared_key)) |pre_shared_key| {
            try validateServerHelloPreSharedKeyExtension(pre_shared_key);
        }
    }

    fn bindClientKeyExchangeSecret(self: *Engine, extensions: []const messages.Extension) EngineError!void {
        if (self.config.role != .client) return;
        const key_share = findExtensionData(extensions, ext_key_share) orelse return error.MissingRequiredServerHelloExtension;
        if (key_share.len != 36) return error.InvalidKeyShareExtension;
        const group = @as(u16, @intCast(readU16(key_share[0..2])));
        if (group != named_group_x25519) return error.InvalidKeyShareExtension;
        const key_len = readU16(key_share[2..4]);
        if (key_len != 32) return error.InvalidKeyShareExtension;
        const client_secret = self.client_x25519_secret_key orelse return error.MissingKeyExchangeSecret;

        var server_pub: [32]u8 = undefined;
        @memcpy(&server_pub, key_share[4..36]);
        const shared = std.crypto.dh.X25519.scalarmult(client_secret, server_pub) catch return error.InvalidKeyShareExtension;
        self.key_exchange_secret = shared;
        self.zeroizeClientEphemeralState();
    }

    fn requireHrrExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        try requireAllowedExtensions(extensions, &.{ ext_supported_versions, ext_key_share, ext_cookie }, error.UnexpectedHrrExtension);
        const supported_versions = findExtensionData(extensions, ext_supported_versions) orelse return error.MissingRequiredHrrExtension;
        if (!serverHelloSupportedVersionIsTls13(supported_versions)) return error.InvalidSupportedVersionExtension;
        const key_share = findExtensionData(extensions, ext_key_share) orelse return error.MissingRequiredHrrExtension;
        try validateHrrKeyShareExtension(key_share, self.config.group_policy);
        if (findExtensionData(extensions, ext_cookie)) |cookie| {
            try validateHrrCookieExtension(cookie);
        }
    }
};

fn buildTls13Nonce(base_iv: [12]u8, seq: u64) [12]u8 {
    var nonce = base_iv;
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, seq, .big);
    var i: usize = 0;
    while (i < seq_bytes.len) : (i += 1) {
        nonce[nonce.len - seq_bytes.len + i] ^= seq_bytes[i];
    }
    return nonce;
}

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
        error.InvalidServerNameExtension,
        error.InvalidAlpnExtension,
        error.InvalidSupportedGroupsExtension,
        error.InvalidKeyShareExtension,
        error.InvalidCookieExtension,
        error.InvalidPreSharedKeyExtension,
        error.UnexpectedServerHelloExtension,
        error.UnexpectedHrrExtension,
        error.InvalidCompressionMethod,
        error.MissingPskKeyExchangeModes,
        error.InvalidPskKeyExchangeModes,
        error.MissingPskDheKeyExchangeMode,
        error.InvalidPreSharedKeyPlacement,
        error.InvalidPskBinder,
        error.InvalidPskBinderLength,
        error.PskBinderCountMismatch,
        error.UnsupportedSignatureAlgorithm,
        error.InvalidInnerContentType,
        error.InvalidRequest,
        => .illegal_parameter,

        error.EarlyDataRejected,
        error.MissingReplayFilter,
        error.EarlyDataTicketExpired,
        error.EarlyDataTicketTooLarge,
        error.MissingServerCredentials,
        error.MissingKeyExchangeSecret,
        => .handshake_failure,

        error.MissingPeerCertificate => .certificate_required,
        error.PeerCertificateValidationFailed => .bad_certificate,

        error.DecryptFailed,
        => .decrypt_error,

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
    comptime allowed: []const u16,
    comptime unexpected_err: anytype,
) EngineError!void {
    for (extensions) |ext| {
        if (!containsU16Comptime(allowed, ext.extension_type)) return unexpected_err;
    }
}

fn containsU16Comptime(comptime values: []const u16, wanted: u16) bool {
    inline for (values) |value| {
        if (value == wanted) return true;
    }
    return false;
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

test "validateConfig rejects early-data without replay filter" {
    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{ .enabled = true },
    }));
}

test "validateConfig rejects debug keylog without callback" {
    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .enable_debug_keylog = true,
    }));
}

test "validateConfig rejects server credential signature scheme outside allowed policy" {
    try std.testing.expectError(error.InvalidConfiguration, validateConfig(.{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .allowed_signature_algorithms = &.{0x0807},
        .server_credentials = .{
            .cert_chain_der = &test_server_cert_chain,
            .signature_scheme = 0x0804,
            .sign_certificate_verify = testSignCertificateVerify,
        },
    }));
}

test "initChecked returns explicit invalid configuration error" {
    try std.testing.expectError(error.InvalidConfiguration, Engine.initChecked(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{ .enabled = true },
    }));
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

test "zeroize staged secrets clears stage slots" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const secret = [_]u8{0xaa} ** 32;
    engine.early_secret = .{ .sha256 = secret };
    engine.handshake_read_secret = .{ .sha256 = secret };
    engine.handshake_write_secret = .{ .sha256 = secret };
    engine.master_secret = .{ .sha256 = secret };
    engine.zeroizeStagedSecrets();

    try std.testing.expect(engine.early_secret == null);
    try std.testing.expect(engine.handshake_read_secret == null);
    try std.testing.expect(engine.handshake_write_secret == null);
    try std.testing.expect(engine.master_secret == null);
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

    try ingestValidServerHelloForClient(&engine);
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

    try ingestValidServerHelloForClient(&engine);
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
        .server_credentials = testServerCredentials(),
        .enable_debug_keylog = true,
        .keylog_callback = Hooks.onKeyLog,
        .keylog_userdata = @intFromPtr(&tracker),
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    _ = try engine.ingestRecord(fin);

    if (builtin.mode == .Debug) {
        try std.testing.expect(tracker.called);
        try std.testing.expect(tracker.label_ok);
    } else {
        try std.testing.expect(!tracker.called);
    }
}

fn validatePskOfferExtensions(extensions: []const messages.Extension, suite: keyschedule.CipherSuite) EngineError!void {
    const psk_index = indexOfExtension(extensions, ext_pre_shared_key) orelse return;
    if (psk_index + 1 != extensions.len) return error.InvalidPreSharedKeyPlacement;
    const psk = extensions[psk_index].data;
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

fn indexOfExtension(extensions: []const messages.Extension, extension_type: u16) ?usize {
    for (extensions, 0..) |ext, i| {
        if (ext.extension_type == extension_type) return i;
    }
    return null;
}

fn isIgnorableTls13ChangeCipherSpec(payload: []const u8) bool {
    return payload.len == 1 and payload[0] == 0x01;
}

fn extractClientHelloX25519Public(extensions: []const messages.Extension) ![32]u8 {
    const key_share = findExtensionData(extensions, ext_key_share) orelse return error.MissingRequiredClientHelloExtension;
    if (key_share.len < 2) return error.InvalidKeyShareExtension;
    const vec_len = readU16(key_share[0..2]);
    if (vec_len + 2 != key_share.len) return error.InvalidKeyShareExtension;

    var i: usize = 2;
    const end = key_share.len;
    while (i < end) {
        if (i + 4 > end) return error.InvalidKeyShareExtension;
        const group = @as(u16, @intCast(readU16(key_share[i .. i + 2])));
        const key_len = readU16(key_share[i + 2 .. i + 4]);
        i += 4;
        if (i + key_len > end) return error.InvalidKeyShareExtension;
        if (group == named_group_x25519) {
            if (key_len != 32) return error.InvalidKeyShareExtension;
            var out: [32]u8 = undefined;
            @memcpy(&out, key_share[i .. i + key_len]);
            return out;
        }
        i += key_len;
    }
    return error.InvalidKeyShareExtension;
}

fn validateClientHelloServerNameExtension(data: []const u8) EngineError!void {
    if (data.len < 5) return error.InvalidServerNameExtension;
    const list_len = readU16(data[0..2]);
    if (list_len == 0) return error.InvalidServerNameExtension;
    if (list_len + 2 != data.len) return error.InvalidServerNameExtension;
    if (data[2] != 0x00) return error.InvalidServerNameExtension; // host_name

    const host_len = readU16(data[3..5]);
    if (host_len == 0) return error.InvalidServerNameExtension;
    if (5 + host_len != data.len) return error.InvalidServerNameExtension;
}

fn validateClientHelloAlpnExtension(data: []const u8) EngineError!void {
    if (data.len < 3) return error.InvalidAlpnExtension;
    const list_len = readU16(data[0..2]);
    if (list_len == 0) return error.InvalidAlpnExtension;
    if (list_len + 2 != data.len) return error.InvalidAlpnExtension;

    var i: usize = 2;
    const end = data.len;
    while (i < end) {
        if (i + 1 > end) return error.InvalidAlpnExtension;
        const name_len = data[i];
        i += 1;
        if (name_len == 0) return error.InvalidAlpnExtension;
        if (i + name_len > end) return error.InvalidAlpnExtension;
        i += name_len;
    }
    if (i != end) return error.InvalidAlpnExtension;
}

fn firstClientHelloAlpnProtocol(data: []const u8) EngineError![]const u8 {
    try validateClientHelloAlpnExtension(data);
    const first_len = data[2];
    if (first_len == 0) return error.InvalidAlpnExtension;
    if (3 + first_len > data.len) return error.InvalidAlpnExtension;
    return data[3 .. 3 + first_len];
}

fn validateClientHelloSupportedGroupsExtension(data: []const u8, policy: GroupPolicy) EngineError!void {
    _ = policy;
    if (data.len < 2) return error.InvalidSupportedGroupsExtension;
    const list_len = readU16(data[0..2]);
    if (list_len == 0) return error.InvalidSupportedGroupsExtension;
    if (list_len % 2 != 0) return error.InvalidSupportedGroupsExtension;
    if (list_len + 2 != data.len) return error.InvalidSupportedGroupsExtension;
}

fn validateClientHelloKeyShareExtension(data: []const u8) EngineError!void {
    if (data.len < 2) return error.InvalidKeyShareExtension;
    const vec_len = readU16(data[0..2]);
    if (vec_len == 0) return error.InvalidKeyShareExtension;
    if (vec_len + 2 != data.len) return error.InvalidKeyShareExtension;

    var i: usize = 2;
    const end = data.len;
    while (i < end) {
        if (i + 4 > end) return error.InvalidKeyShareExtension;
        const key_len = readU16(data[i + 2 .. i + 4]);
        if (key_len == 0) return error.InvalidKeyShareExtension;
        i += 4;
        if (i + key_len > end) return error.InvalidKeyShareExtension;
        i += key_len;
    }
    if (i != end) return error.InvalidKeyShareExtension;
}

fn validateServerHelloKeyShareExtension(data: []const u8, policy: GroupPolicy) EngineError!void {
    if (data.len < 4) return error.InvalidKeyShareExtension;
    const group = @as(u16, @intCast(readU16(data[0..2])));
    if (group == 0) return error.InvalidKeyShareExtension;
    if (!groupAllowedByPolicy(policy, group)) return error.InvalidKeyShareExtension;
    const key_len = readU16(data[2..4]);
    if (key_len + 4 != data.len) return error.InvalidKeyShareExtension;
}

fn validateServerHelloPreSharedKeyExtension(data: []const u8) EngineError!void {
    if (data.len != 2) return error.InvalidPreSharedKeyExtension;
}

fn validateHrrKeyShareExtension(data: []const u8, policy: GroupPolicy) EngineError!void {
    if (data.len != 2) return error.InvalidKeyShareExtension;
    const selected_group = @as(u16, @intCast(readU16(data[0..2])));
    if (selected_group == 0) return error.InvalidKeyShareExtension;
    if (!groupAllowedByPolicy(policy, selected_group)) return error.InvalidKeyShareExtension;
}

fn validateHrrCookieExtension(data: []const u8) EngineError!void {
    if (data.len < 3) return error.InvalidCookieExtension;
    const cookie_len = readU16(data[0..2]);
    if (cookie_len == 0) return error.InvalidCookieExtension;
    if (cookie_len + 2 != data.len) return error.InvalidCookieExtension;
}

fn validateClientHelloKeyShareGroupsSubset(
    key_share_data: []const u8,
    supported_groups_data: []const u8,
    policy: GroupPolicy,
) EngineError!void {
    _ = policy;
    var i: usize = 2;
    const end = key_share_data.len;
    while (i < end) {
        const group = @as(u16, @intCast(readU16(key_share_data[i .. i + 2])));
        if (!supportedGroupsContain(supported_groups_data, group)) return error.InvalidKeyShareExtension;
        const key_len = readU16(key_share_data[i + 2 .. i + 4]);
        i += 4 + key_len;
    }
}

fn groupAllowedByPolicy(policy: GroupPolicy, group: u16) bool {
    if (!containsNamedGroup(policy.allowed_named_groups, group)) return false;
    if (containsNamedGroup(policy.hybrid_named_groups, group) and !policy.allow_hybrid_kex) return false;
    return true;
}

fn containsNamedGroup(groups: []const u16, wanted: u16) bool {
    for (groups) |group| {
        if (group == wanted) return true;
    }
    return false;
}

fn supportedGroupsContain(data: []const u8, wanted: u16) bool {
    var i: usize = 2;
    while (i < data.len) : (i += 2) {
        if (@as(u16, @intCast(readU16(data[i .. i + 2]))) == wanted) return true;
    }
    return false;
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

fn serverHelloRecordWithX25519Public(allocator: std.mem.Allocator, suite: u16, public: [32]u8) ![]u8 {
    var exts = try allocator.alloc(messages.Extension, 2);
    errdefer allocator.free(exts);

    const versions = try allocator.dupe(u8, &.{ 0x03, 0x04 });
    var key_share = try allocator.alloc(u8, 2 + 2 + public.len);
    std.mem.writeInt(u16, key_share[0..2], named_group_x25519, .big);
    std.mem.writeInt(u16, key_share[2..4], @as(u16, @intCast(public.len)), .big);
    @memcpy(key_share[4..], &public);

    exts[0] = .{ .extension_type = ext_supported_versions, .data = versions };
    exts[1] = .{ .extension_type = ext_key_share, .data = key_share };

    var hello = messages.ServerHello{
        .random = [_]u8{0x11} ** 32,
        .session_id_echo = try allocator.dupe(u8, ""),
        .cipher_suite = suite,
        .compression_method = 0x00,
        .extensions = exts,
    };
    defer hello.deinit(allocator);

    const body = try hello.encode(allocator);
    defer allocator.free(body);

    var out = try allocator.alloc(u8, 5 + 4 + body.len);
    out[0] = @intFromEnum(record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(4 + body.len)), .big);
    out[5] = @intFromEnum(state.HandshakeType.server_hello);
    const hs_len = handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &hs_len);
    @memcpy(out[9..], body);
    return out;
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

fn clientHelloRecordWithX25519Public(allocator: std.mem.Allocator, public: [32]u8) ![]u8 {
    var exts = try allocator.alloc(messages.Extension, 5);
    errdefer allocator.free(exts);

    const sni = try allocator.dupe(u8, &.{
        0x00, 0x08, 0x00, 0x00, 0x05, 'a', '.', 'c', 'o', 'm',
    });
    const versions = try allocator.dupe(u8, &.{ 0x02, 0x03, 0x04 });
    const groups = try allocator.dupe(u8, &.{ 0x00, 0x02, 0x00, 0x1d });
    var key_share = try allocator.alloc(u8, 2 + 2 + 2 + public.len);
    std.mem.writeInt(u16, key_share[0..2], @as(u16, @intCast(2 + 2 + public.len)), .big);
    std.mem.writeInt(u16, key_share[2..4], named_group_x25519, .big);
    std.mem.writeInt(u16, key_share[4..6], @as(u16, @intCast(public.len)), .big);
    @memcpy(key_share[6..], &public);
    const alpn = try allocator.dupe(u8, &.{ 0x00, 0x03, 0x02, 'h', '2' });

    exts[0] = .{ .extension_type = ext_server_name, .data = sni };
    exts[1] = .{ .extension_type = ext_supported_versions, .data = versions };
    exts[2] = .{ .extension_type = ext_supported_groups, .data = groups };
    exts[3] = .{ .extension_type = ext_key_share, .data = key_share };
    exts[4] = .{ .extension_type = ext_alpn, .data = alpn };

    var hello = messages.ClientHello{
        .random = [_]u8{0x22} ** 32,
        .session_id = try allocator.dupe(u8, ""),
        .cipher_suites = try allocator.dupe(u16, &.{0x1301}),
        .compression_methods = try allocator.dupe(u8, &.{0x00}),
        .extensions = exts,
    };
    defer hello.deinit(allocator);

    const body = try hello.encode(allocator);
    defer allocator.free(body);

    var out = try allocator.alloc(u8, 5 + 4 + body.len);
    out[0] = @intFromEnum(record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(4 + body.len)), .big);
    out[5] = @intFromEnum(state.HandshakeType.client_hello);
    const hs_len = handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &hs_len);
    @memcpy(out[9..], body);
    return out;
}

fn finishedRecordFromBody(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, 5 + 4 + body.len);
    out[0] = @intFromEnum(record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(4 + body.len)), .big);
    out[5] = @intFromEnum(state.HandshakeType.finished);
    const hs_len = handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &hs_len);
    @memcpy(out[9..], body);
    return out;
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

fn serverHelloRecordWithInvalidKeySharePayload() [63]u8 {
    var frame = serverHelloRecord();
    frame[59] = 0x00;
    frame[60] = 0x00; // group=0 (invalid)
    return frame;
}

fn serverHelloRecordWithHybridKeyShare() [63]u8 {
    var frame = serverHelloRecord();
    frame[59] = @as(u8, @intCast((named_group_x25519_mlkem768 >> 8) & 0xff));
    frame[60] = @as(u8, @intCast(named_group_x25519_mlkem768 & 0xff));
    return frame;
}

fn serverHelloRecordWithInvalidPreSharedKeyPayload() [68]u8 {
    var frame: [68]u8 = undefined;
    const base = serverHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 63, .big);
    const hs_len = handshake.writeU24(59);
    @memcpy(frame[6..9], &hs_len);
    frame[47] = 0x00;
    frame[48] = 0x13; // extension bytes: 14 + pre_shared_key(5)
    // pre_shared_key: type=0x0029 len=1 selected_identity(one-byte, invalid)
    frame[63] = 0x00;
    frame[64] = 0x29;
    frame[65] = 0x00;
    frame[66] = 0x01;
    frame[67] = 0x00;
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

fn clientHelloRecordWithoutAlpn(allocator: std.mem.Allocator, public: [32]u8) ![]u8 {
    var exts = try allocator.alloc(messages.Extension, 4);
    errdefer allocator.free(exts);

    const sni = try allocator.dupe(u8, &.{
        0x00, 0x08, 0x00, 0x00, 0x05, 'a', '.', 'c', 'o', 'm',
    });
    const versions = try allocator.dupe(u8, &.{ 0x02, 0x03, 0x04 });
    const groups = try allocator.dupe(u8, &.{ 0x00, 0x02, 0x00, 0x1d });
    var key_share = try allocator.alloc(u8, 2 + 2 + 2 + public.len);
    std.mem.writeInt(u16, key_share[0..2], @as(u16, @intCast(2 + 2 + public.len)), .big);
    std.mem.writeInt(u16, key_share[2..4], named_group_x25519, .big);
    std.mem.writeInt(u16, key_share[4..6], @as(u16, @intCast(public.len)), .big);
    @memcpy(key_share[6..], &public);

    exts[0] = .{ .extension_type = ext_server_name, .data = sni };
    exts[1] = .{ .extension_type = ext_supported_versions, .data = versions };
    exts[2] = .{ .extension_type = ext_supported_groups, .data = groups };
    exts[3] = .{ .extension_type = ext_key_share, .data = key_share };

    var hello = messages.ClientHello{
        .random = [_]u8{0x22} ** 32,
        .session_id = try allocator.dupe(u8, ""),
        .cipher_suites = try allocator.dupe(u16, &.{0x1301}),
        .compression_methods = try allocator.dupe(u8, &.{0x00}),
        .extensions = exts,
    };
    defer hello.deinit(allocator);

    const body = try hello.encode(allocator);
    defer allocator.free(body);

    var out = try allocator.alloc(u8, 5 + 4 + body.len);
    out[0] = @intFromEnum(record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(4 + body.len)), .big);
    out[5] = @intFromEnum(state.HandshakeType.client_hello);
    const hs_len = handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &hs_len);
    @memcpy(out[9..], body);
    return out;
}

fn clientHelloRecordWithInvalidAlpnPayload() [101]u8 {
    var frame = clientHelloRecord();
    frame[98] = 0x00; // protocol name length (invalid empty ALPN id)
    return frame;
}

fn clientHelloRecordWithInvalidSupportedGroupsPayload() [101]u8 {
    var frame = clientHelloRecord();
    frame[78] = 0x01; // groups list len low byte (odd length)
    return frame;
}

fn clientHelloRecordWithInvalidKeySharePayload() [101]u8 {
    var frame = clientHelloRecord();
    frame[90] = 0x00; // key_exchange_len low byte (invalid zero length)
    return frame;
}

fn clientHelloRecordWithKeyShareGroupOutsideSupportedGroups() [101]u8 {
    var frame = clientHelloRecord();
    frame[88] = 0x17; // key_share group low byte = secp256r1 (supported_groups only has x25519)
    return frame;
}

fn clientHelloRecordWithHybridGroup() [101]u8 {
    var frame = clientHelloRecord();
    frame[79] = @as(u8, @intCast((named_group_x25519_mlkem768 >> 8) & 0xff));
    frame[80] = @as(u8, @intCast(named_group_x25519_mlkem768 & 0xff));
    frame[87] = @as(u8, @intCast((named_group_x25519_mlkem768 >> 8) & 0xff));
    frame[88] = @as(u8, @intCast(named_group_x25519_mlkem768 & 0xff));
    return frame;
}

fn clientHelloRecordWithEmptyServerName() [101]u8 {
    var frame = clientHelloRecord();
    frame[60] = 0x00; // host_len low byte (was 0x05)
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

fn clientHelloRecordWithPskNotLastExtension() [126]u8 {
    var frame = clientHelloRecordWithPskBinderCountMismatch();

    var psk_ext: [19]u8 = undefined;
    @memcpy(psk_ext[0..], frame[107..126]);
    var psk_modes_ext: [6]u8 = undefined;
    @memcpy(psk_modes_ext[0..], frame[101..107]);

    @memcpy(frame[101..120], psk_ext[0..]);
    @memcpy(frame[120..126], psk_modes_ext[0..]);
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

fn hrrServerHelloRecordWithInvalidKeySharePayload() [61]u8 {
    var frame = hrrServerHelloRecord();
    frame[59] = 0x00;
    frame[60] = 0x00; // selected_group=0x0000 (invalid)
    return frame;
}

fn hrrServerHelloRecordWithCookie() [68]u8 {
    var frame: [68]u8 = undefined;
    const base = hrrServerHelloRecord();
    @memcpy(frame[0..base.len], base[0..]);
    std.mem.writeInt(u16, frame[3..5], 63, .big);
    const hs_len = handshake.writeU24(59);
    @memcpy(frame[6..9], &hs_len);
    frame[47] = 0x00;
    frame[48] = 0x13; // extension bytes: 12 + cookie(7)
    // cookie: type=0x002c len=3 cookie_len=1 cookie=0xaa
    frame[61] = 0x00;
    frame[62] = 0x2c;
    frame[63] = 0x00;
    frame[64] = 0x03;
    frame[65] = 0x00;
    frame[66] = 0x01;
    frame[67] = 0xaa;
    return frame;
}

fn hrrServerHelloRecordWithInvalidCookiePayload() [68]u8 {
    var frame = hrrServerHelloRecordWithCookie();
    frame[66] = 0x00; // cookie vector len becomes zero (invalid)
    return frame;
}

fn keyUpdateRecord(request: handshake.KeyUpdateRequest) [10]u8 {
    return Engine.buildKeyUpdateRecord(request);
}

fn keyUpdateRecordWithRawRequest(raw: u8) [10]u8 {
    var frame = keyUpdateRecord(.update_not_requested);
    frame[9] = raw;
    return frame;
}

fn keyUpdateRecordWithBodyLenTwo() [11]u8 {
    var frame: [11]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 6, .big);
    frame[5] = @intFromEnum(state.HandshakeType.key_update);
    const hs_len = handshake.writeU24(2);
    @memcpy(frame[6..9], &hs_len);
    frame[9] = 0x00;
    frame[10] = 0x00;
    return frame;
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

const test_server_cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
const test_server_cert_chain = [_][]const u8{test_server_cert_der[0..]};

fn testSignCertificateVerify(_: []const u8, _: u16, out: []u8, _: usize) anyerror!usize {
    const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
    if (out.len < ed25519_len) return error.OutOfMemory;
    @memset(out[0..ed25519_len], 0x5a);
    return ed25519_len;
}

fn testServerCredentials() ServerCredentials {
    return .{
        .cert_chain_der = &test_server_cert_chain,
        .signature_scheme = 0x0807,
        .sign_certificate_verify = testSignCertificateVerify,
    };
}

fn validFinishedRecordForServer(engine: *Engine, allocator: std.mem.Allocator) ![]u8 {
    const hs = engine.handshake_read_secret orelse return error.TestUnexpectedResult;
    switch (hs) {
        .sha256 => |secret| {
            const digest = engine.transcriptDigestSha256();
            const fin_key = keyschedule.finishedKey(.tls_aes_128_gcm_sha256, secret);
            const verify = keyschedule.finishedVerifyData(.tls_aes_128_gcm_sha256, fin_key, &digest);
            return finishedRecordFromBody(allocator, verify[0..]);
        },
        .sha384 => |secret| {
            const digest = engine.transcriptDigestSha384();
            const fin_key = keyschedule.finishedKey(.tls_aes_256_gcm_sha384, secret);
            const verify = keyschedule.finishedVerifyData(.tls_aes_256_gcm_sha384, fin_key, &digest);
            return finishedRecordFromBody(allocator, verify[0..]);
        },
    }
}

fn ingestValidClientHelloForServer(engine: *Engine) !void {
    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const ch = try clientHelloRecordWithX25519Public(std.testing.allocator, client_kp.public_key);
    defer std.testing.allocator.free(ch);
    _ = try engine.ingestRecord(ch);
}

fn ingestValidServerHelloForClient(engine: *Engine) !void {
    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    try engine.setClientX25519SecretKey(client_kp.secret_key);
    const server_kp = std.crypto.dh.X25519.KeyPair.generate();
    const suite = configuredCipherSuiteCodepoint(engine.config.suite);
    const sh = try serverHelloRecordWithX25519Public(std.testing.allocator, suite, server_kp.public_key);
    defer std.testing.allocator.free(sh);
    _ = try engine.ingestRecord(sh);
}

test "client rejects server hello when x25519 secret is not primed" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const server_kp = std.crypto.dh.X25519.KeyPair.generate();
    const sh = try serverHelloRecordWithX25519Public(std.testing.allocator, 0x1301, server_kp.public_key);
    defer std.testing.allocator.free(sh);

    try std.testing.expectError(error.MissingKeyExchangeSecret, engine.ingestRecord(sh));
}

test "setClientX25519SecretKey rejects non-client role" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.IllegalTransition, engine.setClientX25519SecretKey([_]u8{0xaa} ** 32));
}

test "generateClientX25519KeyShare arms client secret state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const public = try engine.generateClientX25519KeyShare();
    try std.testing.expect(public.len == 32);
    try std.testing.expect(engine.client_x25519_secret_key != null);
}

test "client side handshake flow reaches connected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
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

    try ingestValidServerHelloForClient(&engine);
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

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecordSha384());

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    switch (engine.latest_secret orelse return error.TestUnexpectedResult) {
        .sha256 => return error.TestUnexpectedResult,
        .sha384 => {},
    }
}

test "key schedule stages are populated across client handshake milestones" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    try std.testing.expect(engine.early_secret != null);
    try std.testing.expect(engine.handshake_read_secret != null);
    try std.testing.expect(engine.handshake_write_secret != null);
    try std.testing.expect(engine.master_secret == null);
    try std.testing.expect(engine.latest_secret == null);

    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expect(engine.master_secret != null);
    try std.testing.expect(engine.latest_secret != null);
}

test "key schedule stages follow suite digest width" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_256_gcm_sha384,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    switch (engine.early_secret orelse return error.TestUnexpectedResult) {
        .sha384 => |secret| try std.testing.expectEqual(@as(usize, 48), secret.len),
        .sha256 => return error.TestUnexpectedResult,
    }
    switch (engine.handshake_read_secret orelse return error.TestUnexpectedResult) {
        .sha384 => |secret| try std.testing.expectEqual(@as(usize, 48), secret.len),
        .sha256 => return error.TestUnexpectedResult,
    }
    switch (engine.handshake_write_secret orelse return error.TestUnexpectedResult) {
        .sha384 => |secret| try std.testing.expectEqual(@as(usize, 48), secret.len),
        .sha256 => return error.TestUnexpectedResult,
    }

    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecordSha384());
    switch (engine.master_secret orelse return error.TestUnexpectedResult) {
        .sha384 => |secret| try std.testing.expectEqual(@as(usize, 48), secret.len),
        .sha256 => return error.TestUnexpectedResult,
    }
    switch (engine.latest_secret orelse return error.TestUnexpectedResult) {
        .sha384 => |secret| try std.testing.expectEqual(@as(usize, 48), secret.len),
        .sha256 => return error.TestUnexpectedResult,
    }
}

test "no-psk key schedule uses hash-length zero ikm for early and master extract" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);

    const shared = engine.key_exchange_secret orelse return error.TestUnexpectedResult;
    const zeros = [_]u8{0} ** 32;
    const empty_digest = Engine.emptyTranscriptHashSha256();

    const expected_early = keyschedule.extract(.tls_aes_128_gcm_sha256, &zeros, &zeros);
    const wrong_early = keyschedule.extract(.tls_aes_128_gcm_sha256, &zeros, "");
    switch (engine.early_secret orelse return error.TestUnexpectedResult) {
        .sha256 => |secret| {
            try std.testing.expectEqualSlices(u8, &expected_early, &secret);
            try std.testing.expect(!std.mem.eql(u8, &wrong_early, &secret));
        },
        .sha384 => return error.TestUnexpectedResult,
    }

    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    const derived = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, expected_early, "derived", &empty_digest);
    const hs_base = keyschedule.extract(.tls_aes_128_gcm_sha256, &derived, shared[0..]);
    const master_derived = keyschedule.deriveSecret(.tls_aes_128_gcm_sha256, hs_base, "derived", &empty_digest);
    const expected_master = keyschedule.extract(.tls_aes_128_gcm_sha256, &master_derived, &zeros);
    const wrong_master = keyschedule.extract(.tls_aes_128_gcm_sha256, &master_derived, "");

    switch (engine.master_secret orelse return error.TestUnexpectedResult) {
        .sha256 => |secret| {
            try std.testing.expectEqualSlices(u8, &expected_master, &secret);
            try std.testing.expect(!std.mem.eql(u8, &wrong_master, &secret));
        },
        .sha384 => return error.TestUnexpectedResult,
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

    try ingestValidServerHelloForClient(&engine);
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

test "ignorable tls13 change_cipher_spec is accepted as no-op" {
    const ccs = [_]u8{
        @intFromEnum(record.ContentType.change_cipher_spec),
        0x03,
        0x03,
        0x00,
        0x01,
        0x01,
    };

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const res = try engine.ingestRecord(&ccs);
    try std.testing.expectEqual(@as(usize, 0), res.action_count);
    try std.testing.expectEqual(state.ConnectionState.start, engine.machine.state);
}

test "non-ignorable change_cipher_spec is rejected" {
    const invalid_ccs = [_]u8{
        @intFromEnum(record.ContentType.change_cipher_spec),
        0x03,
        0x03,
        0x00,
        0x01,
        0x02,
    };

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.UnsupportedRecordType, engine.ingestRecord(&invalid_ccs));
}

test "client accepts hrr then server hello" {
    const hrr = hrrServerHelloRecord();

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

    try ingestValidServerHelloForClient(&engine);
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

test "client rejects hrr with invalid key_share payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithInvalidKeySharePayload();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&hrr));
}

test "client accepts hrr with valid cookie extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithCookie();
    _ = try engine.ingestRecord(&hrr);
    try std.testing.expectEqual(state.ConnectionState.wait_server_hello, engine.machine.state);
}

test "client rejects hrr with invalid cookie payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const hrr = hrrServerHelloRecordWithInvalidCookiePayload();
    try std.testing.expectError(error.InvalidCookieExtension, engine.ingestRecord(&hrr));
}

test "keyupdate request is surfaced in action" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
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

test "keyupdate update_not_requested does not trigger reciprocal send action" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    const before = engine.latest_secret orelse return error.TestUnexpectedResult;

    const ku = keyUpdateRecord(.update_not_requested);
    const res = try engine.ingestRecord(&ku);

    try std.testing.expectEqual(@as(usize, 3), res.action_count);
    switch (res.actions[1]) {
        .key_update => |req| try std.testing.expectEqual(handshake.KeyUpdateRequest.update_not_requested, req),
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

test "server role keyupdate request is surfaced and reciprocated" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();
    try ingestValidClientHelloForServer(&engine);
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    _ = try engine.ingestRecord(fin);
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

test "server role keyupdate update_not_requested does not trigger reciprocal send action" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();
    try ingestValidClientHelloForServer(&engine);
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    _ = try engine.ingestRecord(fin);
    const before = engine.latest_secret orelse return error.TestUnexpectedResult;

    const ku = keyUpdateRecord(.update_not_requested);
    const res = try engine.ingestRecord(&ku);

    try std.testing.expectEqual(@as(usize, 3), res.action_count);
    switch (res.actions[1]) {
        .key_update => |req| try std.testing.expectEqual(handshake.KeyUpdateRequest.update_not_requested, req),
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

test "invalid keyupdate request byte is rejected as invalid request" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    const ku = keyUpdateRecordWithRawRequest(2);
    try std.testing.expectError(error.InvalidRequest, engine.ingestRecord(&ku));
}

test "invalid keyupdate body length is rejected as invalid length" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    const ku = keyUpdateRecordWithBodyLenTwo();
    try std.testing.expectError(error.InvalidLength, engine.ingestRecord(&ku));
}

test "invalid keyupdate request maps to illegal_parameter alert intent" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    const out = engine.ingestRecordWithAlertIntent(&keyUpdateRecordWithRawRequest(2));
    switch (out) {
        .ok => return error.TestUnexpectedResult,
        .fatal => |fatal| {
            try std.testing.expectEqual(error.InvalidRequest, fatal.err);
            try std.testing.expectEqual(alerts.AlertDescription.illegal_parameter, fatal.alert.description);
        },
    }
}

test "invalid keyupdate body length maps to decode_error alert intent" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());

    const out = engine.ingestRecordWithAlertIntent(&keyUpdateRecordWithBodyLenTwo());
    switch (out) {
        .ok => return error.TestUnexpectedResult,
        .fatal => |failure| {
            try std.testing.expectEqual(error.InvalidLength, failure.err);
            try std.testing.expectEqual(alerts.AlertLevel.fatal, failure.alert.level);
            try std.testing.expectEqual(alerts.AlertDescription.decode_error, failure.alert.description);
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

test "client role rejects pre-connected early data even when enabled" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
        },
    });
    defer engine.deinit();

    try engine.beginEarlyData("ticket-c", true);
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

test "early data gates replay once then accepts additional records in same connection" {
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
    _ = try engine.ingestRecord(&rec);
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

test "early data replay rejects duplicate ticket across sessions in same scope" {
    var replay = try early_data.ReplayFilter.init(std.testing.allocator, 4096);
    defer replay.deinit();

    const rec = appDataRecord("hello");

    var first = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .replay_node_id = 7,
            .replay_epoch = 42,
        },
    });
    defer first.deinit();

    var second = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{
            .enabled = true,
            .replay_filter = &replay,
            .replay_node_id = 7,
            .replay_epoch = 42,
        },
    });
    defer second.deinit();

    try first.beginEarlyData("ticket-dup", true);
    _ = try first.ingestRecord(&rec);

    try second.beginEarlyData("ticket-dup", true);
    try std.testing.expectError(error.EarlyDataRejected, second.ingestRecord(&rec));
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

test "early data ticket freshness window rejects future-issued ticket" {
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

    try std.testing.expectError(error.EarlyDataTicketExpired, engine.beginEarlyDataWithTimes("ticket-future", true, 1_700_000_100, 1_700_000_000));
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

test "client rejects server hello with invalid key_share payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithInvalidKeySharePayload();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "client rejects server hello hybrid key_share when hybrid kex is disabled" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithHybridKeyShare();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "client rejects hybrid key_share even when hybrid policy is enabled without runtime hybrid secret wiring" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .group_policy = .{
            .allowed_named_groups = &.{named_group_x25519_mlkem768},
            .allow_hybrid_kex = true,
            .hybrid_named_groups = &.{named_group_x25519_mlkem768},
        },
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithHybridKeyShare();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "client rejects server hello with invalid pre_shared_key payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = serverHelloRecordWithInvalidPreSharedKeyPayload();
    try std.testing.expectError(error.InvalidPreSharedKeyExtension, engine.ingestRecord(&rec));
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

test "client accepts server hello when downgrade-like bytes are not in tail position" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    try engine.setClientX25519SecretKey(client_kp.secret_key);
    const server_kp = std.crypto.dh.X25519.KeyPair.generate();
    var rec = try serverHelloRecordWithX25519Public(std.testing.allocator, 0x1301, server_kp.public_key);
    defer std.testing.allocator.free(rec);
    rec[34] = 0x44;
    rec[35] = 0x4f;
    rec[36] = 0x57;
    rec[37] = 0x4e;
    rec[38] = 0x47;
    rec[39] = 0x52;
    rec[40] = 0x44;
    rec[41] = 0x01;

    _ = try engine.ingestRecord(rec);
    try std.testing.expectEqual(state.ConnectionState.wait_encrypted_extensions, engine.machine.state);
}

test "client accepts server hello when downgrade tail is near-match only" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    try engine.setClientX25519SecretKey(client_kp.secret_key);
    const server_kp = std.crypto.dh.X25519.KeyPair.generate();
    var rec = try serverHelloRecordWithX25519Public(std.testing.allocator, 0x1301, server_kp.public_key);
    defer std.testing.allocator.free(rec);
    rec[35] = 0x44;
    rec[36] = 0x4f;
    rec[37] = 0x57;
    rec[38] = 0x4e;
    rec[39] = 0x47;
    rec[40] = 0x52;
    rec[41] = 0x44;
    rec[42] = 0x02;

    _ = try engine.ingestRecord(rec);
    try std.testing.expectEqual(state.ConnectionState.wait_encrypted_extensions, engine.machine.state);
}

test "server accepts client hello without ALPN extension by default" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const rec = try clientHelloRecordWithoutAlpn(std.testing.allocator, client_kp.public_key);
    defer std.testing.allocator.free(rec);
    _ = try engine.ingestRecord(rec);
    try std.testing.expectEqual(state.ConnectionState.wait_client_certificate_or_finished, engine.machine.state);
}

test "server rejects client hello with invalid server_name payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithEmptyServerName();
    try std.testing.expectError(error.InvalidServerNameExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello with invalid alpn payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithInvalidAlpnPayload();
    try std.testing.expectError(error.InvalidAlpnExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello with invalid supported_groups payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithInvalidSupportedGroupsPayload();
    try std.testing.expectError(error.InvalidSupportedGroupsExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello hybrid group when hybrid kex is disabled" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithHybridGroup();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "server rejects hybrid-only key_share when hybrid kex is enabled but not wired" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
        .group_policy = .{
            .allowed_named_groups = &.{named_group_x25519_mlkem768},
            .allow_hybrid_kex = true,
            .hybrid_named_groups = &.{named_group_x25519_mlkem768},
        },
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithHybridGroup();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello with invalid key_share payload" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithInvalidKeySharePayload();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
}

test "server rejects client hello when key_share group is outside supported_groups" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithKeyShareGroupOutsideSupportedGroups();
    try std.testing.expectError(error.InvalidKeyShareExtension, engine.ingestRecord(&rec));
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

test "server rejects psk offer when pre_shared_key is not last extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithPskNotLastExtension();
    try std.testing.expectError(error.InvalidPreSharedKeyPlacement, engine.ingestRecord(&rec));
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
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    try std.testing.expectEqual(state.ConnectionState.wait_client_certificate_or_finished, engine.machine.state);
}

test "server emits outbound handshake flight when credentials are configured" {
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out.len < ed25519_len) return error.OutOfMemory;
            @memset(out[0..ed25519_len], 0x2a);
            return ed25519_len;
        }
    };

    const cert = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const chain = [_][]const u8{cert[0..]};

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = .{
            .cert_chain_der = &chain,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = Hooks.sign,
        },
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const ch = try clientHelloRecordWithX25519Public(std.testing.allocator, client_kp.public_key);
    defer std.testing.allocator.free(ch);
    const res = try engine.ingestRecord(ch);
    try std.testing.expectEqual(@as(usize, 3), res.action_count);
    try std.testing.expectEqual(@as(state.HandshakeType, .client_hello), res.actions[0].handshake);
    switch (res.actions[1]) {
        .send_handshake_flight => |count| try std.testing.expectEqual(@as(u8, 5), count),
        else => return error.TestUnexpectedResult,
    }

    var idx: usize = 0;
    while (idx < 5) : (idx += 1) {
        const rec = engine.popOutboundRecord() orelse return error.TestUnexpectedResult;
        defer std.testing.allocator.free(rec);
        const parsed = try record.parseRecord(rec);
        if (idx == 0) {
            try std.testing.expectEqual(record.ContentType.handshake, parsed.header.content_type);
            const hs = try handshake.parseOne(parsed.payload);
            try std.testing.expectEqual(state.HandshakeType.server_hello, hs.header.handshake_type);
            var sh = try messages.ServerHello.decode(std.testing.allocator, hs.body);
            defer sh.deinit(std.testing.allocator);
            const ext = findExtensionData(sh.extensions, ext_key_share) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(@as(usize, 36), ext.len);
            const key_len = readU16(ext[2..4]);
            try std.testing.expectEqual(@as(usize, 32), key_len);
            try std.testing.expect(!std.mem.eql(u8, sh.random[0..], &([_]u8{0x33} ** 32)));
        } else {
            try std.testing.expectEqual(record.ContentType.application_data, parsed.header.content_type);
            try std.testing.expect(parsed.payload.len > 17);
        }
    }
    try std.testing.expect(engine.key_exchange_secret != null);
}

test "server verifies finished when credentials are configured" {
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out.len < ed25519_len) return error.OutOfMemory;
            @memset(out[0..ed25519_len], 0x2b);
            return ed25519_len;
        }
    };

    const cert = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const chain = [_][]const u8{cert[0..]};
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = .{
            .cert_chain_der = &chain,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = Hooks.sign,
        },
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const ch = try clientHelloRecordWithX25519Public(std.testing.allocator, client_kp.public_key);
    defer std.testing.allocator.free(ch);
    _ = try engine.ingestRecord(ch);

    // Invalid Finished must fail under credential-bound server verification path.
    try std.testing.expectError(error.InvalidFinishedMessage, engine.ingestRecord(&finishedRecord()));

    // Build a valid Finished from current transcript+handshake secret.
    const hs = engine.handshake_read_secret orelse return error.TestUnexpectedResult;
    const verify = switch (hs) {
        .sha256 => |secret| blk: {
            const digest = engine.transcriptDigestSha256();
            const fin_key = keyschedule.finishedKey(.tls_aes_128_gcm_sha256, secret);
            break :blk keyschedule.finishedVerifyData(.tls_aes_128_gcm_sha256, fin_key, &digest);
        },
        .sha384 => return error.TestUnexpectedResult,
    };
    const fin_rec = try finishedRecordFromBody(std.testing.allocator, verify[0..]);
    defer std.testing.allocator.free(fin_rec);
    _ = try engine.ingestRecord(fin_rec);
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "server requires peer certificate before accepting finished when policy demands it" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
        .peer_validation = .{ .require_peer_certificate = true },
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    try std.testing.expectError(error.MissingPeerCertificate, engine.ingestRecord(fin));
}

test "server infers peer certificate requirement from trust store policy" {
    var store = trust_store.TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
        .peer_validation = .{ .trust_store = &store },
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    try std.testing.expectError(error.MissingPeerCertificate, engine.ingestRecord(fin));
}

test "server rejects outbound flight when ed25519 signer returns invalid length" {
    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out: []u8, _: usize) anyerror!usize {
            if (out.len < 4) return error.OutOfMemory;
            @memset(out[0..4], 0xaa);
            return 4;
        }
    };

    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = .{
            .cert_chain_der = &test_server_cert_chain,
            .signature_scheme = 0x0807,
            .sign_certificate_verify = Hooks.sign,
        },
    });
    defer engine.deinit();

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const ch = try clientHelloRecordWithX25519Public(std.testing.allocator, client_kp.public_key);
    defer std.testing.allocator.free(ch);
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, engine.ingestRecord(ch));
}

test "connected plaintext application_data record is rejected without AEAD" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);

    const rec = appDataRecord("hello");
    try std.testing.expectError(error.DecryptFailed, engine.ingestRecord(&rec));
}

test "application data AEAD roundtrip works across client and server engines" {
    var client = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer client.deinit();
    client.machine.state = .connected;

    var server = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer server.deinit();
    server.machine.state = .connected;
    const client_ap = [_]u8{0x11} ** 32;
    const server_ap = [_]u8{0x22} ** 32;
    client.installApplicationSecrets(.{ .sha256 = client_ap }, .{ .sha256 = server_ap });
    server.installApplicationSecrets(.{ .sha256 = client_ap }, .{ .sha256 = server_ap });

    const rec = try client.buildApplicationDataRecord(std.testing.allocator, "ping");
    defer std.testing.allocator.free(rec);
    const res = try server.ingestRecord(rec);
    try std.testing.expectEqual(@as(usize, 1), res.action_count);
    switch (res.actions[0]) {
        .application_data => |data| try std.testing.expectEqualStrings("ping", data),
        else => return error.TestUnexpectedResult,
    }
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

    try ingestValidServerHelloForClient(&engine);
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
        alerts.Alert{ .level = .fatal, .description = .illegal_parameter },
        classifyErrorAlert(error.InvalidPskBinderLength),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .illegal_parameter },
        classifyErrorAlert(error.InvalidPreSharedKeyPlacement),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .illegal_parameter },
        classifyErrorAlert(error.InvalidPreSharedKeyExtension),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .decode_error },
        classifyErrorAlert(error.InvalidLength),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .decode_error },
        classifyErrorAlert(error.InvalidHelloMessage),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .handshake_failure },
        classifyErrorAlert(error.EarlyDataRejected),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .handshake_failure },
        classifyErrorAlert(error.MissingKeyExchangeSecret),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .certificate_required },
        classifyErrorAlert(error.MissingPeerCertificate),
    );
    try std.testing.expectEqual(
        alerts.Alert{ .level = .fatal, .description = .bad_certificate },
        classifyErrorAlert(error.PeerCertificateValidationFailed),
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

    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    try engine.setClientX25519SecretKey(client_kp.secret_key);
    const server_kp = std.crypto.dh.X25519.KeyPair.generate();
    const sh = try serverHelloRecordWithX25519Public(std.testing.allocator, 0x1301, server_kp.public_key);
    defer std.testing.allocator.free(sh);

    const out = engine.ingestRecordWithAlertIntent(sh);
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

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    try std.testing.expectError(error.InvalidCertificateMessage, engine.ingestRecord(&handshakeRecord(.certificate)));
}

test "certificate path valid bodies progress state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .peer_validation = .{ .enforce_certificate_verify = false },
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    _ = try engine.ingestRecord(&certificateVerifyRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "certificate_verify crypto enforcement rejects invalid peer certificate" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, engine.ingestRecord(&certificateVerifyRecord()));
}

test "certificate_verify payload context uses local role string for signing" {
    var server = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer server.deinit();
    const server_payload = try server.buildCertificateVerifyPayload(.local);
    defer std.testing.allocator.free(server_payload);
    try std.testing.expectEqualStrings(
        "TLS 1.3, server CertificateVerify",
        server_payload[64 .. 64 + "TLS 1.3, server CertificateVerify".len],
    );

    var client = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer client.deinit();
    const client_payload = try client.buildCertificateVerifyPayload(.local);
    defer std.testing.allocator.free(client_payload);
    try std.testing.expectEqualStrings(
        "TLS 1.3, client CertificateVerify",
        client_payload[64 .. 64 + "TLS 1.3, client CertificateVerify".len],
    );
}

test "certificate_verify payload context uses peer role string for verification" {
    var server = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer server.deinit();
    const server_payload = try server.buildCertificateVerifyPayload(.peer);
    defer std.testing.allocator.free(server_payload);
    try std.testing.expectEqualStrings(
        "TLS 1.3, client CertificateVerify",
        server_payload[64 .. 64 + "TLS 1.3, client CertificateVerify".len],
    );

    var client = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer client.deinit();
    const client_payload = try client.buildCertificateVerifyPayload(.peer);
    defer std.testing.allocator.free(client_payload);
    try std.testing.expectEqualStrings(
        "TLS 1.3, server CertificateVerify",
        client_payload[64 .. 64 + "TLS 1.3, server CertificateVerify".len],
    );
}

test "client peer validation policy rejects malformed leaf certificate" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .peer_validation = .{
            .expected_server_name = "example.com",
        },
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    try std.testing.expectError(error.PeerCertificateValidationFailed, engine.ingestRecord(&certificateRecord()));
}

test "invalid certificate_verify body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
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

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, engine.ingestRecord(&certificateVerifyRecordWithAlgorithm(0xeeee)));
}

test "server role certificate path valid bodies progress state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
        .peer_validation = .{ .enforce_certificate_verify = false },
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    _ = try engine.ingestRecord(&certificateRecord());
    _ = try engine.ingestRecord(&certificateVerifyRecord());
    const fin = try validFinishedRecordForServer(&engine, std.testing.allocator);
    defer std.testing.allocator.free(fin);
    _ = try engine.ingestRecord(fin);
    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
}

test "server role invalid certificate body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    try std.testing.expectError(error.InvalidCertificateMessage, engine.ingestRecord(&handshakeRecord(.certificate)));
}

test "server role invalid certificate_verify body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .server_credentials = testServerCredentials(),
    });
    defer engine.deinit();

    try ingestValidClientHelloForServer(&engine);
    _ = try engine.ingestRecord(&certificateRecord());
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, engine.ingestRecord(&handshakeRecord(.certificate_verify)));
}

test "invalid encrypted_extensions body is rejected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
    try std.testing.expectError(error.InvalidEncryptedExtensionsMessage, engine.ingestRecord(&handshakeRecord(.encrypted_extensions)));
}

test "new_session_ticket body is validated in connected state" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try ingestValidServerHelloForClient(&engine);
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

    try ingestValidServerHelloForClient(&engine);
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&finishedRecord());
    try std.testing.expectError(error.InvalidNewSessionTicketMessage, engine.ingestRecord(&handshakeRecord(.new_session_ticket)));
}
