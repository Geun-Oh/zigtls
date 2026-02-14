const std = @import("std");
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

pub const Config = struct {
    role: state.Role,
    suite: keyschedule.CipherSuite,
    early_data: EarlyDataConfig = .{},
    allowed_signature_algorithms: []const u16 = &default_signature_algorithms,
};

pub const EarlyDataConfig = struct {
    enabled: bool = false,
    replay_filter: ?*early_data.ReplayFilter = null,
    max_ticket_age_sec: u64 = 600,
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

pub const EngineError = error{
    TooManyActions,
    UnsupportedRecordType,
    EarlyDataRejected,
    MissingReplayFilter,
    EarlyDataTicketExpired,
    TruncationDetected,
    InvalidHelloMessage,
    InvalidCertificateMessage,
    InvalidCertificateVerifyMessage,
    InvalidEncryptedExtensionsMessage,
    InvalidNewSessionTicketMessage,
    MissingRequiredClientHelloExtension,
    MissingRequiredServerHelloExtension,
    MissingPskKeyExchangeModes,
    InvalidPskBinder,
    UnsupportedSignatureAlgorithm,
} || record.ParseError || handshake.ParseError || handshake.KeyUpdateError || state.TransitionError || alerts.DecodeError;

const ext_server_name: u16 = 0x0000;
const ext_supported_groups: u16 = 0x000a;
const ext_alpn: u16 = 0x0010;
const ext_supported_versions: u16 = 0x002b;
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
                        try result.push(.{ .key_update = req });
                        if (req == .update_requested) {
                            try result.push(.{ .send_key_update = .update_not_requested });
                        }
                    }
                    try result.push(.{ .state_changed = self.machine.state });

                    if (prev_state != .connected and self.machine.state == .connected) {
                        self.metrics.connected_transitions += 1;
                        self.latest_secret = self.deriveApplicationTrafficSecret();
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
                    if (replay_filter.seenOrInsert(ticket)) return error.EarlyDataRejected;
                }
                try result.push(.{ .application_data = parsed.payload });
            },
            else => return error.UnsupportedRecordType,
        }

        return result;
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
        return switch (self.transcript) {
            .sha256 => |hasher| blk: {
                var digest: [32]u8 = undefined;
                var h = hasher;
                h.final(&digest);
                const secret = keyschedule.extract(.tls_aes_128_gcm_sha256, "", &digest);
                break :blk .{ .sha256 = keyschedule.deriveLabel(.tls_aes_128_gcm_sha256, secret, "c ap traffic", &digest, 32) };
            },
            .sha384 => |hasher| blk: {
                var digest: [48]u8 = undefined;
                var h = hasher;
                h.final(&digest);
                const secret = keyschedule.extract(.tls_aes_256_gcm_sha384, "", &digest);
                break :blk .{ .sha384 = keyschedule.deriveLabel(.tls_aes_256_gcm_sha384, secret, "c ap traffic", &digest, 48) };
            },
        };
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
                if (self.config.role == .client and !messages.serverHelloHasHrrRandom(body)) {
                    try self.requireServerHelloExtensions(sh.extensions);
                }
            },
            .client_hello => {
                var ch = messages.ClientHello.decode(self.allocator, body) catch return error.InvalidHelloMessage;
                defer ch.deinit(self.allocator);
                if (self.config.role == .server) {
                    try self.requireClientHelloExtensions(ch.extensions);
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

    fn requireClientHelloExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        _ = self;
        if (!hasExtension(extensions, ext_supported_versions)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_server_name)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_supported_groups)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_key_share)) return error.MissingRequiredClientHelloExtension;
        if (!hasExtension(extensions, ext_alpn)) return error.MissingRequiredClientHelloExtension;
        try validatePskOfferExtensions(extensions);
    }

    fn requireServerHelloExtensions(self: Engine, extensions: []const messages.Extension) EngineError!void {
        _ = self;
        if (!hasExtension(extensions, ext_supported_versions)) return error.MissingRequiredServerHelloExtension;
        if (!hasExtension(extensions, ext_key_share)) return error.MissingRequiredServerHelloExtension;
    }
};

fn hasExtension(extensions: []const messages.Extension, extension_type: u16) bool {
    for (extensions) |ext| {
        if (ext.extension_type == extension_type) return true;
    }
    return false;
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

fn validatePskOfferExtensions(extensions: []const messages.Extension) EngineError!void {
    const psk = findExtensionData(extensions, ext_pre_shared_key) orelse return;
    if (!hasExtension(extensions, ext_psk_key_exchange_modes)) return error.MissingPskKeyExchangeModes;
    _ = parsePskBinderVector(psk) catch return error.InvalidPskBinder;
}

fn findExtensionData(extensions: []const messages.Extension, extension_type: u16) ?[]const u8 {
    for (extensions) |ext| {
        if (ext.extension_type == extension_type) return ext.data;
    }
    return null;
}

fn parsePskBinderVector(bytes: []const u8) !usize {
    // pre_shared_key (CH): identities<7..2^16-1> + binders<33..2^16-1>
    var i: usize = 0;
    if (bytes.len < 2 + 2) return error.Truncated;

    const identities_len = readU16(bytes[i .. i + 2]);
    i += 2;
    if (identities_len == 0) return error.InvalidLength;
    if (i + identities_len + 2 > bytes.len) return error.Truncated;
    const identities_end = i + identities_len;
    while (i < identities_end) {
        if (i + 2 > identities_end) return error.Truncated;
        const id_len = readU16(bytes[i .. i + 2]);
        i += 2;
        if (id_len == 0) return error.InvalidLength;
        if (i + id_len + 4 > identities_end) return error.Truncated;
        i += id_len + 4; // identity + obfuscated_ticket_age
    }
    if (i != identities_end) return error.Truncated;

    const binders_len = readU16(bytes[i .. i + 2]);
    i += 2;
    if (binders_len == 0) return error.InvalidLength;
    if (i + binders_len != bytes.len) return error.Truncated;
    const binders_end = i + binders_len;
    var binder_count: usize = 0;
    while (i < binders_end) {
        if (i + 1 > binders_end) return error.Truncated;
        const binder_len = bytes[i];
        i += 1;
        if (binder_len == 0) return error.InvalidLength;
        if (i + binder_len > binders_end) return error.Truncated;
        i += binder_len;
        binder_count += 1;
    }
    if (binder_count == 0 or i != binders_end) return error.InvalidLength;
    return binder_count;
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
    frame[55] = 0xff;
    frame[56] = 0xfe;
    return frame;
}

fn clientHelloRecordWithoutAlpn() [101]u8 {
    var frame = clientHelloRecord();
    frame[92] = 0xff;
    frame[93] = 0xfe;
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

fn hrrServerHelloRecord() [49]u8 {
    var frame: [49]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 44, .big);
    frame[5] = @intFromEnum(state.HandshakeType.server_hello);
    const len = handshake.writeU24(40);
    @memcpy(frame[6..9], &len);
    frame[9] = 0x03;
    frame[10] = 0x03;
    @memcpy(frame[11..43], &handshake.hello_retry_request_random);
    frame[43] = 0x00; // session id len
    frame[44] = 0x13;
    frame[45] = 0x01; // cipher suite
    frame[46] = 0x00; // compression
    frame[47] = 0x00;
    frame[48] = 0x00; // extensions len
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

test "client side handshake flow reaches connected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&handshakeRecord(.finished));

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    try std.testing.expect(engine.latest_secret != null);
}

test "unexpected handshake fails with illegal transition" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    try std.testing.expectError(error.IllegalTransition, engine.ingestRecord(&handshakeRecord(.finished)));
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

test "keyupdate request is surfaced in action" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();
    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&handshakeRecord(.finished));

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

test "server rejects client hello without required extension" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    const rec = clientHelloRecordWithoutAlpn();
    try std.testing.expectError(error.MissingRequiredClientHelloExtension, engine.ingestRecord(&rec));
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

test "valid client hello body is accepted for server role" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&clientHelloRecord());
    try std.testing.expectEqual(state.ConnectionState.wait_client_certificate_or_finished, engine.machine.state);
}

test "metrics counters reflect handshake and alert activity" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });
    defer engine.deinit();

    _ = try engine.ingestRecord(&serverHelloRecord());
    _ = try engine.ingestRecord(&encryptedExtensionsRecord());
    _ = try engine.ingestRecord(&handshakeRecord(.finished));
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
    _ = try engine.ingestRecord(&handshakeRecord(.finished));
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
    _ = try engine.ingestRecord(&handshakeRecord(.finished));
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
    _ = try engine.ingestRecord(&handshakeRecord(.finished));
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
    _ = try engine.ingestRecord(&handshakeRecord(.finished));
    try std.testing.expectError(error.InvalidNewSessionTicketMessage, engine.ingestRecord(&handshakeRecord(.new_session_ticket)));
}
