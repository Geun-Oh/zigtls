const std = @import("std");
const alerts = @import("alerts.zig");
const handshake = @import("handshake.zig");
const keyschedule = @import("keyschedule.zig");
const record = @import("record.zig");
const state = @import("state.zig");

pub const Config = struct {
    role: state.Role,
    suite: keyschedule.CipherSuite,
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
} || record.ParseError || handshake.ParseError || handshake.KeyUpdateError || state.TransitionError || alerts.DecodeError;

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

    pub fn init(allocator: std.mem.Allocator, config: Config) Engine {
        return .{
            .allocator = allocator,
            .config = config,
            .machine = state.Machine.init(config.role),
            .transcript = Transcript.init(config.suite),
        };
    }

    pub fn ingestRecord(self: *Engine, record_bytes: []const u8) EngineError!IngestResult {
        _ = self.allocator;

        const parsed = try record.parseRecord(record_bytes);
        var result = IngestResult.init(5 + parsed.payload.len);

        switch (parsed.header.content_type) {
            .handshake => {
                var cursor = parsed.payload;
                while (cursor.len > 0) {
                    const frame = try handshake.parseOne(cursor);
                    const frame_len = 4 + @as(usize, @intCast(frame.header.length));
                    self.transcript.update(cursor[0..frame_len]);

                    const event = handshake.classifyEvent(frame);
                    try self.machine.onEvent(event);
                    try result.push(.{ .handshake = frame.header.handshake_type });
                    if (event == .hello_retry_request) {
                        try result.push(.{ .hello_retry_request = {} });
                    }
                    if (frame.header.handshake_type == .key_update) {
                        const req = try handshake.parseKeyUpdateRequest(frame.body);
                        try result.push(.{ .key_update = req });
                        if (req == .update_requested) {
                            try result.push(.{ .send_key_update = .update_not_requested });
                        }
                    }
                    try result.push(.{ .state_changed = self.machine.state });

                    if (self.machine.state == .connected) {
                        self.latest_secret = self.deriveApplicationTrafficSecret();
                    }
                    cursor = frame.rest;
                }
            },
            .alert => {
                const alert = try alerts.Alert.decode(parsed.payload);
                try result.push(.{ .received_alert = alert });
                if (alert.description == .close_notify) {
                    self.machine.markClosed();
                } else {
                    self.machine.markClosing();
                }
                try result.push(.{ .state_changed = self.machine.state });
            },
            .application_data => {
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
};

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

fn hrrServerHelloRecord() [43]u8 {
    var frame: [43]u8 = undefined;
    frame[0] = @intFromEnum(record.ContentType.handshake);
    frame[1] = 0x03;
    frame[2] = 0x03;
    std.mem.writeInt(u16, frame[3..5], 38, .big);
    frame[5] = @intFromEnum(state.HandshakeType.server_hello);
    const len = handshake.writeU24(34);
    @memcpy(frame[6..9], &len);
    frame[9] = 0x03;
    frame[10] = 0x03;
    @memcpy(frame[11..43], &handshake.hello_retry_request_random);
    return frame;
}

fn keyUpdateRecord(request: handshake.KeyUpdateRequest) [10]u8 {
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

test "client side handshake flow reaches connected" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });

    _ = try engine.ingestRecord(&handshakeRecord(.server_hello));
    _ = try engine.ingestRecord(&handshakeRecord(.encrypted_extensions));
    _ = try engine.ingestRecord(&handshakeRecord(.finished));

    try std.testing.expectEqual(state.ConnectionState.connected, engine.machine.state);
    try std.testing.expect(engine.latest_secret != null);
}

test "unexpected handshake fails with illegal transition" {
    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });

    try std.testing.expectError(error.IllegalTransition, engine.ingestRecord(&handshakeRecord(.finished)));
}

test "close_notify transitions to closed" {
    var frame = Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });

    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_chacha20_poly1305_sha256,
    });

    _ = try engine.ingestRecord(&frame);
    try std.testing.expectEqual(state.ConnectionState.closed, engine.machine.state);
}

test "client accepts hrr then server hello" {
    const hrr = hrrServerHelloRecord();
    const second_sh = handshakeRecord(.server_hello);

    var engine = Engine.init(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    });

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
    _ = try engine.ingestRecord(&handshakeRecord(.server_hello));
    _ = try engine.ingestRecord(&handshakeRecord(.encrypted_extensions));
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
