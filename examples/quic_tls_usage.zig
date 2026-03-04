const std = @import("std");
const zigtls = @import("zigtls");

const session = zigtls.tls13.session;
const quic_tls = zigtls.quic.tls13;
const tp = zigtls.quic.transport_parameters;

// NOTE:
// This example intentionally models only the QUIC/TLS boundary.
// Packetization, ACK/loss recovery, congestion control, CID lifecycle, and UDP I/O
// belong to the embedding QUIC engine and are represented as placeholders here.

pub const QuicTransportLevel = enum {
    initial,
    handshake,
    application,
};

const QueuedCrypto = struct {
    level: QuicTransportLevel,
    offset: u64,
    payload: []u8,

    fn deinit(self: *QueuedCrypto, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

const ExampleQuicEngine = struct {
    allocator: std.mem.Allocator,
    pending_crypto: std.ArrayList(QueuedCrypto) = .empty,
    send_offset_initial: u64 = 0,
    send_offset_handshake: u64 = 0,
    send_offset_application: u64 = 0,
    installed_handshake_keys: bool = false,
    installed_application_keys: bool = false,

    fn init(allocator: std.mem.Allocator) ExampleQuicEngine {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *ExampleQuicEngine) void {
        while (self.pending_crypto.items.len > 0) {
            var item = self.pending_crypto.orderedRemove(0);
            item.deinit(self.allocator);
        }
        self.pending_crypto.deinit(self.allocator);
    }

    fn queueCryptoAtLevel(
        self: *ExampleQuicEngine,
        level: QuicTransportLevel,
        offset: u64,
        payload: []const u8,
    ) !void {
        const owned = try self.allocator.dupe(u8, payload);
        try self.pending_crypto.append(self.allocator, .{
            .level = level,
            .offset = offset,
            .payload = owned,
        });
    }

    fn installReadKeys(
        self: *ExampleQuicEngine,
        level: QuicTransportLevel,
        keys: quic_tls.PacketProtectionKeys,
    ) void {
        _ = keys;
        if (level == .handshake) self.installed_handshake_keys = true;
        if (level == .application) self.installed_application_keys = true;
    }

    fn installWriteKeys(
        self: *ExampleQuicEngine,
        level: QuicTransportLevel,
        keys: quic_tls.PacketProtectionKeys,
    ) void {
        _ = keys;
        if (level == .handshake) self.installed_handshake_keys = true;
        if (level == .application) self.installed_application_keys = true;
    }
};

fn toTransportLevel(level: session.QuicEncryptionLevel) QuicTransportLevel {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
}

fn decodeSnapshotSecret(
    suite: zigtls.tls13.keyschedule.CipherSuite,
    secret: session.QuicTrafficSecret,
) !quic_tls.TrafficSecret {
    return quic_tls.trafficSecretFromBytes(suite, secret.bytes[0..secret.len]);
}

// 1) Ask TLS engine to emit QUIC ClientHello at Initial level.
fn bootstrapClientHello(
    engine: *session.Engine,
    quic: *ExampleQuicEngine,
) !void {
    try engine.beginQuicClientHandshake(.{
        .server_name = "api.example.com",
        .alpn_protocol = "h3",
    });
    try drainTlsOutboundCrypto(engine, quic);
}

// 2) Ingress QUIC CRYPTO payload into TLS engine.
fn ingestCrypto(
    engine: *session.Engine,
    quic: *ExampleQuicEngine,
    level: session.QuicEncryptionLevel,
    crypto_payload: []const u8,
) !void {
    const res = try engine.ingestQuicHandshake(level, crypto_payload);
    var i: usize = 0;
    while (i < res.action_count) : (i += 1) {
        switch (res.actions[i]) {
            .quic_key_ready => try installDerivedKeys(engine, quic),
            else => {},
        }
    }
}

// 3) Egress TLS handshake payloads into QUIC CRYPTO streams.
fn drainTlsOutboundCrypto(
    engine: *session.Engine,
    quic: *ExampleQuicEngine,
) !void {
    while (engine.popOutboundQuicHandshake()) |outbound| {
        var owned = outbound;
        defer owned.deinit(quic.allocator);

        const transport_level = toTransportLevel(owned.level);
        const offset_ptr = switch (transport_level) {
            .initial => &quic.send_offset_initial,
            .handshake => &quic.send_offset_handshake,
            .application => &quic.send_offset_application,
        };
        try quic.queueCryptoAtLevel(transport_level, offset_ptr.*, owned.payload);
        offset_ptr.* += @as(u64, @intCast(owned.payload.len));
    }
}

// 4) Convert exported secrets to packet-protection keys and install in QUIC engine.
fn installDerivedKeys(
    engine: *session.Engine,
    quic: *ExampleQuicEngine,
) !void {
    const snap = engine.snapshotQuicSecrets();

    if (snap.handshake_read != null and snap.handshake_write != null) {
        const hs_read = try decodeSnapshotSecret(snap.suite, snap.handshake_read.?);
        const hs_write = try decodeSnapshotSecret(snap.suite, snap.handshake_write.?);
        const hs_read_keys = try quic_tls.derivePacketProtectionKeys(snap.suite, &hs_read);
        const hs_write_keys = try quic_tls.derivePacketProtectionKeys(snap.suite, &hs_write);
        quic.installReadKeys(.handshake, hs_read_keys);
        quic.installWriteKeys(.handshake, hs_write_keys);
    }

    if (snap.application_read != null and snap.application_write != null) {
        const app_read = try decodeSnapshotSecret(snap.suite, snap.application_read.?);
        const app_write = try decodeSnapshotSecret(snap.suite, snap.application_write.?);
        const app_read_keys = try quic_tls.derivePacketProtectionKeys(snap.suite, &app_read);
        const app_write_keys = try quic_tls.derivePacketProtectionKeys(snap.suite, &app_write);
        quic.installReadKeys(.application, app_read_keys);
        quic.installWriteKeys(.application, app_write_keys);
    }
}

// 5) Read validated peer transport parameters.
fn applyPeerTransportParameters(
    allocator: std.mem.Allocator,
    engine: *session.Engine,
) !void {
    if (engine.peerQuicTransportParameters()) |peer_tp| {
        var decoded = try tp.decode(allocator, peer_tp);
        defer decoded.deinit(allocator);
    }
}

pub fn main() void {
    std.debug.print(
        "Use this file as reference for zigtls QUIC ingress/egress/key-install integration.\n",
        .{},
    );
}

test "quic tls usage example: bootstrap and no-op ingress path" {
    var engine = try session.Engine.initChecked(std.testing.allocator, .{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
        .quic_mode = true,
        .quic_transport_parameters = "\x01\x00",
        .peer_validation = .{
            .enforce_certificate_verify = false,
        },
    });
    defer engine.deinit();

    var quic = ExampleQuicEngine.init(std.testing.allocator);
    defer quic.deinit();

    try bootstrapClientHello(&engine, &quic);
    try std.testing.expectEqual(@as(usize, 1), quic.pending_crypto.items.len);
    try std.testing.expectEqual(QuicTransportLevel.initial, quic.pending_crypto.items[0].level);
    try std.testing.expectEqual(@as(u64, 0), quic.pending_crypto.items[0].offset);

    // Empty payload is a valid no-op ingest call.
    try ingestCrypto(&engine, &quic, .initial, &[_]u8{});
    try drainTlsOutboundCrypto(&engine, &quic);
    try applyPeerTransportParameters(std.testing.allocator, &engine);
}
