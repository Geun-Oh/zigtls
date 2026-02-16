const std = @import("std");
const zigtls = @import("zigtls");

const termination = zigtls.termination;
const adapter = zigtls.adapter;
const tls13 = zigtls.tls13;

const MockTransport = struct {
    allocator: std.mem.Allocator,
    writes: std.ArrayList(u8) = .empty,

    fn init(allocator: std.mem.Allocator) MockTransport {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *MockTransport) void {
        self.writes.deinit(self.allocator);
    }

    fn asTransport(self: *MockTransport) adapter.Transport {
        return .{
            .userdata = @intFromPtr(self),
            .read_fn = readFn,
            .write_fn = writeFn,
        };
    }

    fn readFn(_: usize, _: []u8) anyerror!usize {
        return error.WouldBlock;
    }

    fn writeFn(userdata: usize, bytes: []const u8) anyerror!usize {
        var self: *MockTransport = @ptrFromInt(userdata);
        try self.writes.appendSlice(self.allocator, bytes);
        return bytes.len;
    }
};

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leaked = gpa_impl.deinit();
        if (leaked == .leak) std.process.exit(2);
    }
    const allocator = gpa_impl.allocator();

    const Hooks = struct {
        fn sign(_: []const u8, _: u16, out_signature: []u8, _: usize) anyerror!usize {
            const ed25519_len = std.crypto.sign.Ed25519.Signature.encoded_length;
            if (out_signature.len < ed25519_len) return error.NoSpaceLeft;
            @memset(out_signature[0..ed25519_len], 0x4a);
            return ed25519_len;
        }
    };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const chain = [_][]const u8{cert_der[0..]};

    var conn = termination.Connection.init(allocator, .{
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
    conn.accept(.{ .connection_id = 1001, .correlation_id = 90001 });
    const client_kp = std.crypto.dh.X25519.KeyPair.generate();
    const client_hello = try buildClientHelloRecord(allocator, client_kp.public_key);
    defer allocator.free(client_hello);
    _ = try conn.ingest_tls_bytes(client_hello);

    var mock = MockTransport.init(allocator);
    defer mock.deinit();

    var loop = adapter.EventLoopAdapter.init(allocator, &conn, mock.asTransport());
    defer loop.deinit();

    var total_written: usize = 0;
    while (true) {
        const flush = try loop.flushWrite(1024);
        if (flush.bytes_written == 0) break;
        total_written += flush.bytes_written;
    }
    if (total_written == 0) return error.NoWriteProgress;

    if (mock.writes.items.len < 5) return error.InvalidRecordSize;
    const payload_len = std.mem.readInt(u16, mock.writes.items[3..5], .big);
    if (mock.writes.items.len < 5 + payload_len) return error.RecordLengthMismatch;
    if (mock.writes.items[0] != @intFromEnum(tls13.record.ContentType.handshake)) return error.UnexpectedRecordType;

    const read = try loop.pumpRead(4);
    if (!read.would_block) return error.ExpectedWouldBlock;

    std.debug.print(
        "lb-sample ok: bytes_written={d} payload_len={d} correlation_id={d}\n",
        .{ total_written, payload_len, conn.correlation_id },
    );
}

fn buildClientHelloRecord(allocator: std.mem.Allocator, client_pub: [32]u8) ![]u8 {
    const ext_supported_versions_data = try allocator.dupe(u8, &.{ 0x02, 0x03, 0x04 });
    errdefer allocator.free(ext_supported_versions_data);

    const sni_name = "example.com";
    var ext_server_name_data = try allocator.alloc(u8, 5 + sni_name.len);
    errdefer allocator.free(ext_server_name_data);
    std.mem.writeInt(u16, ext_server_name_data[0..2], @as(u16, @intCast(3 + sni_name.len)), .big);
    ext_server_name_data[2] = 0x00;
    std.mem.writeInt(u16, ext_server_name_data[3..5], @as(u16, @intCast(sni_name.len)), .big);
    @memcpy(ext_server_name_data[5..], sni_name);

    var ext_supported_groups_data = try allocator.alloc(u8, 4);
    errdefer allocator.free(ext_supported_groups_data);
    std.mem.writeInt(u16, ext_supported_groups_data[0..2], 2, .big);
    std.mem.writeInt(u16, ext_supported_groups_data[2..4], tls13.session.named_group_x25519, .big);

    const alpn = "h2";
    var ext_alpn_data = try allocator.alloc(u8, 3 + alpn.len);
    errdefer allocator.free(ext_alpn_data);
    std.mem.writeInt(u16, ext_alpn_data[0..2], @as(u16, @intCast(1 + alpn.len)), .big);
    ext_alpn_data[2] = @as(u8, @intCast(alpn.len));
    @memcpy(ext_alpn_data[3..], alpn);

    var ext_key_share_data = try allocator.alloc(u8, 2 + 2 + 2 + client_pub.len);
    errdefer allocator.free(ext_key_share_data);
    std.mem.writeInt(u16, ext_key_share_data[0..2], @as(u16, @intCast(2 + 2 + client_pub.len)), .big);
    std.mem.writeInt(u16, ext_key_share_data[2..4], tls13.session.named_group_x25519, .big);
    std.mem.writeInt(u16, ext_key_share_data[4..6], @as(u16, @intCast(client_pub.len)), .big);
    @memcpy(ext_key_share_data[6..], &client_pub);

    var extensions = try allocator.alloc(tls13.messages.Extension, 5);
    errdefer {
        allocator.free(ext_supported_versions_data);
        allocator.free(ext_server_name_data);
        allocator.free(ext_supported_groups_data);
        allocator.free(ext_alpn_data);
        allocator.free(ext_key_share_data);
        allocator.free(extensions);
    }
    extensions[0] = .{ .extension_type = 0x002b, .data = ext_supported_versions_data };
    extensions[1] = .{ .extension_type = 0x0000, .data = ext_server_name_data };
    extensions[2] = .{ .extension_type = 0x000a, .data = ext_supported_groups_data };
    extensions[3] = .{ .extension_type = 0x0010, .data = ext_alpn_data };
    extensions[4] = .{ .extension_type = 0x0033, .data = ext_key_share_data };

    var random: [32]u8 = undefined;
    std.crypto.random.bytes(&random);

    const session_id = try allocator.alloc(u8, 0);
    errdefer allocator.free(session_id);
    var cipher_suites = try allocator.alloc(u16, 1);
    errdefer allocator.free(cipher_suites);
    cipher_suites[0] = 0x1301;
    const compression_methods = try allocator.dupe(u8, &.{0x00});
    errdefer allocator.free(compression_methods);

    var ch = tls13.messages.ClientHello{
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .extensions = extensions,
    };
    defer ch.deinit(allocator);

    const body = try ch.encode(allocator);
    defer allocator.free(body);
    if (body.len > std.math.maxInt(u16) - 4) return error.RecordOverflow;

    var out = try allocator.alloc(u8, 5 + 4 + body.len);
    out[0] = @intFromEnum(tls13.record.ContentType.handshake);
    std.mem.writeInt(u16, out[1..3], tls13.record.tls_legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @as(u16, @intCast(4 + body.len)), .big);
    out[5] = @intFromEnum(tls13.state.HandshakeType.client_hello);
    const len_u24 = tls13.handshake.writeU24(@as(u24, @intCast(body.len)));
    @memcpy(out[6..9], &len_u24);
    @memcpy(out[9..], body);
    return out;
}
