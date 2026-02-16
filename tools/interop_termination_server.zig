const std = @import("std");
const zigtls = @import("zigtls");

const cert_reload = zigtls.cert_reload;
const termination = zigtls.termination;
const tls_record = zigtls.tls13.record;
const tls_handshake = zigtls.tls13.handshake;
const tls_messages = zigtls.tls13.messages;

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 0,
    cert_path: []const u8 = "",
    key_path: []const u8 = "",
    expected_sni: []const u8 = "localhost",
    expected_alpn: []const u8 = "h2",
    timeout_ms: i32 = 2500,
    max_rounds: usize = 512,
};

const CliError = error{
    MissingValue,
    MissingRequiredFlag,
    InvalidFlag,
    Timeout,
    PeerFatalAlert,
    HandshakeNotCompleted,
};

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leaked = gpa_impl.deinit();
        if (leaked == .leak) std.process.exit(2);
    }
    const allocator = gpa_impl.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
        usage();
        return;
    }

    const cfg = parseArgs(args) catch |err| {
        usage();
        return err;
    };
    const trace = std.posix.getenv("ZIGTLS_INTEROP_TRACE") != null;

    var store = cert_reload.Store.init(allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cfg.cert_path, cfg.key_path);

    var allowed_server_names = [_][]const u8{cfg.expected_sni};
    var allowed_alpn = [_][]const u8{cfg.expected_alpn};

    var conn = try termination.Connection.initChecked(allocator, .{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
        },
        .dynamic_server_credentials = .{
            .store = &store,
            .signature_scheme = 0x0807,
            .auto_sign_from_store_ed25519 = true,
        },
        .client_hello_policy = .{
            .require_server_name = true,
            .require_alpn = true,
            .allowed_server_names = allowed_server_names[0..],
            .allowed_alpn_protocols = allowed_alpn[0..],
        },
    });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 1, .correlation_id = 1 });

    const address = try std.net.Address.parseIp(cfg.host, cfg.port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    if (!try pollFd(server.stream.handle, std.posix.POLL.IN, cfg.timeout_ms)) {
        return error.Timeout;
    }

    var accepted = try server.accept();
    defer accepted.stream.close();

    try exchangeWithPeer(&conn, accepted.stream, cfg, trace);

    if (conn.engine.machine.state != .connected and conn.engine.machine.state != .closed) {
        return error.HandshakeNotCompleted;
    }

    std.debug.print(
        "interop-termination-server ok: state={s} sni={s} alpn={s}\n",
        .{
            @tagName(conn.engine.machine.state),
            conn.observedClientHelloServerName() orelse "-",
            conn.observedClientHelloAlpn() orelse "-",
        },
    );
}

fn usage() void {
    std.debug.print(
        "usage: interop-termination-server --port <u16> --cert <path> --key <path> [--host <ip>] [--sni <name>] [--alpn <proto>] [--timeout-ms <i32>] [--max-rounds <usize>]\n",
        .{},
    );
}

fn parseArgs(args: []const [:0]u8) !Config {
    var cfg = Config{};
    var i: usize = 1;
    while (i < args.len) {
        const arg: []const u8 = args[i][0..args[i].len];
        if (std.mem.eql(u8, arg, "--host")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.host = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.port = try std.fmt.parseInt(u16, args[i][0..args[i].len], 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.cert_path = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.key_path = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--sni")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.expected_sni = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.expected_alpn = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.timeout_ms = try std.fmt.parseInt(i32, args[i][0..args[i].len], 10);
        } else if (std.mem.eql(u8, arg, "--max-rounds")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.max_rounds = try std.fmt.parseInt(usize, args[i][0..args[i].len], 10);
        } else {
            return error.InvalidFlag;
        }
        i += 1;
    }

    if (cfg.port == 0 or cfg.cert_path.len == 0 or cfg.key_path.len == 0) {
        return error.MissingRequiredFlag;
    }
    return cfg;
}

fn exchangeWithPeer(conn: *termination.Connection, stream: std.net.Stream, cfg: Config, trace: bool) !void {
    var connected = false;
    var rounds: usize = 0;
    var ingress_buf: [256 * 1024]u8 = undefined;
    var ingress_len: usize = 0;
    var logged_handshake_keys = false;
    var logged_app_keys = false;
    while (rounds < cfg.max_rounds) : (rounds += 1) {
        var progressed = false;

        if (try pollFd(stream.handle, std.posix.POLL.IN, cfg.timeout_ms)) {
            var read_buf: [16 * 1024]u8 = undefined;
            const n = stream.read(&read_buf) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
            if (n == 0) {
                _ = conn.on_transport_eof() catch {};
                break;
            }
            if (trace) {
                std.debug.print("trace read: bytes={d}\n", .{n});
            }
            progressed = true;
            if (ingress_len + n > ingress_buf.len) return error.RecordOverflow;
            @memcpy(ingress_buf[ingress_len .. ingress_len + n], read_buf[0..n]);
            ingress_len += n;
            try ingestBufferedRecords(
                conn,
                ingress_buf[0..],
                &ingress_len,
                &progressed,
                trace,
                &logged_handshake_keys,
                &logged_app_keys,
            );
        }

        try flushPendingRecords(conn, stream, cfg.timeout_ms, &progressed, trace);

        if (conn.engine.machine.state == .connected) {
            connected = true;
        }

        if (connected and !progressed) break;
    }

    if (!connected) return error.HandshakeNotCompleted;

    _ = conn.shutdown() catch {};
    var progressed = false;
    try flushPendingRecords(conn, stream, cfg.timeout_ms, &progressed, trace);
}

fn ingestBufferedRecords(
    conn: *termination.Connection,
    ingress_buf: []u8,
    ingress_len: *usize,
    progressed: *bool,
    trace: bool,
    logged_handshake_keys: *bool,
    logged_app_keys: *bool,
) !void {
    while (true) {
        if (ingress_len.* < 5) return;
        const parsed = tls_record.parseRecord(ingress_buf[0..ingress_len.*]) catch |err| switch (err) {
            error.IncompleteHeader, error.IncompletePayload => return,
            else => return err,
        };
        const rec_len = 5 + parsed.payload.len;
        if (trace) {
            if (parsed.header.content_type == .handshake) {
                describeClientHelloMetadata(ingress_buf[0..rec_len]) catch {};
            } else if (parsed.header.content_type == .alert) {
                if (zigtls.tls13.alerts.Alert.decode(parsed.payload)) |alert| {
                    std.debug.print(
                        "trace peer alert: level={s} desc={s}\n",
                        .{ @tagName(alert.level), @tagName(alert.description) },
                    );
                } else |_| {}
            }
            std.debug.print(
                "trace ingest: type={s} ver=0x{x:0>4} len={d} state={s}\n",
                .{
                    @tagName(parsed.header.content_type),
                    parsed.header.legacy_version,
                    parsed.header.length,
                    @tagName(conn.engine.machine.state),
                },
            );
        }
        const out = try conn.ingest_tls_bytes_with_alert(ingress_buf[0..rec_len]);
        switch (out) {
            .ok => {
                if (trace) {
                    std.debug.print("trace ingest ok: state={s}\n", .{@tagName(conn.engine.machine.state)});
                }
                if (trace and !logged_handshake_keys.* and conn.engine.hs_key_len != 0) {
                    logged_handshake_keys.* = true;
                    const write_secret = conn.engine.handshake_write_secret orelse return error.MissingKeyExchangeSecret;
                    const read_secret = conn.engine.handshake_read_secret orelse return error.MissingKeyExchangeSecret;
                    const write_secret_bytes: []const u8 = switch (write_secret) {
                        .sha256 => |s| s[0..],
                        .sha384 => |s| s[0..],
                    };
                    const read_secret_bytes: []const u8 = switch (read_secret) {
                        .sha256 => |s| s[0..],
                        .sha384 => |s| s[0..],
                    };
                    std.debug.print(
                        "interop hs material: write_secret={x} read_secret={x} write_key={x} read_key={x} write_iv={x} read_iv={x}\n",
                        .{
                            write_secret_bytes,
                            read_secret_bytes,
                            conn.engine.hs_write_key[0..conn.engine.hs_key_len],
                            conn.engine.hs_read_key[0..conn.engine.hs_key_len],
                            conn.engine.hs_write_iv[0..],
                            conn.engine.hs_read_iv[0..],
                        },
                    );
                }
                if (trace and !logged_app_keys.* and conn.engine.app_key_len != 0) {
                    logged_app_keys.* = true;
                    const write_secret = conn.engine.app_write_secret orelse return error.ApplicationCipherNotReady;
                    const read_secret = conn.engine.app_read_secret orelse return error.ApplicationCipherNotReady;
                    const write_secret_bytes: []const u8 = switch (write_secret) {
                        .sha256 => |s| s[0..],
                        .sha384 => |s| s[0..],
                    };
                    const read_secret_bytes: []const u8 = switch (read_secret) {
                        .sha256 => |s| s[0..],
                        .sha384 => |s| s[0..],
                    };
                    std.debug.print(
                        "interop app material: write_secret={x} read_secret={x} write_key={x} read_key={x} write_iv={x} read_iv={x}\n",
                        .{
                            write_secret_bytes,
                            read_secret_bytes,
                            conn.engine.app_write_key[0..conn.engine.app_key_len],
                            conn.engine.app_read_key[0..conn.engine.app_key_len],
                            conn.engine.app_write_iv[0..],
                            conn.engine.app_read_iv[0..],
                        },
                    );
                }
            },
            .fatal => |fatal| {
                std.debug.print(
                    "interop fatal: err={s} alert={s}\n",
                    .{ @errorName(fatal.err), @tagName(fatal.alert.description) },
                );
                return error.PeerFatalAlert;
            },
        }

        progressed.* = true;
        if (rec_len < ingress_len.*) {
            const remain = ingress_len.* - rec_len;
            std.mem.copyForwards(u8, ingress_buf[0..remain], ingress_buf[rec_len..ingress_len.*]);
            ingress_len.* = remain;
            continue;
        }
        ingress_len.* = 0;
        return;
    }
}

fn describeClientHelloMetadata(record_bytes: []const u8) !void {
    const parsed = try tls_record.parseRecord(record_bytes);
    if (parsed.header.content_type != .handshake) return error.NotClientHello;
    const hs = try tls_handshake.parseOne(parsed.payload);
    if (hs.header.handshake_type != .client_hello) return error.NotClientHello;
    var fba_buf: [32 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const allocator = fba.allocator();
    var hello = try tls_messages.ClientHello.decode(allocator, hs.body);
    defer hello.deinit(allocator);
    const key_share = findExtension(hello.extensions, 0x0033) orelse return error.NotClientHello;
    const x25519_pub = try extractX25519FromClientKeyShare(key_share);
    var ks_buf: [256]u8 = undefined;
    const ks_desc = try formatKeyShareEntries(key_share, &ks_buf);
    std.debug.print(
        "trace clienthello: random={x} x25519_pub={x} key_shares={s}\n",
        .{ hello.random, x25519_pub, ks_desc },
    );
}

fn findExtension(exts: []const tls_messages.Extension, ext_type: u16) ?[]const u8 {
    for (exts) |ext| {
        if (ext.extension_type == ext_type) return ext.data;
    }
    return null;
}

fn extractX25519FromClientKeyShare(data: []const u8) ![32]u8 {
    if (data.len < 2) return error.InvalidKeyShareExtension;
    const vec_len = readU16(data[0..2]);
    if (@as(usize, vec_len) + 2 != data.len) return error.InvalidKeyShareExtension;
    var i: usize = 2;
    while (i < data.len) {
        if (i + 4 > data.len) return error.InvalidKeyShareExtension;
        const group = readU16(data[i .. i + 2]);
        const key_len = readU16(data[i + 2 .. i + 4]);
        i += 4;
        if (i + key_len > data.len) return error.InvalidKeyShareExtension;
        if (group == 0x001d) {
            if (key_len != 32) return error.InvalidKeyShareExtension;
            var out: [32]u8 = undefined;
            @memcpy(&out, data[i .. i + key_len]);
            return out;
        }
        i += key_len;
    }
    return error.InvalidKeyShareExtension;
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn formatKeyShareEntries(data: []const u8, out_buf: []u8) ![]const u8 {
    if (data.len < 2) return error.InvalidKeyShareExtension;
    const vec_len = readU16(data[0..2]);
    if (@as(usize, vec_len) + 2 != data.len) return error.InvalidKeyShareExtension;
    var i: usize = 2;
    var w: usize = 0;
    while (i < data.len) {
        if (i + 4 > data.len) return error.InvalidKeyShareExtension;
        const group = readU16(data[i .. i + 2]);
        const key_len = readU16(data[i + 2 .. i + 4]);
        i += 4;
        if (i + key_len > data.len) return error.InvalidKeyShareExtension;
        const n = try std.fmt.bufPrint(out_buf[w..], "{s}0x{x:0>4}/{d}", .{
            if (w == 0) "" else ",",
            group,
            key_len,
        });
        w += n.len;
        i += key_len;
    }
    return out_buf[0..w];
}

fn flushPendingRecords(
    conn: *termination.Connection,
    stream: std.net.Stream,
    timeout_ms: i32,
    progressed: *bool,
    trace: bool,
) !void {
    var frame_buf: [65_540]u8 = undefined;
    while (true) {
        const n = conn.drain_tls_records(&frame_buf) catch |err| switch (err) {
            error.OutputBufferTooSmall => unreachable,
            else => return err,
        };
        if (n == 0) break;
        if (trace and n >= 5) {
            const hdr = tls_record.parseHeader(frame_buf[0..5]) catch null;
            if (hdr) |h| {
                std.debug.print(
                    "trace drain: type={s} ver=0x{x:0>4} len={d} state={s}\n",
                    .{
                        @tagName(h.content_type),
                        h.legacy_version,
                        h.length,
                        @tagName(conn.engine.machine.state),
                    },
                );
                if (h.content_type == .handshake and n > 5) {
                    std.debug.print("trace drain handshake-bytes={x}\n", .{frame_buf[5..n]});
                }
            } else {
                std.debug.print("trace drain: bytes={d} state={s}\n", .{ n, @tagName(conn.engine.machine.state) });
            }
        }
        progressed.* = true;
        try writeAllPolling(stream, frame_buf[0..n], timeout_ms);
    }
}

fn writeAllPolling(stream: std.net.Stream, bytes: []const u8, timeout_ms: i32) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        if (!try pollFd(stream.handle, std.posix.POLL.OUT, timeout_ms)) return error.Timeout;
        const n = stream.write(bytes[written..]) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (n == 0) return error.Timeout;
        written += n;
    }
}

fn pollFd(fd: std.posix.fd_t, events: i16, timeout_ms: i32) !bool {
    var fds = [_]std.posix.pollfd{
        .{
            .fd = fd,
            .events = events,
            .revents = 0,
        },
    };
    const n = try std.posix.poll(&fds, timeout_ms);
    return n > 0 and (fds[0].revents & events) != 0;
}
