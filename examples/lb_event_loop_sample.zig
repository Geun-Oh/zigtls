const std = @import("std");
const zigtls = @import("zigtls");

const cert_reload = zigtls.cert_reload;
const termination = zigtls.termination;
const tls_record = zigtls.tls13.record;

const Config = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8443,
    cert_path: []const u8 = "certs/server-cert.pem",
    key_path: []const u8 = "certs/server-key.pem",
    sni: []const u8 = "localhost",
    alpn: []const u8 = "http/1.1",
    timeout_ms: i32 = 5000,
    max_rounds: usize = 512,
};

const default_config = Config{
    .host = "127.0.0.1",
    .port = 8443,
    .cert_path = "certs/server-cert.pem",
    .key_path = "certs/server-key.pem",
    .sni = "localhost",
    .alpn = "http/1.1",
    .timeout_ms = 5000,
    .max_rounds = 512,
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

    var cfg = default_config;
    if (args.len > 1) {
        if (args.len == 2 and std.mem.eql(u8, args[1], "--help")) {
            usage();
            return;
        }
        cfg = try parseArgs(args, cfg);
    }

    var store = cert_reload.Store.init(allocator);
    defer store.deinit();
    _ = try store.reloadFromFiles(cfg.cert_path, cfg.key_path);

    const address = try std.net.Address.parseIp(cfg.host, cfg.port);
    var server = try address.listen(.{ .reuse_address = true });
    defer server.deinit();

    std.debug.print("listening on https://{s}:{d}\n", .{ cfg.host, cfg.port });
    var connection_id: u64 = 0;
    while (true) {
        var accepted = try server.accept();
        connection_id += 1;

        handleOneConnection(allocator, accepted.stream, &store, cfg) catch |err| {
            std.debug.print("connection #{d} failed: {s}\n", .{ connection_id, @errorName(err) });
            accepted.stream.close();
            continue;
        };

        accepted.stream.close();
        std.debug.print("connection #{d} handled and closed\n", .{connection_id});
    }
}

fn usage() void {
    std.debug.print(
        "usage: zigtls_test [--host <ip>] [--port <u16>] [--cert <path>] [--key <path>] [--sni <name>] [--alpn <proto>] [--timeout-ms <i32>] [--max-rounds <usize>]\n" ++
            "default: --host 127.0.0.1 --port 8443 --cert certs/server-cert.pem --key certs/server-key.pem --sni localhost --alpn http/1.1 --timeout-ms 5000 --max-rounds 512\n",
        .{},
    );
}

fn parseArgs(args: []const [:0]u8, base: Config) !Config {
    var cfg = base;
    var i: usize = 1;
    while (i < args.len) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--host")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.host = args[i];
        } else if (std.mem.eql(u8, arg, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.cert_path = args[i];
        } else if (std.mem.eql(u8, arg, "--key")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.key_path = args[i];
        } else if (std.mem.eql(u8, arg, "--sni")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.sni = args[i];
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.alpn = args[i];
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.timeout_ms = try std.fmt.parseInt(i32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--max-rounds")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            cfg.max_rounds = try std.fmt.parseInt(usize, args[i], 10);
        } else {
            return error.InvalidFlag;
        }
        i += 1;
    }
    return cfg;
}

fn handleOneConnection(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
    store: *cert_reload.Store,
    cfg: Config,
) !void {
    var allowed_server_names = [_][]const u8{cfg.sni};
    var allowed_alpn = [_][]const u8{cfg.alpn};

    var conn = try termination.Connection.initChecked(allocator, .{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
        },
        .dynamic_server_credentials = .{
            .store = store,
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

    var ingress_buf: [256 * 1024]u8 = undefined;
    var ingress_len: usize = 0;
    var plaintext_buf: [16 * 1024]u8 = undefined;
    var req_buf: [16 * 1024]u8 = undefined;
    var req_len: usize = 0;
    var response_sent = false;

    var rounds: usize = 0;
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
            if (ingress_len + n > ingress_buf.len) return error.IngressOverflow;
            @memcpy(ingress_buf[ingress_len .. ingress_len + n], read_buf[0..n]);
            ingress_len += n;
            ingestBufferedRecords(&conn, ingress_buf[0..], &ingress_len, &progressed) catch |err| switch (err) {
                error.PeerFatalAlert => {
                    if (response_sent) break;
                    return err;
                },
                else => return err,
            };
        }

        const plain_n = conn.read_plaintext(&plaintext_buf);
        if (plain_n > 0 and !response_sent) {
            progressed = true;
            const chunk = plaintext_buf[0..plain_n];
            if (req_len + chunk.len > req_buf.len) return error.RequestTooLarge;
            @memcpy(req_buf[req_len .. req_len + chunk.len], chunk);
            req_len += chunk.len;

            if (std.mem.indexOf(u8, req_buf[0..req_len], "\r\n\r\n") != null) {
                const body = "hello from zigtls termination\n";
                const response = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 29\r\nconnection: close\r\n\r\n" ++ body;
                _ = try conn.write_plaintext(response);
                try conn.shutdown();
                response_sent = true;
            }
        }

        try flushPendingRecords(&conn, stream, cfg.timeout_ms, &progressed);

        if (response_sent and !progressed) break;
    }
}

fn ingestBufferedRecords(
    conn: *termination.Connection,
    ingress_buf: []u8,
    ingress_len: *usize,
    progressed: *bool,
) !void {
    while (true) {
        if (ingress_len.* < 5) return;

        const parsed = tls_record.parseRecord(ingress_buf[0..ingress_len.*]) catch |err| switch (err) {
            error.IncompleteHeader, error.IncompletePayload => return,
            else => return err,
        };
        const rec_len = 5 + parsed.payload.len;

        const out = try conn.ingest_tls_bytes_with_alert(ingress_buf[0..rec_len]);
        switch (out) {
            .ok => {},
            .fatal => return error.PeerFatalAlert,
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

fn flushPendingRecords(
    conn: *termination.Connection,
    stream: std.net.Stream,
    timeout_ms: i32,
    progressed: *bool,
) !void {
    var frame_buf: [65_540]u8 = undefined;
    while (true) {
        const n = conn.drain_tls_records(&frame_buf) catch |err| switch (err) {
            error.OutputBufferTooSmall => unreachable,
            else => return err,
        };
        if (n == 0) break;
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
