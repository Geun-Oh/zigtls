const std = @import("std");
const termination = @import("termination.zig");
const tls13 = @import("tls13.zig");

pub const TransportReadFn = *const fn (userdata: usize, out: []u8) anyerror!usize;
pub const TransportWriteFn = *const fn (userdata: usize, bytes: []const u8) anyerror!usize;

pub const Transport = struct {
    userdata: usize,
    read_fn: TransportReadFn,
    write_fn: TransportWriteFn,
};

pub const Error = anyerror;

pub const PumpResult = struct {
    read_events: usize = 0,
    bytes_read: usize = 0,
    bytes_written: usize = 0,
    would_block: bool = false,
};

pub const EventLoopAdapter = struct {
    const max_pending_read_bytes = (5 + tls13.record.max_ciphertext) * 4;

    conn: *termination.Connection,
    transport: Transport,
    pending_read_buf: [max_pending_read_bytes]u8 = undefined,
    pending_read_off: usize = 0,
    pending_read_len: usize = 0,
    pending_write_buf: [65_540]u8 = undefined,
    pending_write_len: usize = 0,
    pending_write_off: usize = 0,

    pub fn init(allocator: std.mem.Allocator, conn: *termination.Connection, transport: Transport) EventLoopAdapter {
        _ = allocator;
        return .{
            .conn = conn,
            .transport = transport,
        };
    }

    pub fn deinit(_: *EventLoopAdapter) void {}

    pub fn pumpRead(self: *EventLoopAdapter, max_iters: usize) Error!PumpResult {
        var out = PumpResult{};
        var i: usize = 0;
        var read_buf: [4096]u8 = undefined;

        while (i < max_iters) : (i += 1) {
            const n = self.transport.read_fn(self.transport.userdata, &read_buf) catch |err| {
                if (err == error.WouldBlock) {
                    out.would_block = true;
                    break;
                }
                return err;
            };
            if (n == 0) {
                try self.conn.on_transport_eof();
                break;
            }

            out.read_events += 1;
            out.bytes_read += n;
            try self.appendPendingRead(read_buf[0..n]);
            try self.processPendingRead();
        }

        return out;
    }

    pub fn flushWrite(self: *EventLoopAdapter, max_iters: usize) Error!PumpResult {
        var out = PumpResult{};
        var i: usize = 0;
        while (i < max_iters) : (i += 1) {
            if (self.pending_write_len == 0) {
                const n = try self.conn.drain_tls_records(&self.pending_write_buf);
                if (n == 0) break;
                self.pending_write_len = n;
                self.pending_write_off = 0;
            }

            const slice = self.pending_write_buf[self.pending_write_off..self.pending_write_len];
            const written = self.transport.write_fn(self.transport.userdata, slice) catch |err| {
                if (err == error.WouldBlock) {
                    out.would_block = true;
                    break;
                }
                return err;
            };
            if (written == 0) {
                out.would_block = true;
                break;
            }
            out.bytes_written += written;
            self.pending_write_off += written;
            if (self.pending_write_off >= self.pending_write_len) {
                self.clearPendingWrite();
            }
        }
        return out;
    }

    fn clearPendingWrite(self: *EventLoopAdapter) void {
        self.pending_write_len = 0;
        self.pending_write_off = 0;
    }

    fn appendPendingRead(self: *EventLoopAdapter, chunk: []const u8) Error!void {
        if (chunk.len == 0) return;
        if (self.pending_read_off + self.pending_read_len + chunk.len > self.pending_read_buf.len) {
            if (self.pending_read_len > 0) {
                const src = self.pending_read_buf[self.pending_read_off .. self.pending_read_off + self.pending_read_len];
                std.mem.copyForwards(u8, self.pending_read_buf[0..self.pending_read_len], src);
            }
            self.pending_read_off = 0;
        }
        if (self.pending_read_off + self.pending_read_len + chunk.len > self.pending_read_buf.len) {
            return error.ReadBufferOverflow;
        }

        const dst_start = self.pending_read_off + self.pending_read_len;
        @memcpy(self.pending_read_buf[dst_start .. dst_start + chunk.len], chunk);
        self.pending_read_len += chunk.len;
    }

    fn processPendingRead(self: *EventLoopAdapter) Error!void {
        while (self.pending_read_len > 0) {
            if (self.pending_read_len < 5) break;

            const pending = self.pending_read_buf[self.pending_read_off .. self.pending_read_off + self.pending_read_len];
            const header = tls13.record.parseHeader(pending[0..5]) catch |err| switch (err) {
                error.IncompleteHeader => break,
                else => {
                    const ingest = try self.conn.ingest_tls_bytes_with_alert(pending);
                    switch (ingest) {
                        .ok => {
                            self.pending_read_off = 0;
                            self.pending_read_len = 0;
                            return;
                        },
                        .fatal => return error.FatalAlert,
                    }
                },
            };

            const record_len: usize = 5 + @as(usize, header.length);
            if (pending.len < record_len) break;

            const ingest = try self.conn.ingest_tls_bytes_with_alert(pending[0..record_len]);
            switch (ingest) {
                .ok => {},
                .fatal => return error.FatalAlert,
            }
            self.pending_read_off += record_len;
            self.pending_read_len -= record_len;
            if (self.pending_read_len == 0) {
                self.pending_read_off = 0;
            }
        }
    }
};

const MockTransport = struct {
    allocator: std.mem.Allocator,
    read_chunks: [4][]const u8 = [_][]const u8{ &.{}, &.{}, &.{}, &.{} },
    read_count: usize = 0,
    read_idx: usize = 0,
    writes: std.ArrayList(u8) = .empty,
    max_write_chunk: usize = std.math.maxInt(usize),
    read_would_block: bool = true,

    fn init(allocator: std.mem.Allocator) MockTransport {
        return .{
            .allocator = allocator,
        };
    }

    fn deinit(self: *MockTransport) void {
        self.writes.deinit(self.allocator);
    }

    fn asTransport(self: *MockTransport) Transport {
        return .{
            .userdata = @intFromPtr(self),
            .read_fn = readFn,
            .write_fn = writeFn,
        };
    }

    fn readFn(userdata: usize, out: []u8) anyerror!usize {
        var self: *MockTransport = @ptrFromInt(userdata);
        if (self.read_idx < self.read_count) {
            const chunk = self.read_chunks[self.read_idx];
            self.read_idx += 1;
            if (chunk.len > out.len) return error.NoSpaceLeft;
            @memcpy(out[0..chunk.len], chunk);
            return chunk.len;
        }
        if (self.read_would_block) return error.WouldBlock;
        return 0;
    }

    fn writeFn(userdata: usize, bytes: []const u8) anyerror!usize {
        var self: *MockTransport = @ptrFromInt(userdata);
        const n = @min(bytes.len, self.max_write_chunk);
        if (n == 0) return error.WouldBlock;
        try self.writes.appendSlice(self.allocator, bytes[0..n]);
        return n;
    }
};

test "flushWrite handles partial writes with reentry safety" {
    var conn = termination.Connection.init(std.testing.allocator, .{
        .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});
    conn.engine.machine.state = .connected;
    // Seed application traffic keys for write path; fail-closed key-schedule now
    // rejects connected writes without traffic secret material.
    @memset(conn.engine.app_write_key[0..16], 0x11);
    @memset(conn.engine.app_write_iv[0..12], 0x22);
    conn.engine.app_key_len = 16;
    conn.engine.app_tag_len = 16;
    _ = try conn.write_plaintext("hello");

    var mock = MockTransport.init(std.testing.allocator);
    defer mock.deinit();
    mock.max_write_chunk = 2;

    var adapter = EventLoopAdapter.init(std.testing.allocator, &conn, mock.asTransport());
    defer adapter.deinit();

    const r1 = try adapter.flushWrite(1);
    try std.testing.expectEqual(@as(usize, 2), r1.bytes_written);
    try std.testing.expect(adapter.pending_write_len > 0);

    _ = try adapter.flushWrite(16);
    try std.testing.expect(mock.writes.items.len >= 5);
    try std.testing.expectEqual(@as(u8, 23), mock.writes.items[0]);
    const payload_len = std.mem.readInt(u16, mock.writes.items[3..5], .big);
    try std.testing.expectEqual(mock.writes.items.len, 5 + payload_len);
    try std.testing.expectEqual(@as(usize, 0), adapter.pending_write_len);
}

test "pumpRead consumes readable chunks then returns WouldBlock" {
    var conn = termination.Connection.init(std.testing.allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});

    var mock = MockTransport.init(std.testing.allocator);
    defer mock.deinit();
    mock.read_chunks[0] = &.{ 22, 3, 3, 0, 0 };
    mock.read_count = 1;
    mock.read_would_block = true;

    var adapter = EventLoopAdapter.init(std.testing.allocator, &conn, mock.asTransport());
    defer adapter.deinit();

    const out = try adapter.pumpRead(8);
    try std.testing.expectEqual(@as(usize, 1), out.read_events);
    try std.testing.expectEqual(@as(usize, 5), out.bytes_read);
    try std.testing.expect(out.would_block);
}

test "pumpRead reassembles fragmented alert record across reads" {
    var conn = termination.Connection.init(std.testing.allocator, .{
        .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});

    const close_notify = tls13.session.Engine.buildAlertRecord(.{
        .level = .warning,
        .description = .close_notify,
    });

    var mock = MockTransport.init(std.testing.allocator);
    defer mock.deinit();
    mock.read_chunks[0] = close_notify[0..3];
    mock.read_chunks[1] = close_notify[3..];
    mock.read_count = 2;
    mock.read_would_block = true;

    var adapter = EventLoopAdapter.init(std.testing.allocator, &conn, mock.asTransport());
    defer adapter.deinit();

    const out = try adapter.pumpRead(8);
    try std.testing.expectEqual(@as(usize, 2), out.read_events);
    try std.testing.expectEqual(@as(usize, close_notify.len), out.bytes_read);
    try std.testing.expect(out.would_block);
    try std.testing.expectEqual(@as(usize, 0), adapter.pending_read_len);
    try std.testing.expect(conn.engine.machine.state == .closed);
}

test "pumpRead handles full record plus partial next record in one chunk" {
    var conn = termination.Connection.init(std.testing.allocator, .{
        .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{});

    const close_notify = tls13.session.Engine.buildAlertRecord(.{
        .level = .warning,
        .description = .close_notify,
    });
    const user_cancel = tls13.session.Engine.buildAlertRecord(.{
        .level = .fatal,
        .description = .user_canceled,
    });

    var chunk: [12]u8 = undefined;
    @memcpy(chunk[0..7], close_notify[0..]);
    @memcpy(chunk[7..12], user_cancel[0..5]);

    var mock = MockTransport.init(std.testing.allocator);
    defer mock.deinit();
    mock.read_chunks[0] = chunk[0..];
    mock.read_chunks[1] = user_cancel[5..];
    mock.read_count = 2;
    mock.read_would_block = true;

    var adapter = EventLoopAdapter.init(std.testing.allocator, &conn, mock.asTransport());
    defer adapter.deinit();

    const out = try adapter.pumpRead(8);
    try std.testing.expectEqual(@as(usize, 2), out.read_events);
    try std.testing.expectEqual(@as(usize, chunk.len + user_cancel.len - 5), out.bytes_read);
    try std.testing.expect(out.would_block);
    try std.testing.expectEqual(@as(usize, 0), adapter.pending_read_len);
    try std.testing.expectEqual(@as(u64, 2), conn.snapshot_metrics().alerts_received);
}
