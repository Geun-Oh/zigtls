const std = @import("std");
const termination = @import("termination.zig");

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
    conn: *termination.Connection,
    transport: Transport,
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

    pub fn deinit(_: *EventLoopAdapter) void {
    }

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
            const ingest = try self.conn.ingest_tls_bytes_with_alert(read_buf[0..n]);
            switch (ingest) {
                .ok => {},
                .fatal => return error.FatalAlert,
            }
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
};

const MockTransport = struct {
    allocator: std.mem.Allocator,
    read_chunks: [4][]const u8 = [_][]const u8{&.{}, &.{}, &.{}, &.{}},
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
    const expected = [_]u8{ 23, 3, 3, 0, 5, 'h', 'e', 'l', 'l', 'o' };
    try std.testing.expectEqualSlices(u8, &expected, mock.writes.items);
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
