const std = @import("std");
const zigtls = @import("zigtls");

const termination = zigtls.termination;
const adapter = zigtls.adapter;

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

    var conn = termination.Connection.init(allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 1001, .correlation_id = 90001 });

    _ = try conn.write_plaintext("lb->client");

    var mock = MockTransport.init(allocator);
    defer mock.deinit();

    var loop = adapter.EventLoopAdapter.init(allocator, &conn, mock.asTransport());
    defer loop.deinit();

    const flush = try loop.flushWrite(16);
    if (flush.bytes_written == 0) return error.NoWriteProgress;

    if (mock.writes.items.len < 5) return error.InvalidRecordSize;
    const payload_len = std.mem.readInt(u16, mock.writes.items[3..5], .big);
    if (mock.writes.items.len != 5 + payload_len) return error.RecordLengthMismatch;
    if (mock.writes.items[0] != 23) return error.UnexpectedRecordType;

    const read = try loop.pumpRead(4);
    if (!read.would_block) return error.ExpectedWouldBlock;

    std.debug.print(
        "lb-sample ok: bytes_written={d} payload_len={d} correlation_id={d}\n",
        .{ flush.bytes_written, payload_len, conn.correlation_id },
    );
}
