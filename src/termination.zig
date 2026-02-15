const std = @import("std");
const tls13 = @import("tls13.zig");

pub const Config = struct {
    session: tls13.session.Config,
};

pub const ConnectionContext = struct {
    connection_id: u64 = 0,
};

pub const Error = error{
    NotAccepted,
    OutputBufferTooSmall,
    UnsupportedOperation,
} || tls13.session.EngineError || std.mem.Allocator.Error;

const PendingRecord = struct {
    buf: [16]u8 = undefined,
    len: usize = 0,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    engine: tls13.session.Engine,
    accepted: bool = false,
    pending_records: [4]PendingRecord = [_]PendingRecord{.{}} ** 4,
    pending_record_count: usize = 0,
    pending_plaintext: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator, config: Config) Connection {
        return .{
            .allocator = allocator,
            .engine = tls13.session.Engine.init(allocator, config.session),
            .pending_plaintext = .empty,
        };
    }

    pub fn deinit(self: *Connection) void {
        self.engine.deinit();
        self.pending_plaintext.deinit(self.allocator);
    }

    pub fn accept(self: *Connection, _: ConnectionContext) void {
        self.accepted = true;
    }

    pub fn ingest_tls_bytes(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestResult {
        if (!self.accepted) return error.NotAccepted;
        const result = try self.engine.ingestRecord(record_bytes);
        try self.collectActions(result);
        return result;
    }

    pub fn ingest_tls_bytes_with_alert(self: *Connection, record_bytes: []const u8) Error!tls13.session.IngestWithAlertOutcome {
        if (!self.accepted) return error.NotAccepted;
        const out = self.engine.ingestRecordWithAlertIntent(record_bytes);
        switch (out) {
            .ok => |res| {
                try self.collectActions(res);
                return .{ .ok = res };
            },
            .fatal => return out,
        }
    }

    pub fn drain_tls_records(self: *Connection, out: []u8) Error!usize {
        if (self.pending_record_count == 0) return 0;

        const first = self.pending_records[0];
        if (out.len < first.len) return error.OutputBufferTooSmall;

        @memcpy(out[0..first.len], first.buf[0..first.len]);
        self.shiftPendingRecordsLeft();
        return first.len;
    }

    pub fn read_plaintext(self: *Connection, out: []u8) usize {
        if (self.pending_plaintext.items.len == 0 or out.len == 0) return 0;

        const n = @min(out.len, self.pending_plaintext.items.len);
        @memcpy(out[0..n], self.pending_plaintext.items[0..n]);
        if (n == self.pending_plaintext.items.len) {
            self.pending_plaintext.clearRetainingCapacity();
        } else {
            _ = self.pending_plaintext.orderedRemoveRange(0, n);
        }
        return n;
    }

    pub fn write_plaintext(_: *Connection, _: []const u8) Error!usize {
        return error.UnsupportedOperation;
    }

    pub fn shutdown(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        const frame = tls13.session.Engine.buildAlertRecord(.{ .level = .warning, .description = .close_notify });
        try self.pushPendingRecord(frame[0..]);
        self.engine.machine.markClosed();
    }

    pub fn on_transport_eof(self: *Connection) Error!void {
        if (!self.accepted) return error.NotAccepted;
        try self.engine.onTransportEof();
    }

    pub fn snapshot_metrics(self: Connection) tls13.session.Metrics {
        return self.engine.snapshotMetrics();
    }

    fn collectActions(self: *Connection, result: tls13.session.IngestResult) Error!void {
        var i: usize = 0;
        while (i < result.action_count) : (i += 1) {
            switch (result.actions[i]) {
                .send_alert => |alert| {
                    const frame = tls13.session.Engine.buildAlertRecord(alert);
                    try self.pushPendingRecord(frame[0..]);
                },
                .send_key_update => |req| {
                    const frame = tls13.session.Engine.buildKeyUpdateRecord(req);
                    try self.pushPendingRecord(frame[0..]);
                },
                .application_data => |data| {
                    try self.pending_plaintext.appendSlice(self.allocator, data);
                },
                else => {},
            }
        }
    }

    fn pushPendingRecord(self: *Connection, bytes: []const u8) Error!void {
        if (bytes.len > self.pending_records[0].buf.len) return error.OutputBufferTooSmall;
        if (self.pending_record_count >= self.pending_records.len) return error.OutputBufferTooSmall;

        self.pending_records[self.pending_record_count].len = bytes.len;
        @memcpy(self.pending_records[self.pending_record_count].buf[0..bytes.len], bytes);
        self.pending_record_count += 1;
    }

    fn shiftPendingRecordsLeft(self: *Connection) void {
        if (self.pending_record_count == 0) return;
        var i: usize = 1;
        while (i < self.pending_record_count) : (i += 1) {
            self.pending_records[i - 1] = self.pending_records[i];
        }
        self.pending_record_count -= 1;
    }
};

test "connection requires accept before ingest" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();

    try std.testing.expectError(error.NotAccepted, conn.ingest_tls_bytes(&.{ 22, 3, 3, 0, 0 }));
}

test "shutdown enqueues close_notify record and can be drained" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{ .connection_id = 1 });

    try conn.shutdown();

    var out: [16]u8 = undefined;
    const n = try conn.drain_tls_records(&out);
    try std.testing.expectEqual(@as(usize, 7), n);
    try std.testing.expectEqual(@as(u8, 21), out[0]);
    try std.testing.expectEqual(@as(u8, 1), out[5]);
    try std.testing.expectEqual(@as(u8, 0), out[6]);
}

test "write plaintext is explicit unsupported operation" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{});

    try std.testing.expectError(error.UnsupportedOperation, conn.write_plaintext("ping"));
}

test "ingest with alert intent maps invalid record to fatal outcome" {
    var conn = Connection.init(std.testing.allocator, .{ .session = .{ .role = .client, .suite = .tls_aes_128_gcm_sha256 } });
    defer conn.deinit();
    conn.accept(.{});

    const out = try conn.ingest_tls_bytes_with_alert(&.{22, 3, 4, 0, 0});
    switch (out) {
        .fatal => |f| {
            try std.testing.expectEqual(error.InvalidLegacyVersion, f.err);
            try std.testing.expectEqual(tls13.alerts.AlertDescription.protocol_version, f.alert.description);
        },
        else => return error.TestUnexpectedResult,
    }
}
