const std = @import("std");

pub const LatencyHistogram = struct {
    // <= 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1000ms, +Inf
    bucket_bounds_ns: [9]u64 = .{
        std.time.ns_per_ms * 1,
        std.time.ns_per_ms * 5,
        std.time.ns_per_ms * 10,
        std.time.ns_per_ms * 25,
        std.time.ns_per_ms * 50,
        std.time.ns_per_ms * 100,
        std.time.ns_per_ms * 250,
        std.time.ns_per_ms * 500,
        std.time.ns_per_ms * 1000,
    },
    bucket_counts: [10]u64 = [_]u64{0} ** 10,

    pub fn observe(self: *LatencyHistogram, latency_ns: u64) void {
        for (self.bucket_bounds_ns, 0..) |bound, idx| {
            if (latency_ns <= bound) {
                self.bucket_counts[idx] += 1;
                return;
            }
        }
        self.bucket_counts[self.bucket_counts.len - 1] += 1;
    }

    pub fn total(self: LatencyHistogram) u64 {
        var sum: u64 = 0;
        for (self.bucket_counts) |count| sum += count;
        return sum;
    }

    pub fn quantileUpperBoundNs(self: LatencyHistogram, q: f64) ?u64 {
        if (!(q > 0 and q <= 1.0)) return null;
        const t = self.total();
        if (t == 0) return null;

        const target = @as(u64, @intFromFloat(@ceil(@as(f64, @floatFromInt(t)) * q)));
        var cumulative: u64 = 0;
        for (self.bucket_counts, 0..) |count, idx| {
            cumulative += count;
            if (cumulative < target) continue;
            if (idx < self.bucket_bounds_ns.len) return self.bucket_bounds_ns[idx];
            return self.bucket_bounds_ns[self.bucket_bounds_ns.len - 1];
        }
        return self.bucket_bounds_ns[self.bucket_bounds_ns.len - 1];
    }
};

pub const Metrics = struct {
    handshake_started: u64 = 0,
    handshake_success: u64 = 0,
    handshake_fail: u64 = 0,
    resume_hit: u64 = 0,
    resume_miss: u64 = 0,
    early_data_accept: u64 = 0,
    early_data_reject: u64 = 0,
    keyupdate_count: u64 = 0,
    alert_counts: [256]u64 = [_]u64{0} ** 256,
    handshake_latency: LatencyHistogram = .{},

    pub fn observeHandshakeStart(self: *Metrics) void {
        self.handshake_started += 1;
    }

    pub fn observeHandshakeFinished(self: *Metrics, success: bool, latency_ns: u64) void {
        if (success) {
            self.handshake_success += 1;
        } else {
            self.handshake_fail += 1;
        }
        self.handshake_latency.observe(latency_ns);
    }

    pub fn observeAlert(self: *Metrics, alert_description: u8) void {
        self.alert_counts[alert_description] += 1;
    }

    pub fn observeResume(self: *Metrics, hit: bool) void {
        if (hit) {
            self.resume_hit += 1;
        } else {
            self.resume_miss += 1;
        }
    }

    pub fn observeEarlyData(self: *Metrics, accepted: bool) void {
        if (accepted) {
            self.early_data_accept += 1;
        } else {
            self.early_data_reject += 1;
        }
    }

    pub fn observeKeyUpdate(self: *Metrics) void {
        self.keyupdate_count += 1;
    }

    pub fn exportPrometheus(self: Metrics, allocator: std.mem.Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        const w = out.writer(allocator);

        try w.print("zigtls_handshake_started_total {d}\n", .{self.handshake_started});
        try w.print("zigtls_handshake_success_total {d}\n", .{self.handshake_success});
        try w.print("zigtls_handshake_fail_total {d}\n", .{self.handshake_fail});
        try w.print("zigtls_resume_hit_total {d}\n", .{self.resume_hit});
        try w.print("zigtls_resume_miss_total {d}\n", .{self.resume_miss});
        try w.print("zigtls_early_data_accept_total {d}\n", .{self.early_data_accept});
        try w.print("zigtls_early_data_reject_total {d}\n", .{self.early_data_reject});
        try w.print("zigtls_keyupdate_total {d}\n", .{self.keyupdate_count});

        var alert_idx: usize = 0;
        while (alert_idx < self.alert_counts.len) : (alert_idx += 1) {
            const count = self.alert_counts[alert_idx];
            if (count == 0) continue;
            try w.print("zigtls_alert_total{{code=\"{d}\"}} {d}\n", .{ alert_idx, count });
        }

        var cumulative: u64 = 0;
        for (self.handshake_latency.bucket_counts, 0..) |count, idx| {
            cumulative += count;
            if (idx < self.handshake_latency.bucket_bounds_ns.len) {
                try w.print(
                    "zigtls_handshake_latency_bucket{{le=\"{d}\"}} {d}\n",
                    .{ self.handshake_latency.bucket_bounds_ns[idx], cumulative },
                );
            } else {
                try w.print("zigtls_handshake_latency_bucket{{le=\"+Inf\"}} {d}\n", .{cumulative});
            }
        }
        try w.print("zigtls_handshake_latency_count {d}\n", .{self.handshake_latency.total()});

        if (self.handshake_latency.quantileUpperBoundNs(0.50)) |v| {
            try w.print("zigtls_handshake_latency_p50_ns {d}\n", .{v});
        }
        if (self.handshake_latency.quantileUpperBoundNs(0.95)) |v| {
            try w.print("zigtls_handshake_latency_p95_ns {d}\n", .{v});
        }
        if (self.handshake_latency.quantileUpperBoundNs(0.99)) |v| {
            try w.print("zigtls_handshake_latency_p99_ns {d}\n", .{v});
        }

        return out.toOwnedSlice(allocator);
    }
};

test "metrics counters and histogram quantiles are tracked" {
    var m = Metrics{};
    m.observeHandshakeStart();
    m.observeHandshakeFinished(true, std.time.ns_per_ms * 6);
    m.observeHandshakeFinished(false, std.time.ns_per_ms * 200);
    m.observeAlert(10);
    m.observeAlert(10);
    m.observeKeyUpdate();
    m.observeResume(true);
    m.observeResume(false);
    m.observeEarlyData(false);

    try std.testing.expectEqual(@as(u64, 1), m.handshake_started);
    try std.testing.expectEqual(@as(u64, 1), m.handshake_success);
    try std.testing.expectEqual(@as(u64, 1), m.handshake_fail);
    try std.testing.expectEqual(@as(u64, 2), m.alert_counts[10]);
    try std.testing.expectEqual(@as(u64, 1), m.keyupdate_count);
    try std.testing.expectEqual(@as(u64, 1), m.resume_hit);
    try std.testing.expectEqual(@as(u64, 1), m.resume_miss);
    try std.testing.expectEqual(@as(u64, 1), m.early_data_reject);
    try std.testing.expectEqual(@as(?u64, std.time.ns_per_ms * 250), m.handshake_latency.quantileUpperBoundNs(0.95));
}

test "prometheus export includes key metric families" {
    var m = Metrics{};
    m.observeHandshakeStart();
    m.observeHandshakeFinished(true, std.time.ns_per_ms * 3);
    m.observeAlert(0);
    m.observeKeyUpdate();

    const body = try m.exportPrometheus(std.testing.allocator);
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "zigtls_handshake_started_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "zigtls_alert_total{code=\"0\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "zigtls_handshake_latency_p50_ns") != null);
}
