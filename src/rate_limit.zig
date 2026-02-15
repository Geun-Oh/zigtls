const std = @import("std");

pub const Error = error{
    InvalidConfig,
};

pub const TokenBucket = struct {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_ns: u64,

    pub fn init(burst: u32, refill_per_sec: u32, now_ns: u64) Error!TokenBucket {
        if (burst == 0 or refill_per_sec == 0) return error.InvalidConfig;
        return .{
            .capacity = @floatFromInt(burst),
            .refill_per_sec = @floatFromInt(refill_per_sec),
            .tokens = @floatFromInt(burst),
            .last_ns = now_ns,
        };
    }

    pub fn allowAt(self: *TokenBucket, now_ns: u64) bool {
        self.refill(now_ns);
        if (self.tokens < 1.0) return false;
        self.tokens -= 1.0;
        return true;
    }

    pub fn available(self: *TokenBucket, now_ns: u64) u32 {
        self.refill(now_ns);
        return @as(u32, @intFromFloat(@floor(self.tokens)));
    }

    fn refill(self: *TokenBucket, now_ns: u64) void {
        if (now_ns <= self.last_ns) return;
        const delta_ns = now_ns - self.last_ns;
        self.last_ns = now_ns;

        const delta_sec = @as(f64, @floatFromInt(delta_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        self.tokens += delta_sec * self.refill_per_sec;
        if (self.tokens > self.capacity) self.tokens = self.capacity;
    }
};

test "token bucket consumes burst then rejects" {
    var b = try TokenBucket.init(3, 10, 0);
    try std.testing.expect(b.allowAt(0));
    try std.testing.expect(b.allowAt(0));
    try std.testing.expect(b.allowAt(0));
    try std.testing.expect(!b.allowAt(0));
}

test "token bucket refills over time" {
    var b = try TokenBucket.init(2, 2, 0); // 2 tokens/sec
    try std.testing.expect(b.allowAt(0));
    try std.testing.expect(b.allowAt(0));
    try std.testing.expect(!b.allowAt(0));

    // +0.5s => +1 token
    try std.testing.expect(b.allowAt(std.time.ns_per_s / 2));
    try std.testing.expect(!b.allowAt(std.time.ns_per_s / 2));

    // +1s more => +2 tokens but capped to capacity 2
    try std.testing.expectEqual(@as(u32, 2), b.available(std.time.ns_per_s + std.time.ns_per_s / 2));
}

test "invalid config is rejected" {
    try std.testing.expectError(error.InvalidConfig, TokenBucket.init(0, 1, 0));
    try std.testing.expectError(error.InvalidConfig, TokenBucket.init(1, 0, 0));
}
