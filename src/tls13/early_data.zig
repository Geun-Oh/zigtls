const std = @import("std");

pub const InitError = error{
    InvalidBitCount,
    OutOfMemory,
};

pub const ReplayFilter = struct {
    allocator: std.mem.Allocator,
    words: []u64,
    bit_count: usize,

    pub fn init(allocator: std.mem.Allocator, bit_count: usize) InitError!ReplayFilter {
        if (bit_count < 64 or !std.math.isPowerOfTwo(bit_count)) {
            return error.InvalidBitCount;
        }

        const word_count = bit_count / 64;
        const words = try allocator.alloc(u64, word_count);
        @memset(words, 0);

        return .{
            .allocator = allocator,
            .words = words,
            .bit_count = bit_count,
        };
    }

    pub fn deinit(self: *ReplayFilter) void {
        self.allocator.free(self.words);
        self.words = &.{};
        self.bit_count = 0;
    }

    pub fn seenOrInsert(self: *ReplayFilter, token: []const u8) bool {
        const idx0 = self.index(0x91e10da5c79e7b1d, token);
        const idx1 = self.index(0xd6e8feb86659fd93, token);
        const idx2 = self.index(0xa0761d6478bd642f, token);

        const seen = self.isSet(idx0) and self.isSet(idx1) and self.isSet(idx2);
        self.set(idx0);
        self.set(idx1);
        self.set(idx2);
        return seen;
    }

    fn index(self: ReplayFilter, seed: u64, token: []const u8) usize {
        const h = std.hash.Wyhash.hash(seed, token);
        return @as(usize, @intCast(h)) & (self.bit_count - 1);
    }

    fn isSet(self: ReplayFilter, bit_index: usize) bool {
        const word_idx = bit_index / 64;
        const bit = @as(u6, @intCast(bit_index % 64));
        return (self.words[word_idx] & (@as(u64, 1) << bit)) != 0;
    }

    fn set(self: *ReplayFilter, bit_index: usize) void {
        const word_idx = bit_index / 64;
        const bit = @as(u6, @intCast(bit_index % 64));
        self.words[word_idx] |= (@as(u64, 1) << bit);
    }
};

test "replay filter rejects invalid bit count" {
    try std.testing.expectError(error.InvalidBitCount, ReplayFilter.init(std.testing.allocator, 1000));
}

test "replay filter marks duplicate token as seen" {
    var filter = try ReplayFilter.init(std.testing.allocator, 4096);
    defer filter.deinit();

    try std.testing.expect(!filter.seenOrInsert("ticket-1"));
    try std.testing.expect(filter.seenOrInsert("ticket-1"));
}
