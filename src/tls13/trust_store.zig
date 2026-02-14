const std = @import("std");

pub const TrustStore = struct {
    bundle: std.crypto.Certificate.Bundle = .{},

    pub fn initEmpty() TrustStore {
        return .{};
    }

    pub fn deinit(self: *TrustStore, allocator: std.mem.Allocator) void {
        self.bundle.deinit(allocator);
    }

    pub fn rescanSystem(self: *TrustStore, allocator: std.mem.Allocator) !void {
        try self.bundle.rescan(allocator);
    }

    pub fn loadPemFileAbsolute(self: *TrustStore, allocator: std.mem.Allocator, abs_path: []const u8) !void {
        try self.bundle.addCertsFromFilePathAbsolute(allocator, abs_path);
    }

    pub fn loadPemDirAbsolute(self: *TrustStore, allocator: std.mem.Allocator, abs_path: []const u8) !void {
        try self.bundle.addCertsFromDirPathAbsolute(allocator, abs_path);
    }

    pub fn verifyParsed(self: TrustStore, parsed: std.crypto.Certificate.Parsed, now_sec: i64) !void {
        try self.bundle.verify(parsed, now_sec);
    }

    pub fn count(self: TrustStore) usize {
        return self.bundle.map.count();
    }
};

test "empty trust store has zero certificates" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "loading nonexistent pem file returns not found" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    try std.testing.expectError(error.FileNotFound, store.loadPemFileAbsolute(std.testing.allocator, "/__zigtls_missing_ca_bundle__.pem"));
}
