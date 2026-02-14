const std = @import("std");

pub const LoadStrategy = struct {
    prefer_system: bool = true,
    fallback_pem_file_absolute: ?[]const u8 = null,
    fallback_pem_dir_absolute: ?[]const u8 = null,
};

pub const LoadResult = enum {
    system,
    pem_file,
    pem_dir,
    none,
};

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

    pub fn loadWithStrategy(self: *TrustStore, allocator: std.mem.Allocator, strategy: LoadStrategy) !LoadResult {
        if (strategy.prefer_system) {
            self.rescanSystem(allocator) catch {};
            if (self.count() > 0) return .system;
        }

        if (strategy.fallback_pem_file_absolute) |path| {
            try self.loadPemFileAbsolute(allocator, path);
            if (self.count() > 0) return .pem_file;
        }

        if (strategy.fallback_pem_dir_absolute) |path| {
            try self.loadPemDirAbsolute(allocator, path);
            if (self.count() > 0) return .pem_dir;
        }

        return .none;
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

test "strategy returns none when all sources disabled" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    const result = try store.loadWithStrategy(std.testing.allocator, .{
        .prefer_system = false,
    });
    try std.testing.expectEqual(LoadResult.none, result);
}

test "strategy propagates fallback file errors deterministically" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    try std.testing.expectError(error.FileNotFound, store.loadWithStrategy(std.testing.allocator, .{
        .prefer_system = false,
        .fallback_pem_file_absolute = "/__zigtls_missing_ca_bundle__.pem",
    }));
}
