const std = @import("std");

pub const TrustStoreError = error{
    PathNotAbsolute,
};

pub const LoadStrategy = struct {
    prefer_system: bool = true,
    fail_on_system_error: bool = false,
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
    const SystemLoaderFn = *const fn (self: *TrustStore, allocator: std.mem.Allocator) anyerror!void;

    pub fn initEmpty() TrustStore {
        return .{};
    }

    pub fn deinit(self: *TrustStore, allocator: std.mem.Allocator) void {
        self.bundle.deinit(allocator);
    }

    pub fn rescanSystem(self: *TrustStore, allocator: std.mem.Allocator) !void {
        try self.bundle.rescan(allocator);
    }

    pub fn loadPemFileAbsolute(self: *TrustStore, allocator: std.mem.Allocator, abs_path: []const u8) (TrustStoreError || anyerror)!void {
        if (!std.fs.path.isAbsolute(abs_path)) return error.PathNotAbsolute;
        try self.bundle.addCertsFromFilePathAbsolute(allocator, abs_path);
    }

    pub fn loadPemDirAbsolute(self: *TrustStore, allocator: std.mem.Allocator, abs_path: []const u8) (TrustStoreError || anyerror)!void {
        if (!std.fs.path.isAbsolute(abs_path)) return error.PathNotAbsolute;
        try self.bundle.addCertsFromDirPathAbsolute(allocator, abs_path);
    }

    pub fn verifyParsed(self: TrustStore, parsed: std.crypto.Certificate.Parsed, now_sec: i64) !void {
        try self.bundle.verify(parsed, now_sec);
    }

    pub fn count(self: TrustStore) usize {
        return self.bundle.map.count();
    }

    pub fn loadWithStrategy(self: *TrustStore, allocator: std.mem.Allocator, strategy: LoadStrategy) !LoadResult {
        return self.loadWithStrategyInternal(allocator, strategy, defaultSystemLoader);
    }

    fn loadWithStrategyInternal(
        self: *TrustStore,
        allocator: std.mem.Allocator,
        strategy: LoadStrategy,
        system_loader: SystemLoaderFn,
    ) !LoadResult {
        if (strategy.prefer_system) {
            system_loader(self, allocator) catch |err| {
                if (strategy.fail_on_system_error) return err;
            };
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

    fn defaultSystemLoader(self: *TrustStore, allocator: std.mem.Allocator) !void {
        try self.rescanSystem(allocator);
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

test "pem file loader rejects relative path" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    try std.testing.expectError(error.PathNotAbsolute, store.loadPemFileAbsolute(std.testing.allocator, "relative/ca.pem"));
}

test "pem dir loader rejects relative path" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    try std.testing.expectError(error.PathNotAbsolute, store.loadPemDirAbsolute(std.testing.allocator, "relative/certs"));
}

test "strategy can propagate strict system load errors" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    const Hooks = struct {
        fn failSystemLoad(_: *TrustStore, _: std.mem.Allocator) !void {
            return error.AccessDenied;
        }
    };

    try std.testing.expectError(error.AccessDenied, store.loadWithStrategyInternal(std.testing.allocator, .{
        .prefer_system = true,
        .fail_on_system_error = true,
    }, Hooks.failSystemLoad));
}

test "strategy can ignore system load errors and continue fallback path" {
    var store = TrustStore.initEmpty();
    defer store.deinit(std.testing.allocator);

    const Hooks = struct {
        fn failSystemLoad(_: *TrustStore, _: std.mem.Allocator) !void {
            return error.AccessDenied;
        }
    };

    const result = try store.loadWithStrategyInternal(std.testing.allocator, .{
        .prefer_system = true,
        .fail_on_system_error = false,
    }, Hooks.failSystemLoad);
    try std.testing.expectEqual(LoadResult.none, result);
}
