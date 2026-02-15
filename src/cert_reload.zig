const std = @import("std");

pub const max_reload_file_bytes: usize = 512 * 1024;

pub const SnapshotView = struct {
    generation: u64,
    cert_pem: []const u8,
    key_pem: []const u8,
};

const Snapshot = struct {
    generation: u64,
    cert_pem: []u8,
    key_pem: []u8,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    active: ?Snapshot = null,
    previous: ?Snapshot = null,
    generation_counter: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Store) void {
        if (self.active) |snap| freeSnapshot(self.allocator, snap);
        if (self.previous) |snap| freeSnapshot(self.allocator, snap);
        self.* = undefined;
    }

    pub fn reloadFromFiles(self: *Store, cert_path: []const u8, key_path: []const u8) Error!u64 {
        const cert = try std.fs.cwd().readFileAlloc(self.allocator, cert_path, max_reload_file_bytes);
        errdefer self.allocator.free(cert);
        const key = try std.fs.cwd().readFileAlloc(self.allocator, key_path, max_reload_file_bytes);
        errdefer self.allocator.free(key);

        if (cert.len == 0 or key.len == 0) return error.EmptyCredential;

        self.generation_counter += 1;
        const next = Snapshot{
            .generation = self.generation_counter,
            .cert_pem = cert,
            .key_pem = key,
        };

        if (self.previous) |old_prev| freeSnapshot(self.allocator, old_prev);
        self.previous = self.active;
        self.active = next;
        return next.generation;
    }

    pub fn rollback(self: *Store) Error!void {
        const prev = self.previous orelse return error.NoPreviousSnapshot;
        const cur = self.active;
        self.active = prev;
        self.previous = cur;
    }

    pub fn snapshot(self: Store) ?SnapshotView {
        const active = self.active orelse return null;
        return .{
            .generation = active.generation,
            .cert_pem = active.cert_pem,
            .key_pem = active.key_pem,
        };
    }
};

pub const Error = error{
    EmptyCredential,
    NoPreviousSnapshot,
} || std.fs.File.OpenError || std.fs.File.ReadError || std.mem.Allocator.Error;

fn freeSnapshot(allocator: std.mem.Allocator, snap: Snapshot) void {
    allocator.free(snap.cert_pem);
    allocator.free(snap.key_pem);
}

test "reload updates generation and keeps previous snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    const g1 = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqual(@as(u64, 1), g1);
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-B" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-B" });

    const g2 = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqual(@as(u64, 2), g2);
    try std.testing.expectEqualStrings("CERT-B", store.snapshot().?.cert_pem);
    try std.testing.expectEqual(@as(u64, 1), store.previous.?.generation);
}

test "failed reload keeps existing active snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.reloadFromFiles(cert_path, key_path);
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);

    try std.testing.expectError(error.FileNotFound, store.reloadFromFiles("/no/such/cert.pem", key_path));
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);
}

test "rollback restores previous active snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-A" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-A" });

    const cert_path = try tmp.dir.realpathAlloc(std.testing.allocator, "cert.pem");
    defer std.testing.allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(std.testing.allocator, "key.pem");
    defer std.testing.allocator.free(key_path);

    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.reloadFromFiles(cert_path, key_path);

    try tmp.dir.writeFile(.{ .sub_path = "cert.pem", .data = "CERT-B" });
    try tmp.dir.writeFile(.{ .sub_path = "key.pem", .data = "KEY-B" });
    _ = try store.reloadFromFiles(cert_path, key_path);

    try std.testing.expectEqualStrings("CERT-B", store.snapshot().?.cert_pem);
    try store.rollback();
    try std.testing.expectEqualStrings("CERT-A", store.snapshot().?.cert_pem);
}

test "rollback requires previous snapshot" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectError(error.NoPreviousSnapshot, store.rollback());
}
