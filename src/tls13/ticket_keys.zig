const std = @import("std");

pub const max_ticket_keys: usize = 8;

pub const TicketKey = struct {
    key_id: u32,
    material: [32]u8,
    not_before_unix: i64,
    not_after_unix: i64,
    can_encrypt: bool = true,
};

const Slot = struct {
    key: TicketKey,
    generation: u64,
};

pub const Manager = struct {
    slots: [max_ticket_keys]?Slot = [_]?Slot{null} ** max_ticket_keys,
    generation_counter: u64 = 0,

    pub fn init() Manager {
        return .{};
    }

    pub fn rotate(self: *Manager, key: TicketKey) Error!void {
        try validateKey(key);

        // Existing active key remains decrypt-only after rotation.
        var i: usize = 0;
        while (i < self.slots.len) : (i += 1) {
            if (self.slots[i]) |*slot| {
                slot.key.can_encrypt = false;
            }
        }

        const idx = self.findInsertIndex();
        self.generation_counter += 1;
        self.slots[idx] = Slot{ .key = key, .generation = self.generation_counter };
    }

    pub fn currentEncryptKey(self: Manager, now_unix: i64) Error!TicketKey {
        var best: ?Slot = null;

        for (self.slots) |opt| {
            const slot = opt orelse continue;
            if (!slot.key.can_encrypt) continue;
            if (!isValidAt(slot.key, now_unix)) continue;
            if (best == null or slot.generation > best.?.generation) {
                best = slot;
            }
        }

        if (best == null) return error.NoEncryptKeyAvailable;
        return best.?.key;
    }

    pub fn findDecryptKey(self: Manager, key_id: u32, now_unix: i64) ?TicketKey {
        var best: ?Slot = null;
        for (self.slots) |opt| {
            const slot = opt orelse continue;
            if (slot.key.key_id != key_id) continue;
            if (!isValidAt(slot.key, now_unix)) continue;
            if (best == null or slot.generation > best.?.generation) {
                best = slot;
            }
        }
        return if (best) |slot| slot.key else null;
    }

    pub fn count(self: Manager) usize {
        var n: usize = 0;
        for (self.slots) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    fn findInsertIndex(self: Manager) usize {
        var empty_index: ?usize = null;
        var oldest_index: usize = 0;
        var oldest_generation: u64 = std.math.maxInt(u64);

        var i: usize = 0;
        while (i < self.slots.len) : (i += 1) {
            if (self.slots[i] == null) {
                empty_index = i;
                break;
            }
            const generation = self.slots[i].?.generation;
            if (generation < oldest_generation) {
                oldest_generation = generation;
                oldest_index = i;
            }
        }

        return empty_index orelse oldest_index;
    }
};

pub const Error = error{
    InvalidValidityWindow,
    NoEncryptKeyAvailable,
};

fn validateKey(key: TicketKey) Error!void {
    if (key.not_after_unix <= key.not_before_unix) return error.InvalidValidityWindow;
}

fn isValidAt(key: TicketKey, now_unix: i64) bool {
    return key.not_before_unix <= now_unix and now_unix <= key.not_after_unix;
}

fn mkMaterial(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

test "rotate selects newest valid encrypt key" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 1, .material = mkMaterial(1), .not_before_unix = 0, .not_after_unix = 100 });
    try m.rotate(.{ .key_id = 2, .material = mkMaterial(2), .not_before_unix = 0, .not_after_unix = 100 });

    const active = try m.currentEncryptKey(10);
    try std.testing.expectEqual(@as(u32, 2), active.key_id);
}

test "rotation keeps prior keys decrypt-capable" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 10, .material = mkMaterial(0xaa), .not_before_unix = 0, .not_after_unix = 50 });
    try m.rotate(.{ .key_id = 20, .material = mkMaterial(0xbb), .not_before_unix = 0, .not_after_unix = 100 });

    const old = m.findDecryptKey(10, 10) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 10), old.key_id);

    const active = try m.currentEncryptKey(10);
    try std.testing.expectEqual(@as(u32, 20), active.key_id);
    try std.testing.expect(active.can_encrypt);
    try std.testing.expect(!(old.can_encrypt));
}

test "expired key is not selected" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 1, .material = mkMaterial(1), .not_before_unix = 0, .not_after_unix = 5 });

    try std.testing.expectError(error.NoEncryptKeyAvailable, m.currentEncryptKey(6));
    try std.testing.expect(m.findDecryptKey(1, 6) == null);
}

test "invalid validity window is rejected" {
    var m = Manager.init();
    try std.testing.expectError(error.InvalidValidityWindow, m.rotate(.{
        .key_id = 1,
        .material = mkMaterial(1),
        .not_before_unix = 10,
        .not_after_unix = 10,
    }));
}

test "manager evicts oldest generation when full" {
    var m = Manager.init();
    var i: usize = 0;
    while (i < max_ticket_keys) : (i += 1) {
        try m.rotate(.{
            .key_id = @as(u32, @intCast(i + 1)),
            .material = mkMaterial(@as(u8, @intCast(i + 1))),
            .not_before_unix = 0,
            .not_after_unix = 100,
        });
    }

    try std.testing.expectEqual(max_ticket_keys, m.count());
    const first_old = m.findDecryptKey(1, 10) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 1), first_old.key_id);

    try m.rotate(.{ .key_id = 99, .material = mkMaterial(99), .not_before_unix = 0, .not_after_unix = 100 });
    try std.testing.expectEqual(max_ticket_keys, m.count());
    try std.testing.expect(m.findDecryptKey(1, 10) == null);
    try std.testing.expectEqual(@as(u32, 99), (try m.currentEncryptKey(10)).key_id);
}
