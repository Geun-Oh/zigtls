const std = @import("std");

pub const max_clock_skew_sec: i64 = 300;

pub const CertStatus = enum {
    good,
    revoked,
    unknown,
};

pub const ResponseView = struct {
    status: CertStatus,
    produced_at: i64,
    this_update: i64,
    next_update: ?i64,
};

pub const ValidationResult = enum {
    accepted,
    soft_fail,
};

pub const CheckError = error{
    MissingResponse,
    Revoked,
    UnknownStatus,
    FutureProducedAt,
    ProducedBeforeThisUpdate,
    FutureThisUpdate,
    InvalidTimeWindow,
    StaleResponse,
};

pub fn checkStapled(response: ?ResponseView, now_sec: i64, allow_soft_fail: bool) CheckError!ValidationResult {
    const resp = response orelse {
        if (allow_soft_fail) return .soft_fail;
        return error.MissingResponse;
    };

    switch (resp.status) {
        .good => {},
        .revoked => return error.Revoked,
        .unknown => {
            if (allow_soft_fail) return .soft_fail;
            return error.UnknownStatus;
        },
    }

    if (resp.produced_at > now_sec + max_clock_skew_sec) {
        if (allow_soft_fail) return .soft_fail;
        return error.FutureProducedAt;
    }

    if (resp.produced_at + max_clock_skew_sec < resp.this_update) {
        if (allow_soft_fail) return .soft_fail;
        return error.ProducedBeforeThisUpdate;
    }

    if (resp.this_update > now_sec + max_clock_skew_sec) {
        if (allow_soft_fail) return .soft_fail;
        return error.FutureThisUpdate;
    }

    const next = resp.next_update orelse {
        if (allow_soft_fail) return .soft_fail;
        return error.InvalidTimeWindow;
    };

    if (next < resp.this_update) {
        if (allow_soft_fail) return .soft_fail;
        return error.InvalidTimeWindow;
    }

    if (next + max_clock_skew_sec < now_sec) {
        if (allow_soft_fail) return .soft_fail;
        return error.StaleResponse;
    }

    return .accepted;
}

test "good response is accepted" {
    const now: i64 = 1_700_000_000;
    const res = try checkStapled(.{
        .status = .good,
        .produced_at = now - 100,
        .this_update = now - 100,
        .next_update = now + 3600,
    }, now, false);
    try std.testing.expectEqual(ValidationResult.accepted, res);
}

test "revoked response fails hard" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.Revoked, checkStapled(.{
        .status = .revoked,
        .produced_at = now,
        .this_update = now,
        .next_update = now + 10,
    }, now, true));
}

test "missing response soft-fails only when allowed" {
    const now: i64 = 1_700_000_000;
    const soft = try checkStapled(null, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
    try std.testing.expectError(error.MissingResponse, checkStapled(null, now, false));
}

test "future produced_at is rejected unless soft-fail policy allows" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.FutureProducedAt, checkStapled(.{
        .status = .good,
        .produced_at = now + max_clock_skew_sec + 1,
        .this_update = now,
        .next_update = now + 3600,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .good,
        .produced_at = now + max_clock_skew_sec + 1,
        .this_update = now,
        .next_update = now + 3600,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "produced_at before this_update is rejected unless soft-fail policy allows" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.ProducedBeforeThisUpdate, checkStapled(.{
        .status = .good,
        .produced_at = now - 1000,
        .this_update = now - 100,
        .next_update = now + 3600,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .good,
        .produced_at = now - 1000,
        .this_update = now - 100,
        .next_update = now + 3600,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "unknown status hard-fails or soft-fails by policy" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.UnknownStatus, checkStapled(.{
        .status = .unknown,
        .produced_at = now,
        .this_update = now,
        .next_update = now + 60,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .unknown,
        .produced_at = now,
        .this_update = now,
        .next_update = now + 60,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "future this_update is rejected unless soft-fail policy allows" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.FutureThisUpdate, checkStapled(.{
        .status = .good,
        .produced_at = now + 1,
        .this_update = now + max_clock_skew_sec + 1,
        .next_update = now + max_clock_skew_sec + 100,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .good,
        .produced_at = now + 1,
        .this_update = now + max_clock_skew_sec + 1,
        .next_update = now + max_clock_skew_sec + 100,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "clock-skew boundaries are accepted for produced_at and this_update" {
    const now: i64 = 1_700_000_000;

    const produced_at_boundary = try checkStapled(.{
        .status = .good,
        .produced_at = now + max_clock_skew_sec,
        .this_update = now,
        .next_update = now + 3600,
    }, now, false);
    try std.testing.expectEqual(ValidationResult.accepted, produced_at_boundary);

    const produced_before_this_update_boundary = try checkStapled(.{
        .status = .good,
        .produced_at = now - 1000,
        .this_update = now - 1000 + max_clock_skew_sec,
        .next_update = now + 3600,
    }, now, false);
    try std.testing.expectEqual(ValidationResult.accepted, produced_before_this_update_boundary);

    const this_update_boundary = try checkStapled(.{
        .status = .good,
        .produced_at = now + 1,
        .this_update = now + max_clock_skew_sec,
        .next_update = now + max_clock_skew_sec + 100,
    }, now, false);
    try std.testing.expectEqual(ValidationResult.accepted, this_update_boundary);
}

test "invalid next_update window is rejected unless soft-fail policy allows" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.InvalidTimeWindow, checkStapled(.{
        .status = .good,
        .produced_at = now - 10,
        .this_update = now - 10,
        .next_update = now - 20,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .good,
        .produced_at = now - 10,
        .this_update = now - 10,
        .next_update = now - 20,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "missing next_update is rejected unless soft-fail policy allows" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.InvalidTimeWindow, checkStapled(.{
        .status = .good,
        .produced_at = now - 10,
        .this_update = now - 10,
        .next_update = null,
    }, now, false));

    const soft = try checkStapled(.{
        .status = .good,
        .produced_at = now - 10,
        .this_update = now - 10,
        .next_update = null,
    }, now, true);
    try std.testing.expectEqual(ValidationResult.soft_fail, soft);
}

test "stale response boundary accepts skew limit and rejects beyond limit" {
    const now: i64 = 1_700_000_000;

    const at_boundary = try checkStapled(.{
        .status = .good,
        .produced_at = now - 3600,
        .this_update = now - 3600,
        .next_update = now - max_clock_skew_sec,
    }, now, false);
    try std.testing.expectEqual(ValidationResult.accepted, at_boundary);

    try std.testing.expectError(error.StaleResponse, checkStapled(.{
        .status = .good,
        .produced_at = now - 3600,
        .this_update = now - 3600,
        .next_update = now - max_clock_skew_sec - 1,
    }, now, false));
}
