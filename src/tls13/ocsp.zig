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
