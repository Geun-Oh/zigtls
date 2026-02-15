const std = @import("std");
const zigtls = @import("zigtls");

const keyschedule = zigtls.tls13.keyschedule;

const SuiteStats = struct {
    suite_name: []const u8,
    match: Stats,
    mismatch: Stats,
};

const Stats = struct {
    count: usize,
    mean_ns: f64,
    stddev_ns: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    min_ns: u64,
    max_ns: u64,
};

const Config = struct {
    iterations: usize = 20_000,
    warmup: usize = 2_000,
};

pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const leaked = gpa_impl.deinit();
        if (leaked == .leak) std.debug.print("timing-probe: allocator leak detected\n", .{});
    }
    const gpa = gpa_impl.allocator();

    const cfg = try parseArgs(gpa);
    const stdout = std.fs.File.stdout().deprecatedWriter();

    const suite_stats = [_]SuiteStats{
        try runSuite(gpa, .tls_aes_128_gcm_sha256, "TLS_AES_128_GCM_SHA256", cfg),
        try runSuite(gpa, .tls_aes_256_gcm_sha384, "TLS_AES_256_GCM_SHA384", cfg),
        try runSuite(gpa, .tls_chacha20_poly1305_sha256, "TLS_CHACHA20_POLY1305_SHA256", cfg),
    };

    try stdout.print("zigtls-timing-probe\n", .{});
    try stdout.print("parameters: iterations={d} warmup={d}\n", .{ cfg.iterations, cfg.warmup });

    for (suite_stats) |suite| {
        try printCase(stdout, suite.suite_name, "match", suite.match);
        try printCase(stdout, suite.suite_name, "mismatch", suite.mismatch);

        const denom = @max(suite.match.mean_ns, suite.mismatch.mean_ns);
        const gap_ratio_abs = if (denom == 0.0) 0.0 else @abs(suite.match.mean_ns - suite.mismatch.mean_ns) / denom;
        const mean_delta = suite.match.mean_ns - suite.mismatch.mean_ns;
        try stdout.print(
            "suite={s} gap_ratio_abs={d:.6} mean_delta_ns={d:.2}\n",
            .{ suite.suite_name, gap_ratio_abs, mean_delta },
        );
    }
}

fn printCase(writer: anytype, suite_name: []const u8, case_name: []const u8, stats: Stats) !void {
    try writer.print(
        "suite={s} case={s} count={d} mean_ns={d:.2} stddev_ns={d:.2} p50_ns={d} p95_ns={d} p99_ns={d} min_ns={d} max_ns={d}\n",
        .{
            suite_name,
            case_name,
            stats.count,
            stats.mean_ns,
            stats.stddev_ns,
            stats.p50_ns,
            stats.p95_ns,
            stats.p99_ns,
            stats.min_ns,
            stats.max_ns,
        },
    );
}

fn runSuite(
    allocator: std.mem.Allocator,
    comptime suite: keyschedule.CipherSuite,
    suite_name: []const u8,
    cfg: Config,
) !SuiteStats {
    const base = keyschedule.extract(suite, "timing-salt", "timing-ikm");
    const hs = keyschedule.deriveSecret(suite, base, "c hs traffic", "timing-transcript");
    const fin = keyschedule.finishedKey(suite, hs);
    const expected = keyschedule.finishedVerifyData(suite, fin, "timing-transcript");

    var mismatch = expected;
    mismatch[mismatch.len - 1] ^= 0x01;

    const match_samples = try collectSamples(suite, allocator, fin, "timing-transcript", expected[0..], cfg);
    defer allocator.free(match_samples);

    const mismatch_samples = try collectSamples(suite, allocator, fin, "timing-transcript", mismatch[0..], cfg);
    defer allocator.free(mismatch_samples);

    return .{
        .suite_name = suite_name,
        .match = try computeStats(allocator, match_samples),
        .mismatch = try computeStats(allocator, mismatch_samples),
    };
}

fn collectSamples(
    comptime suite: keyschedule.CipherSuite,
    allocator: std.mem.Allocator,
    fin: keyschedule.SecretType(suite),
    transcript_hash: []const u8,
    expected: []const u8,
    cfg: Config,
) ![]u64 {
    var warmup_i: usize = 0;
    while (warmup_i < cfg.warmup) : (warmup_i += 1) {
        const ok = keyschedule.verifyFinished(suite, fin, transcript_hash, expected);
        std.mem.doNotOptimizeAway(ok);
    }

    const samples = try allocator.alloc(u64, cfg.iterations);
    var timer = try std.time.Timer.start();
    _ = timer.lap();

    var i: usize = 0;
    while (i < cfg.iterations) : (i += 1) {
        const ok = keyschedule.verifyFinished(suite, fin, transcript_hash, expected);
        std.mem.doNotOptimizeAway(ok);
        samples[i] = timer.lap();
    }

    return samples;
}

fn computeStats(allocator: std.mem.Allocator, samples: []const u64) !Stats {
    if (samples.len == 0) return error.EmptySamples;

    const sorted = try allocator.dupe(u64, samples);
    defer allocator.free(sorted);
    std.sort.pdq(u64, sorted, {}, lessThanU64);

    var sum: f64 = 0.0;
    var min_ns: u64 = std.math.maxInt(u64);
    var max_ns: u64 = 0;

    for (samples) |v| {
        sum += @floatFromInt(v);
        if (v < min_ns) min_ns = v;
        if (v > max_ns) max_ns = v;
    }

    const count_f: f64 = @floatFromInt(samples.len);
    const mean = sum / count_f;

    var variance_acc: f64 = 0.0;
    for (samples) |v| {
        const vf: f64 = @floatFromInt(v);
        const d = vf - mean;
        variance_acc += d * d;
    }
    const variance = variance_acc / count_f;

    return .{
        .count = samples.len,
        .mean_ns = mean,
        .stddev_ns = @sqrt(variance),
        .p50_ns = sorted[percentileIndex(samples.len, 50)],
        .p95_ns = sorted[percentileIndex(samples.len, 95)],
        .p99_ns = sorted[percentileIndex(samples.len, 99)],
        .min_ns = min_ns,
        .max_ns = max_ns,
    };
}

fn percentileIndex(len: usize, p: u8) usize {
    if (len <= 1) return 0;
    return ((len - 1) * p) / 100;
}

fn lessThanU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn parseArgs(allocator: std.mem.Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var cfg = Config{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--iterations")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.iterations = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--warmup")) {
            if (i + 1 >= args.len) return error.MissingValue;
            cfg.warmup = try std.fmt.parseInt(usize, args[i + 1], 10);
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("usage: timing-probe [--iterations <n>] [--warmup <n>]\n", .{});
            std.process.exit(0);
        }
        return error.InvalidArgument;
    }

    if (cfg.iterations == 0) return error.InvalidIterations;
    return cfg;
}

test "percentile index boundaries" {
    try std.testing.expectEqual(@as(usize, 0), percentileIndex(1, 50));
    try std.testing.expectEqual(@as(usize, 4), percentileIndex(5, 100));
    try std.testing.expectEqual(@as(usize, 3), percentileIndex(5, 95));
}

test "compute stats rejects empty samples" {
    try std.testing.expectError(error.EmptySamples, computeStats(std.testing.allocator, &.{}));
}
