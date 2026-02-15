const std = @import("std");
const zigtls = @import("zigtls");

const keyschedule = zigtls.tls13.keyschedule;
const session = zigtls.tls13.session;

const MiB: f64 = 1024.0 * 1024.0;

const Report = struct {
    suite_name: []const u8,
    latency_ns: u64,
    throughput_bytes_per_sec: u64,
};

pub fn main() !void {
    const stdout = std.fs.File.stdout().deprecatedWriter();

    const ks_iterations: usize = 50_000;
    const aead_iterations: usize = 8_192;
    const payload_len: usize = 16 * 1024;

    const reports = [_]Report{
        .{
            .suite_name = "TLS_AES_128_GCM_SHA256",
            .latency_ns = try benchmarkKeySchedule(.tls_aes_128_gcm_sha256, ks_iterations),
            .throughput_bytes_per_sec = try benchmarkAead(std.crypto.aead.aes_gcm.Aes128Gcm, aead_iterations, payload_len),
        },
        .{
            .suite_name = "TLS_AES_256_GCM_SHA384",
            .latency_ns = try benchmarkKeySchedule(.tls_aes_256_gcm_sha384, ks_iterations),
            .throughput_bytes_per_sec = try benchmarkAead(std.crypto.aead.aes_gcm.Aes256Gcm, aead_iterations, payload_len),
        },
        .{
            .suite_name = "TLS_CHACHA20_POLY1305_SHA256",
            .latency_ns = try benchmarkKeySchedule(.tls_chacha20_poly1305_sha256, ks_iterations),
            .throughput_bytes_per_sec = try benchmarkAead(std.crypto.aead.chacha_poly.ChaCha20Poly1305, aead_iterations, payload_len),
        },
    };

    try stdout.print("zigtls-perf-probe\n", .{});
    try stdout.print("parameters: ks_iterations={d} aead_iterations={d} payload_bytes={d}\n", .{ ks_iterations, aead_iterations, payload_len });

    for (reports) |report| {
        const per_iter_ns = @as(f64, @floatFromInt(report.latency_ns)) / @as(f64, @floatFromInt(ks_iterations));
        const mbps = @as(f64, @floatFromInt(report.throughput_bytes_per_sec)) / MiB;
        try stdout.print(
            "suite={s} handshake_ks_ns_total={d} handshake_ks_ns_per_iter={d:.2} app_throughput_mib_s={d:.2}\n",
            .{ report.suite_name, report.latency_ns, per_iter_ns, mbps },
        );
    }

    const baseline_config = session.Config{
        .role = .client,
        .suite = .tls_aes_128_gcm_sha256,
    };
    const early_data_config = session.Config{
        .role = .server,
        .suite = .tls_aes_128_gcm_sha256,
        .early_data = .{ .enabled = true, .max_ticket_len = 4096 },
    };
    try stdout.print(
        "memory_ceiling_bytes baseline={d} early_data_enabled={d}\n",
        .{
            session.estimatedConnectionMemoryCeiling(baseline_config),
            session.estimatedConnectionMemoryCeiling(early_data_config),
        },
    );
}

fn benchmarkKeySchedule(comptime suite: keyschedule.CipherSuite, iterations: usize) !u64 {
    var timer = try std.time.Timer.start();
    _ = timer.lap();

    var accumulator: u8 = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const early = keyschedule.extract(suite, "perf-salt", "perf-ikm");
        const hs = keyschedule.deriveSecret(suite, early, "c hs traffic", "transcript-hash");
        const fin_key = keyschedule.finishedKey(suite, hs);
        const verify = keyschedule.finishedVerifyData(suite, fin_key, "transcript-hash");
        accumulator ^= verify[0];
    }

    std.mem.doNotOptimizeAway(&accumulator);
    return timer.read();
}

fn benchmarkAead(comptime Aead: type, iterations: usize, payload_len: usize) !u64 {
    const allocator = std.heap.page_allocator;
    const plaintext = try allocator.alloc(u8, payload_len);
    defer allocator.free(plaintext);
    const ciphertext = try allocator.alloc(u8, payload_len);
    defer allocator.free(ciphertext);

    @memset(plaintext, 0x5a);

    var tag: [Aead.tag_length]u8 = undefined;
    var key: [Aead.key_length]u8 = [_]u8{0x42} ** Aead.key_length;
    var nonce: [Aead.nonce_length]u8 = [_]u8{0x24} ** Aead.nonce_length;

    var timer = try std.time.Timer.start();
    _ = timer.lap();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        nonce[nonce.len - 1] = @as(u8, @intCast(i & 0xff));
        Aead.encrypt(ciphertext, tag[0..], plaintext, &.{}, nonce, key);
    }

    std.mem.doNotOptimizeAway(ciphertext.ptr);
    std.mem.doNotOptimizeAway(&tag);
    std.mem.doNotOptimizeAway(&key);

    const elapsed_ns = timer.read();
    if (elapsed_ns == 0) return 0;

    const processed_bytes = @as(u128, iterations) * @as(u128, payload_len);
    const bytes_per_sec = (processed_bytes * std.time.ns_per_s) / elapsed_ns;
    return @as(u64, @intCast(bytes_per_sec));
}
