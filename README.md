# zigtls

`zigtls` is a Zig-first TLS termination library for load balancers and edge proxies.
It is built to be imported by other Zig projects and to run behind production-style release gates (strict interop, BoGo profile checks, timing/perf assertions, and reliability drills).

## What this library provides

- TLS termination primitives for event-loop integrations (`zigtls.termination`)
- Non-blocking adapter for transport I/O loops (`zigtls.adapter`)
- Cert reload, ticket key management, metrics, and handshake policy hooks
- Strict validation tooling and reproducible evidence scripts under `scripts/release` and `scripts/interop`

## Package compatibility

- Zig minimum version: `0.15.2` (`build.zig.zon`)
- Current library version string: `0.1.0-dev` (`src/root.zig`)

## Import from another Zig project

Add this repository as a Zig dependency, then import `zigtls` from your build graph.

You can add zigtls in your project like below command.

```zig
zig fetch --save https://github.com/Geun-Oh/zigtls/releases/download/v0.1.1/zigtls-v0.1.1.tar.gz
```

Than it will be added into your `build.zig.zon` dependency entry (replace tag/hash with your pinned release):

```zig
.dependencies = .{
    .zigtls = .{
        .url = "https://github.com/Geun-Oh/zigtls/releases/download/<tag>/zigtls-<tag>.tar.gz",
        .hash = "<content-hash>",
    },
},
```

Tag releases automatically publish this tarball and emit the exact snippet/hash in release notes via `.github/workflows/tag-release.yml` (trigger: `push` on `v*` tags).

Wire the module in `build.zig`:

```zig
const zigtls_dep = b.dependency("zigtls", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zigtls", zigtls_dep.module("zigtls"));
```

Use in code:

```zig
const zigtls = @import("zigtls");
```

## Quickstart

Build and run the included event-loop sample:

```bash
zig build lb-example
```

Sample source: `examples/lb_event_loop_sample.zig`

Minimal server-side usage shape:

```zig
const std = @import("std");
const zigtls = @import("zigtls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var conn = zigtls.termination.Connection.init(allocator, .{
        .session = .{ .role = .server, .suite = .tls_aes_128_gcm_sha256 },
    });
    defer conn.deinit();

    conn.accept(.{ .connection_id = 1, .correlation_id = 1 });

    // 1) ingest TLS record bytes from socket
    // _ = try conn.ingest_tls_bytes(record_bytes);
    // 2) drain outbound TLS records to socket
    // _ = try conn.drain_tls_records(out_buf);
    // 3) read decrypted plaintext
    // _ = conn.read_plaintext(app_buf);
}
```

## API map

- Library root exports: `src/root.zig`
  - `zigtls.tls13`
  - `zigtls.termination`
  - `zigtls.adapter`
  - `zigtls.cert_reload`
  - `zigtls.rate_limit`
  - `zigtls.metrics`
- Termination API details: `docs/termination-api.md`
- Error matrix: `docs/error-termination-matrix.md`

## Production gate commands

Base regression gate:

```bash
zig build test
```

Task/release gate entrypoint:

```bash
bash scripts/release/verify_task_gates.sh
```

Strict preflight (interop + gates + evidence sync):

```bash
bash scripts/release/preflight.sh --strict-interop --task-gates --sync-evidence-docs
```

External consumer compatibility check:

```bash
bash scripts/release/check_external_consumer.sh
```

External consumer URL/hash compatibility check:

```bash
bash scripts/release/check_external_consumer_url.sh --url <tarball-url-or-path> --hash <content-hash>
```

## Operational guides

- Release workflow: `docs/release-runbook.md`
- Sign-off checklist: `docs/release-signoff.md`
- Risk acceptance: `docs/risk-acceptance.md`
- Security response: `docs/security-response-policy.md`
- Rollout/canary/rollback: `docs/rollout-canary-gate.md`
- API compatibility policy: `docs/api-compatibility-policy.md`

## Contributing

Contributions are welcome.

1. Fork and create a feature branch.
2. Follow repository gates before submitting:
   - `zig build test`
   - `bash scripts/release/verify_task_gates.sh --basic-only`
3. Keep changes atomic and revert-friendly.
4. For behavior changes, include tests and update relevant docs.
5. Use patch-style commit messages (`MINOR|MEDIUM|MAJOR`, optionally `BUG/`).

For release-sensitive changes, follow `docs/release-runbook.md` and `docs/release-signoff.md`.

## License

This project is licensed under the MIT License. See `LICENSE`.
