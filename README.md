# ⚡ zigtls

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
zig fetch --save https://github.com/Geun-Oh/zigtls/releases/download/v0.1.2/zigtls-v0.1.2.tar.gz
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
Examples index: `examples/README.md`  
QUIC TLS integration example guide: `examples/quic_tls_usage.zig`
This sample is an event-loop/protocol flow demo. It uses mock credentials, not production certificate issuance or rotation.

Production-oriented server-side usage shape (real cert/key binding):

```zig
const std = @import("std");
const zigtls = @import("zigtls");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var store = zigtls.cert_reload.Store.init(allocator);
    defer store.deinit();

    // PEM files are provisioned/rotated by external tooling (ACME, cert-manager, etc.).
    _ = try store.reloadFromFiles("./certs/server-cert.pem", "./certs/server-key.pem");

    var conn = try zigtls.termination.Connection.initChecked(allocator, .{
        .session = .{
            .role = .server,
            .suite = .tls_aes_128_gcm_sha256,
        },
        .dynamic_server_credentials = .{
            .store = &store,
            // Auto signer path expects Ed25519 PKCS#8 private key.
            .auto_sign_from_store_ed25519 = true,
        },
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

For non-Ed25519 keys, use manual signer callback mode via `dynamic_server_credentials.sign_certificate_verify`.

## API map

- Library root exports: `src/root.zig`
  - `zigtls.tls13`
  - `zigtls.quic` (experimental QUIC TLS 1.3 helpers)
  - `zigtls.termination`
  - `zigtls.adapter`
  - `zigtls.cert_reload`
  - `zigtls.rate_limit`
  - `zigtls.metrics`
- `zigtls.quic.tls13` provides QUIC-facing TLS key schedule helpers only: Initial secret derivation, packet protection key/IV/HP derivation, key-update derivation, and QUIC packet nonce construction.
- `zigtls.quic.transport_parameters` provides QUIC transport-parameters varint encode/decode helpers with duplicate/truncation validation.
- QUIC transport engine responsibilities (packetization, ACK/loss recovery, congestion control, CID lifecycle, UDP IO) are intentionally out of `zigtls.quic` public API scope and are expected to be implemented by the embedding QUIC engine.
- Termination API details: `docs/termination-api.md`
- Error matrix: `docs/error-termination-matrix.md`

## QUIC support boundary and usage

### Scope boundary

| Area | Provided by zigtls | Must be implemented by QUIC engine |
| --- | --- | --- |
| TLS 1.3 handshake state machine | Yes (`zigtls.tls13.session`) | No |
| QUIC transport-parameter encoding/decoding | Yes (`zigtls.quic.transport_parameters`) | No |
| QUIC key derivation (Initial/Handshake/1-RTT key material helpers) | Yes (`zigtls.quic.tls13`) | No |
| Packet format/seal/open, ACK/loss recovery, congestion control | No | Yes |
| Connection ID lifecycle/migration | No | Yes |
| UDP socket I/O and timers | No | Yes |

`zigtls` intentionally follows a BoringSSL-style boundary: TLS + crypto primitives only.  
A full QUIC transport stack is out of scope for this library.

### Integration flow

1. Build/parse QUIC transport parameters in your QUIC engine, and pass serialized local parameters to TLS config (`quic_mode`, `quic_transport_parameters`).
2. Feed reassembled CRYPTO payload bytes into `engine.ingestQuicHandshake(level, payload)`.
3. Drain TLS-generated handshake payloads with `engine.popOutboundQuicHandshake()` and send them as QUIC CRYPTO data at the returned level.
4. Watch `IngestResult.actions` for `.quic_key_ready` and/or poll `engine.snapshotQuicSecrets()` to detect newly available Handshake/1-RTT secrets.
5. Convert exported secret bytes to `zigtls.quic.tls13.TrafficSecret`, derive packet-protection keys with `derivePacketProtectionKeys`, and install them in your QUIC packet protection path.
6. Read validated peer transport parameters through `engine.peerQuicTransportParameters()` after ClientHello/EncryptedExtensions ingress validation.

QUIC-native handshake API surface in `zigtls.tls13.session.Engine`:
- `ingestQuicHandshake(level, payload)`: ingress path for QUIC CRYPTO payload bytes (`initial`/`handshake`/`application`).
- `popOutboundQuicHandshake()`: egress path that returns `{ level, payload }` for QUIC CRYPTO emission.
- `noteOutboundQuicHandshake(payload)`: transcript sync hook for user-generated outbound ClientHello frames only (do not call for payloads returned by `popOutboundQuicHandshake()`).
- `peerQuicTransportParameters()`: returns the peer QUIC TP bytes captured during handshake validation.
- `snapshotQuicSecrets()`: exports currently available handshake/application traffic secrets.

Example secret-export -> key-derivation path:

```zig
const snap = engine.snapshotQuicSecrets();
if (snap.application_write) |sec| {
    const ts = try zigtls.quic.tls13.trafficSecretFromBytes(
        snap.suite,
        sec.bytes[0..sec.len],
    );
    const keys = try zigtls.quic.tls13.derivePacketProtectionKeys(snap.suite, &ts);
    _ = keys; // install into your QUIC packet protection path
}
```

Companion transport-engine example code (packet/recovery/session glue) lives in:
- `../zigtls-test-quic/src/quic/*.zig`
- `../zigtls-test-quic/src/main.zig`

## Production gate commands

Base regression gate:

```bash
zig build test
```

QUIC helper regression subset:

```bash
zig test src/quic.zig
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
