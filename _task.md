# Production-Grade TLS 1.3 in Zig - Implementation Task Specification

## 1. Objective
Deliver a production-grade TLS 1.3 library in Zig with security-first defaults, strong interoperability, and deterministic testability.

Primary outcomes:
- Correct TLS 1.3 behavior per RFC 8446 on both client and server paths.
- Audit-friendly architecture (explicit state machine, explicit allocations, transport-independent core).
- Hardened negative-path handling (malformed input, illegal transitions, truncation, replay).
- Reproducible verification pipeline (interop + fuzz + regression corpus).

## 2. Scope and Boundaries
### In Scope (v1 MUST)
- TLS 1.3 only.
- Client and server modes.
- Sans-I/O core engine (buffer-in / buffer-out, no socket ownership).
- Record layer + handshake + key schedule + alerts.
- X.509 path validation engine with RFC 5280-critical checks.
- Session tickets/PSK resumption.
- 0-RTT support only with mandatory anti-replay controls.

### Out of Scope (v1)
- TLS 1.2 fallback.
- QUIC glue layer.
- Custom/legacy cipher suites.
- Non-standard protocol extensions.

### Next Phase (v2 SHOULD)
- Extended policy validation coverage.
- AIA fetching for missing intermediates.
- Formal-method-assisted proofs for selected components.

## 3. Architectural Requirements (Non-Negotiable)
### 3.1 Sans-I/O Core
- Core TLS engine must not perform network I/O.
- External runtime feeds encrypted bytes and drains TLS output explicitly.
- Same core must work with sync and async runtimes.

### 3.2 Explicit Allocation Discipline
- Every API that allocates must accept an allocator.
- Handshake-scoped transient data: `ArenaAllocator`-based lifecycle.
- Record/data path: fixed buffers or reusable pool; avoid per-record heap churn.
- Document per-connection memory ceiling and enforce limits.

### 3.3 Linearized State Machine
- Client/server handshake states represented as explicit finite states.
- All message transitions validated centrally.
- Unexpected message or state jump must emit spec-correct alert and fail closed.

### 3.4 Crypto Path Discipline
- Use vetted primitives; no ad-hoc crypto primitive reimplementation.
- Constant-time handling for secret-dependent operations.
- Key material zeroization on lifecycle end.

## 4. Protocol Feature Requirements
### 4.1 Core TLS 1.3
- Full 1-RTT handshake flow.
- Mandatory support:
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- Key schedule correctness (early/handshake/master/traffic secrets).

### 4.2 Required Advanced Flows
- HelloRetryRequest (HRR) fully implemented and tested.
- KeyUpdate handling for long-lived sessions.
- close semantics hardened:
  - TCP FIN without authenticated `close_notify` must not be treated as clean EOF.

### 4.3 Session Resumption and 0-RTT
- PSK binder verification required.
- 0-RTT disabled by default.
- If enabled, server anti-replay protection is mandatory (e.g., Bloom filter + ticket/window policy).
- API must let application explicitly mark idempotent operations eligible for early data.

### 4.4 Post-Quantum Readiness
- Design group negotiation and key-share plumbing to support hybrid KEX.
- Prioritize `X25519MLKEM768` integration path.
- Keep feature gated until interoperability and performance criteria are met.

## 5. Certificate and Trust Validation Requirements
### 5.1 RFC 5280-Critical Validation
- Enforce Basic Constraints for CA chain elements.
- Enforce Key Usage / Extended Key Usage for server auth/client auth contexts.
- SAN hostname verification mandatory.
- Name constraints support required for constrained CAs.

### 5.2 Revocation and Freshness
- OCSP stapling parse and validate path in client mode.
- Fail/soft-fail policy configurable, default policy documented.

### 5.3 Trust Store Integration
- Platform trust-anchor loading strategy must be explicit and testable.
- Deterministic fallback path for custom trust bundles.

## 6. API and Module Design
Required modules (minimum):
- `record`
- `handshake`
- `keyschedule`
- `state`
- `alerts`
- `certificate_validation`
- `session`

API constraints:
- Typed config with safe defaults.
- Separation between high-level convenience API and low-level engine API.
- Clear error taxonomy (decode, alert, cert, policy, internal).
- Debug-only key logging callback gated explicitly.

## 7. Security Hardening Checklist
Must satisfy before release candidate:
- Parser strictness on length, duplication, and extension legality.
- Downgrade protections validated.
- Alert behavior matches TLS 1.3 semantics.
- Side-channel review completed for timing-sensitive paths.
- Secret lifecycle policy documented and tested.
- Defensive limits enforced for record, handshake, and certificate sizes.

## 8. Verification Strategy and Release Gates
### 8.1 Test Layers
- Unit tests:
  - HKDF labels, transcript evolution, Finished verify_data, FSM transitions.
- Negative tests:
  - malformed records, invalid signatures, bad binders, illegal transitions.
- Interop:
  - matrix against OpenSSL, BoringSSL (BoGo), rustls, NSS.
- Fuzzing:
  - handshake parser, record parser, state mutation corpus.
- Regression corpus:
  - all historical crashers must remain in CI replay set.

### 8.2 BoGo Requirement
- Implement shim compatible with BoringSSL test runner.
- Track pass/fail by category and require no unresolved critical failures.

### 8.3 Release Gate (Do Not Ship Unless)
- RFC requirement matrix complete and traceable to tests.
- Interop matrix green at required profile.
- Fuzzing stable with no unresolved high/critical crash.
- Security review findings triaged and fixed/accepted with rationale.

## 9. Performance and Resource Targets
Define and continuously measure:
- Handshake latency budget (P50/P99).
- Bulk data throughput by cipher suite.
- CPU hotspots (crypto vs parser vs state transitions).
- Memory per active connection.

Performance constraints:
- No avoidable copies in record hot path.
- Avoid allocator churn in steady-state data transfer.

## 10. Execution Plan
### Phase 0: Spec Traceability Foundation
- Build RFC 8446 requirement matrix (`MUST/SHOULD -> module -> tests`).
- Lock module boundaries and error taxonomy.

### Phase 1: Sans-I/O Core + Handshake Baseline
- Implement record + handshake + key schedule + FSM baseline.
- Client/server happy path with strict parser checks.

### Phase 2: Production Features
- HRR, KeyUpdate, tickets/PSK, extension coverage (SNI/ALPN/groups).
- Certificate validation depth and trust store integration.

### Phase 3: Security Hardening
- 0-RTT anti-replay, OCSP stapling validation, truncation-attack handling.
- Side-channel audit and secret lifecycle enforcement.

### Phase 4: Verification and Readiness
- BoGo integration and interop closure.
- Continuous fuzzing + regression corpus governance.
- Performance tuning, docs freeze, release checklist sign-off.

## 11. Deliverables
- `docs/rfc8446-matrix.md`
- TLS 1.3 core module tree under `src/tls13/`
- Interop harness scripts and CI jobs
- Fuzz targets and regression corpus tooling
- Security hardening checklist and release runbook

## 12. Definition of Done (DoD)
A build is production-ready only if all conditions hold:
- Spec traceability matrix complete.
- Mandatory protocol features implemented (including HRR and KeyUpdate).
- Required certificate validations active by default policy.
- Interop and BoGo gates satisfied.
- Fuzzing and negative tests stable.
- Security and performance acceptance criteria met and documented.
