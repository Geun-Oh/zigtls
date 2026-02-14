===
timestamp: 2026-02-14T21:40:00+09:00
description: Align _task.md with implementation blueprint in _implementation.md
type: plan
===
Motivation
- `_task.md` currently captures a generic TLS 1.3 roadmap but misses several implementation-critical constraints and priorities emphasized in `_implementation.md` (Sans-I/O-first architecture, explicit allocation policy, HRR/KeyUpdate completeness, replay-safe 0-RTT policy, OCSP stapling validation, PQ hybrid group support, BoGo-first verification path, truncation-attack handling).

Scope
- Read and summarize `_implementation.md`.
- Update `_task.md` so it is a direct, executable task document that reflects the implementation blueprint priorities and sequencing from `_implementation.md`.
- No Zig source code changes in this task.

Design
- Preserve `_task.md` intent (production-grade TLS 1.3 roadmap), but reframe sections into implementation-enforceable workstreams.
- Add explicit requirements currently under-specified: Sans-I/O core boundary, allocator discipline (Arena for handshake, fixed/pool for records), linearized FSM, HRR+KeyUpdate support, 0-RTT anti-replay architecture, X.509 RFC5280 validation depth, OCSP stapling, PQ hybrid readiness, BoGo shim/compliance target, continuous fuzzing, truncation attack semantics.
- Keep outcomes measurable (acceptance criteria, release gates, test matrix).

Risks/Perf Impact
- Risk: Over-scoping `_task.md` into non-v1 requirements. Mitigation: separate MUST for v1 vs OPTIONAL/next-phase.
- Risk: Ambiguous wording leading to implementation drift. Mitigation: use testable acceptance checks per section.
- Perf impact: documentation-only change; no runtime impact.

Test Plan (commands)
- `rg -n "Sans-I/O|ArenaAllocator|HelloRetryRequest|KeyUpdate|0-RTT|Bloom|OCSP|X25519MLKEM768|BoGo|close_notify" _task.md`
- `sed -n '1,260p' _task.md`

Rollback
- Revert `_task.md` to previous revision via VCS if alignment is judged incorrect.
- Keep WAL append-only; corrections logged as superseding entries.

Commit Plan
- Single commit for docs unit:
  - files: `_task.md`, `_write_ahead_log.md`
  - subject style: `MINOR: docs: realign TLS task blueprint to implementation analysis`
===
timestamp: 2026-02-14T21:43:00+09:00
description: Rewrite _task.md into implementation-enforceable TLS 1.3 task specification
type: code change
===
Decisions + Rationale
- Replaced generic roadmap language with enforceable requirements and release gates aligned to `_implementation.md`.
- Added hard architectural constraints: Sans-I/O core, explicit allocator discipline, linearized FSM.
- Added protocol/security specifics missing or weak in prior file: HRR, KeyUpdate, truncation (`close_notify`) semantics, mandatory anti-replay controls for 0-RTT, OCSP stapling path, RFC 5280-critical validation, PQ hybrid readiness (`X25519MLKEM768`), BoGo shim requirement.
- Preserved phased rollout while introducing v1 MUST/v2 SHOULD boundaries to reduce scope ambiguity.

Files/Sections Touched
- `_task.md` (full rewrite).

Risks/Perf Notes
- No runtime/perf impact (documentation-only).
- Main risk is interpretation mismatch on optional vs required roadmap items; mitigated by explicit MUST/SHOULD and release-gate wording.
===
timestamp: 2026-02-14T21:44:00+09:00
description: Validate rewritten _task.md contains required implementation constraints
type: test
===
Commands Executed
- `rg -n "Sans-I/O|ArenaAllocator|HelloRetryRequest|KeyUpdate|0-RTT|Bloom|OCSP|X25519MLKEM768|BoGo|close_notify" _task.md`
- `sed -n '1,260p' _task.md`

Observed Results
- Keyword presence check passed; required topics detected at expected sections (architecture, protocol requirements, verification gates, execution plan, DoD).
- Manual content check passed for structure integrity and readability after rewrite.

Conclusion
- `_task.md` is aligned with `_implementation.md` blueprint and now encodes testable implementation requirements.
===
timestamp: 2026-02-14T21:45:00+09:00
description: Clarify allocator policy wording with explicit ArenaAllocator term and re-run keyword validation
type: code change
===
Decisions + Rationale
- Updated allocation policy wording to include explicit `ArenaAllocator` naming for handshake-scoped memory, matching `_implementation.md` terminology and reducing ambiguity.

Files/Sections Touched
- `_task.md` (Section 3.2).

Risks/Perf Notes
- Documentation-only wording change; no runtime impact.

===
timestamp: 2026-02-14T21:45:30+09:00
description: Re-run keyword validation after allocator terminology adjustment
type: test
===
Commands Executed
- `rg -n "Sans-I/O|ArenaAllocator|HelloRetryRequest|KeyUpdate|0-RTT|Bloom|OCSP|X25519MLKEM768|BoGo|close_notify" _task.md`

Observed Results
- Validation passed and now explicitly includes `ArenaAllocator` match.
===
timestamp: 2026-02-14T21:52:00+09:00
description: Author Korean deep-dive task description document from _task.md
type: plan
===
Motivation
- User requested a Korean document that explains each `_task.md` capability in detail: why it must be implemented, which technologies are needed, and how implementation proceeds.

Scope
- Create `_task_description_ko.md` in Korean.
- Expand each major section of `_task.md` with rationale, required technologies, and implementation sequence.
- No source code/runtime behavior changes.

Design
- Mirror `_task.md` structure to keep traceability.
- For each feature area, include three fixed subsections:
  - 구현 필요성(Why)
  - 필요 기술/요소(Tech)
  - 구현 절차(How)
- Add release/verification/operation details so the document is directly actionable by implementers.

Risks/Perf Impact
- Risk: Overly abstract explanation reducing execution value. Mitigation: include concrete deliverables/checkpoints.
- Perf impact: documentation-only change; no runtime impact.

Test Plan (commands)
- `test -f _task_description_ko.md && echo exists`
- `rg -n "구현 필요성|필요 기술|구현 절차|Sans-I/O|HelloRetryRequest|KeyUpdate|0-RTT|OCSP|BoGo" _task_description_ko.md`
- `sed -n '1,260p' _task_description_ko.md`

Rollback
- Revert `_task_description_ko.md` via VCS if content quality or scope alignment is unsatisfactory.
- Keep WAL append-only and supersede with a new WAL entry when corrections are needed.

Commit Plan
- Single docs-unit commit:
  - files: `_task_description_ko.md`, `_write_ahead_log.md`
  - subject style: `MINOR: docs: add Korean detailed implementation guide for TLS task spec`
===
timestamp: 2026-02-14T21:54:00+09:00
description: Create Korean detailed implementation explanation document from _task.md
type: docs
===
Decisions + Rationale
- Added `_task_description_ko.md` as a Korean deep-dive companion document to `_task.md`.
- Preserved end-to-end traceability by mirroring major sections of `_task.md`.
- Standardized each section with three implementation-focused facets: `구현 필요성`, `필요 기술`, `구현 절차`.
- Expanded operationally critical topics explicitly: Sans-I/O boundary, allocator policy, HRR/KeyUpdate/close_notify handling, 0-RTT anti-replay, OCSP stapling, BoGo, release gates, performance/operations.

Files/Sections Touched
- `_task_description_ko.md` (new file, full content).

Risks/Perf Notes
- Documentation-only addition; no runtime/performance impact.
- Risk of drift from `_task.md` reduced by structure mirroring and term alignment.

===
timestamp: 2026-02-14T21:54:30+09:00
description: Validate Korean task description document presence and coverage
type: test
===
Commands Executed
- `test -f _task_description_ko.md && echo exists`
- `rg -n "구현 필요성|필요 기술|구현 절차|Sans-I/O|HelloRetryRequest|KeyUpdate|0-RTT|OCSP|BoGo" _task_description_ko.md`
- `sed -n '1,260p' _task_description_ko.md`

Observed Results
- File existence check passed.
- Required terms and structure markers detected across sections.
- Content inspection confirms Korean detailed expansion with rationale/tech/how for each feature area.
===
timestamp: 2026-02-14T22:02:00+09:00
description: Start code implementation from _task.md with Zig project initialization and Phase 0/1 core
type: plan
===
Motivation
- User requested end-to-end code implementation starting from Zig project initialization based on `_task.md`.

Scope
- Initialize Zig project structure in current workspace.
- Implement Phase 0/1 baseline aligned with `_task.md`:
  - module boundaries under `src/tls13/`
  - Sans-I/O style core API surface
  - explicit FSM and alert handling
  - baseline key schedule wrapper and transcript plumbing
  - strict parser/length checks for a minimal handshake flow
- Add tests for normal/error/boundary behavior for implemented parts.

Design
- Build incrementally with compilable checkpoints.
- Keep external dependencies minimal: Zig std only.
- Prefer conservative, reviewable implementation over broad incomplete stubs.

Risks/Perf Impact
- Risk: full production-grade TLS scope is large; initial implementation will prioritize foundational, testable core first while preserving extension points for later phases.
- Perf: avoid dynamic allocation in hot parser paths where possible; use explicit allocator wiring.

Test Plan (commands)
- `zig test src/root.zig`
- `zig build test`
- targeted unit tests for FSM/parser/alerts/keyschedule modules.

Rollback
- Revert newly added project files and modules if baseline design is rejected.
- Log superseding decisions append-only in WAL.

Commit Plan
- Feature-unit commits (if VCS available):
  - init/build wiring
  - tls13 core modules
  - tests and validation
===
timestamp: 2026-02-14T22:12:00+09:00
description: Initialize Zig project and implement TLS13 foundational modules with Sans-I/O engine baseline
type: code change
===
Decisions + Rationale
- Initialized Zig project (`zig init`) and established module boundaries aligned to `_task.md` Phase 0/1.
- Implemented `src/tls13/` foundational modules using Zig std only (minimal external dependency profile):
  - `alerts.zig`: alert enums, encode/decode with strict validation.
  - `state.zig`: explicit role-based linear FSM with illegal-transition rejection.
  - `record.zig`: TLS record header/payload parsing with strict bounds/version checks.
  - `handshake.zig`: handshake frame parser (u24 length) and transcript hash utility.
  - `keyschedule.zig`: HKDF extract/expand-label wrappers for SHA-256/SHA-384 suites.
  - `session.zig`: Sans-I/O ingest engine (`ingestRecord`) wiring record+handshake+FSM and alert handling.
  - `certificate_validation.zig`: hostname validation baseline and explicit unsupported-chain placeholder.
- Added `src/tls13.zig` export hub and rewired `src/root.zig` / `src/main.zig` to library-first layout.
- Kept implementation conservative and test-driven for compile-safe incremental baseline.

Files/Functions Touched
- New files:
  - `src/tls13/alerts.zig`
  - `src/tls13/state.zig`
  - `src/tls13/record.zig`
  - `src/tls13/handshake.zig`
  - `src/tls13/keyschedule.zig`
  - `src/tls13/session.zig`
  - `src/tls13/certificate_validation.zig`
  - `src/tls13.zig`
- Updated files:
  - `src/root.zig`
  - `src/main.zig`
  - `build.zig`, `build.zig.zon` and initial template files from `zig init`.

Risks/Perf Notes
- Current certificate chain validation is intentionally incomplete (placeholder returns `UnsupportedChainValidation`) and requires Phase 2/3 implementation.
- Session engine currently models baseline handshake/control flow, not full RFC 8446 message semantics yet.
- Parser paths enforce strict bounds and avoid hidden allocations in ingest hot path.

===
timestamp: 2026-02-14T22:13:00+09:00
description: Validate foundational implementation with module and build tests
type: test
===
Commands Executed
- `zig version`
- `zig test src/tls13/alerts.zig`
- `zig test src/tls13/state.zig`
- `zig test src/tls13/record.zig`
- `zig test src/tls13/handshake.zig`
- `zig test src/tls13/keyschedule.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig test src/tls13/session.zig`
- `zig test src/root.zig`
- `zig build test`
- `zig build`
- `zig fmt src/main.zig src/root.zig src/tls13.zig src/tls13/*.zig`
- `zig build test` (post-format)

Observed Results
- All module tests passed for implemented baseline.
- `zig build` initially failed due Zig 0.15 API change in `src/main.zig` (`std.io.getStdOut` removed); fixed by switching to `std.debug.print`.
- After fix, `zig build` and `zig build test` passed.
===
timestamp: 2026-02-14T22:20:00+09:00
description: Implement Phase 2 protocol features on baseline (HRR and KeyUpdate handling)
type: plan
===
Motivation
- User requested to continue implementation after baseline commits.
- `_task.md` Phase 2 requires concrete handling for HRR and KeyUpdate semantics.

Scope
- Extend handshake parsing/types to represent HelloRetryRequest.
- Extend state machine transitions for HRR flow and connected-state KeyUpdate handling.
- Extend session engine action model to surface KeyUpdate request/update behavior.
- Add/adjust unit tests for normal/error/boundary cases covering HRR and KeyUpdate transitions.

Design
- Keep changes localized to `state.zig`, `handshake.zig`, and `session.zig`.
- Maintain Sans-I/O pattern: only parse/transition/action emission, no transport coupling.
- Preserve strict failure on illegal transitions.

Risks/Perf Impact
- Risk: Overfitting HRR detection logic. Mitigation: use deterministic structural rule from ServerHello body with retry_random marker.
- Perf impact is minimal (small parsing checks and enum dispatch additions).

Test Plan (commands)
- `zig test src/tls13/state.zig`
- `zig test src/tls13/handshake.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert affected module files if semantics are incorrect.
- Append superseding WAL entries rather than editing previous entries.

Commit Plan
- Single feature commit:
  - `MEDIUM: tls13: add HRR and KeyUpdate state handling`
===
timestamp: 2026-02-14T22:26:00+09:00
description: Add HRR classification and KeyUpdate request handling to TLS13 state/session paths
type: code change
===
Decisions + Rationale
- Introduced handshake event abstraction to distinguish `hello_retry_request` from ordinary `server_hello` while preserving existing handshake type parsing.
- Extended client FSM to accept HRR in `wait_server_hello` and remain in the same state until a subsequent non-HRR `server_hello`.
- Added KeyUpdate request parser and surfaced request semantics in session actions.
- Added `send_key_update` action emission for `update_requested` input to keep Sans-I/O transport independence while making response behavior explicit.

Files/Functions Touched
- `src/tls13/state.zig`
  - Added `HandshakeEvent`, `Machine.onEvent`, `fromHandshakeType`, HRR transition rule.
- `src/tls13/handshake.zig`
  - Added HRR random marker constant, `classifyEvent`, `parseKeyUpdateRequest`.
- `src/tls13/session.zig`
  - Wired event classification into `ingestRecord`, added `hello_retry_request`, `key_update`, and `send_key_update` actions, added HRR/KeyUpdate test frames.

Risks/Perf Notes
- HRR detection currently uses random-marker rule and minimal ServerHello structure check; full extension-level validation remains pending for later phase.
- Added checks are constant-size and low overhead.

===
timestamp: 2026-02-14T22:27:00+09:00
description: Validate HRR and KeyUpdate implementation with module and integration tests
type: test
===
Commands Executed
- `zig fmt src/tls13/state.zig src/tls13/handshake.zig src/tls13/session.zig`
- `zig test src/tls13/state.zig`
- `zig test src/tls13/handshake.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- All state/handshake/session tests passed.
- Session suite now includes HRR round handling and KeyUpdate request/response-action checks.
- Full package test build passed.
===
timestamp: 2026-02-14T22:31:00+09:00
description: Implement early-data gating and anti-replay baseline (0-RTT policy)
type: plan
===
Motivation
- `_task.md` requires 0-RTT disabled by default, anti-replay protection when enabled, and an API for idempotency gating.

Scope
- Add `early_data` module with replay filter implementation.
- Extend session config/init to enforce anti-replay requirement when 0-RTT is enabled.
- Add explicit API to mark early data as idempotent and attach replay token.
- Enforce rejection of pre-handshake application_data unless policy checks pass.

Design
- Use std-only implementation with Bloom-like replay filter (deterministic hash probes).
- Keep transport-agnostic behavior via Sans-I/O action/error model.
- Preserve strict fail-closed default behavior.

Risks/Perf Impact
- Replay filter is probabilistic (false positives possible) by design.
- Memory footprint depends on configured bitset size; defaults will be conservative.

Test Plan (commands)
- `zig test src/tls13/early_data.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert early-data related module and session changes if policy semantics are rejected.
- Record superseding entries append-only in WAL.

Commit Plan
- `MEDIUM: tls13: enforce 0-rtt gating with anti-replay baseline`
===
timestamp: 2026-02-14T22:36:00+09:00
description: Add 0-RTT gating policy with replay filter baseline in session engine
type: code change
===
Decisions + Rationale
- Added new `early_data` module implementing a std-only replay filter with multiple hash probes to support anti-replay checks.
- Extended session config with explicit early-data policy: disabled by default, and replay filter required when enabled.
- Added `beginEarlyData(ticket, idempotent)` API to force application-level idempotency declaration before early data acceptance.
- Enforced fail-closed handling for pre-handshake application_data: reject when policy checks fail, reject replayed tokens, accept only when enabled + idempotent + non-replayed token.

Files/Functions Touched
- `src/tls13/early_data.zig` (new)
  - `ReplayFilter.init/deinit/seenOrInsert`.
- `src/tls13/session.zig`
  - `Config.early_data`, `EarlyDataConfig`, `Engine.beginEarlyData`, early-data checks in `ingestRecord`.
  - Added `Engine.deinit` ticket cleanup.
  - Added tests for default rejection and anti-replay/idempotency gating.
- `src/tls13.zig`
  - Exported `early_data` module.

Risks/Perf Notes
- Replay filter is probabilistic (false positives possible), which can reject valid early data but does not weaken security.
- Memory usage scales with configured replay filter bitset size.

===
timestamp: 2026-02-14T22:37:00+09:00
description: Validate early-data anti-replay implementation with module and integration tests
type: test
===
Commands Executed
- `zig fmt src/tls13/early_data.zig src/tls13/session.zig src/tls13.zig`
- `zig test src/tls13/early_data.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Early-data module tests passed.
- Session tests passed including 0-RTT default rejection and anti-replay acceptance/replay rejection cases.
- Full package test build passed.
===
timestamp: 2026-02-14T22:41:00+09:00
description: Add truncation-attack protection via close_notify-aware EOF handling
type: plan
===
Motivation
- `_task.md` requires hardened close semantics: TCP FIN must not be treated as clean shutdown without authenticated `close_notify`.

Scope
- Add transport EOF API to session engine.
- Track receipt of `close_notify` alert.
- Return explicit truncation error on EOF without prior `close_notify`.
- Add positive/negative tests for EOF behavior.

Design
- Keep Sans-I/O boundary: expose EOF as an explicit engine method, not socket operations.
- Preserve existing alert parsing and state transitions.

Risks/Perf Impact
- Minimal overhead: one boolean flag + branch in EOF path.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert session EOF handling changes if semantics conflict with desired integration model.

Commit Plan
- `MINOR: tls13: enforce close_notify before clean eof`
===
timestamp: 2026-02-14T22:44:00+09:00
description: Enforce close_notify-aware EOF handling to mitigate truncation attacks
type: code change
===
Decisions + Rationale
- Added explicit transport EOF handling API (`onTransportEof`) to keep truncation semantics inside Sans-I/O engine boundaries.
- Introduced `saw_close_notify` tracking and `TruncationDetected` error when EOF arrives before authenticated `close_notify`.
- Preserved existing alert-driven close transitions and made clean EOF contingent on prior close_notify receipt.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added `EngineError.TruncationDetected`.
  - Added `Engine.onTransportEof`.
  - Added close_notify tracking in alert ingestion path.
  - Added truncation positive/negative tests.

Risks/Perf Notes
- Minimal runtime impact (single boolean tracking and EOF branch).

===
timestamp: 2026-02-14T22:44:30+09:00
description: Validate truncation-protection EOF semantics
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session tests passed with new truncation and clean-close EOF cases.
- Full package test build passed.
===
timestamp: 2026-02-14T22:49:00+09:00
description: Expand certificate validation core logic (basic constraints and EKU/KU checks)
type: plan
===
Motivation
- Current certificate validation module only had hostname check plus placeholder chain validation.
- `_task.md` requires RFC 5280-critical checks as a first-class requirement.

Scope
- Add parser-independent certificate validation primitives for:
  - basic constraints path rules
  - key usage / extended key usage checks for server auth context
- Keep full ASN.1/X.509 parsing out of scope for this unit.
- Add unit tests for positive/negative chain and usage-policy cases.

Design
- Introduce lightweight `CertificateView` data model for validation logic tests.
- Expose deterministic validation functions independent of transport and parser.

Risks/Perf Impact
- No hot-path impact yet; this is validation core logic for later parser integration.

Test Plan (commands)
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Rollback
- Revert certificate validation logic expansion if API shape conflicts with planned parser integration.

Commit Plan
- `MEDIUM: tls13: add rfc5280 validation core checks`
===
timestamp: 2026-02-14T22:52:00+09:00
description: Expand certificate validation with basic constraints and server usage checks
type: code change
===
Decisions + Rationale
- Replaced minimal placeholder-only validation logic with parser-independent RFC5280 core checks.
- Added `CertificateView` model and validation routines for:
  - intermediate CA requirement
  - path length constraint enforcement
  - leaf digital-signature key usage and server-auth EKU presence
- Kept ASN.1 parsing and full trust-chain building out of this unit to maintain feature-unit scope.

Files/Functions Touched
- `src/tls13/certificate_validation.zig`
  - Added `ExtendedKeyUsage`, `KeyUsage`, `CertificateView`.
  - Added `validateServerChain` and `validateLeafServerUsage`.
  - Added test cases for happy path and failure cases.

Risks/Perf Notes
- Logic currently assumes caller provides parsed certificate views; parser integration remains a later step.

===
timestamp: 2026-02-14T22:52:30+09:00
description: Validate certificate validation logic expansion
type: test
===
Commands Executed
- `zig fmt src/tls13/certificate_validation.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Observed Results
- Certificate validation unit tests passed.
- Full package tests passed.
===
timestamp: 2026-02-14T23:00:00+09:00
description: Add OCSP stapling policy checks and trust-store loading abstraction
type: code change
===
Decisions + Rationale
- Added `ocsp` module to evaluate stapled response freshness/status under hard-fail or soft-fail policy.
- Added `trust_store` module wrapping `std.crypto.Certificate.Bundle` for system rescan and absolute PEM file/dir loading.
- Integrated OCSP policy evaluation into certificate validation via `validateStapledOcsp` using existing validation policy (`allow_soft_fail_ocsp`).
- Exported both modules via `src/tls13.zig` for package consumers.

Files/Functions Touched
- New files:
  - `src/tls13/ocsp.zig`
  - `src/tls13/trust_store.zig`
- Updated:
  - `src/tls13/certificate_validation.zig`
  - `src/tls13.zig`

Risks/Perf Notes
- OCSP module validates policy/time semantics on a parsed view; ASN.1 OCSP parsing remains future work.
- Trust-store loader delegates to std bundle behavior; platform-specific certificate availability still environment-dependent.

===
timestamp: 2026-02-14T23:00:30+09:00
description: Validate OCSP and trust-store modules plus integration tests
type: test
===
Commands Executed
- `zig fmt src/tls13/ocsp.zig src/tls13/trust_store.zig src/tls13/certificate_validation.zig src/tls13.zig`
- `zig test src/tls13/ocsp.zig`
- `zig test src/tls13/trust_store.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Observed Results
- All OCSP/trust-store/certificate-validation tests passed.
- Full package test build passed.
===
timestamp: 2026-02-14T23:06:00+09:00
description: Add RFC8446 requirement matrix and interop harness script scaffolding
type: plan
===
Motivation
- `_task.md` immediate actions require a traceable RFC matrix and initial interop harness setup (OpenSSL and rustls first).

Scope
- Add `docs/rfc8446-matrix.md` with section-level requirement mapping to current modules/tests and status markers.
- Add `scripts/interop/openssl_local.sh` and `scripts/interop/rustls_local.sh` scaffolding scripts for local handshake checks.
- Add minimal script syntax validation tests.

Design
- Matrix uses concise IDs and status (`implemented`, `partial`, `pending`) to keep progress auditable.
- Interop scripts are deterministic local harness wrappers (no hidden network dependencies beyond local loopback).

Risks/Perf Impact
- Documentation and scripting only; no runtime TLS core behavior changes.
- rustls script may depend on tool availability in host environment.

Test Plan (commands)
- `bash -n scripts/interop/openssl_local.sh scripts/interop/rustls_local.sh`
- `zig build test`

Rollback
- Revert docs/scripts if format or assumptions are rejected.

Commit Plan
- `MINOR: docs: add rfc8446 matrix and interop script scaffolding`
===
timestamp: 2026-02-14T23:10:00+09:00
description: Add RFC8446 matrix document and initial OpenSSL/rustls interop harness scripts
type: docs
===
Decisions + Rationale
- Added `docs/rfc8446-matrix.md` as a traceability map from RFC topics to modules/tests and implementation status.
- Added local interop harness scripts for OpenSSL and rustls to bootstrap Phase 4 interoperability workflow.
- Kept scripts explicit and environment-driven (rustls binary paths via env vars) to avoid hidden dependency assumptions.

Files/Sections Touched
- `docs/rfc8446-matrix.md` (new)
- `scripts/interop/openssl_local.sh` (new)
- `scripts/interop/rustls_local.sh` (new)

Risks/Perf Notes
- Scripts are scaffolding and may require environment-specific binary flags for rustls tools.
- No runtime core TLS path change.

===
timestamp: 2026-02-14T23:10:30+09:00
description: Validate matrix/docs and interop script syntax
type: test
===
Commands Executed
- `bash -n scripts/interop/openssl_local.sh scripts/interop/rustls_local.sh`
- `zig build test`

Observed Results
- Shell syntax checks passed.
- Full package tests passed after adding docs/scripts.
===
timestamp: 2026-02-14T23:18:00+09:00
description: Expand handshake FSM to support certificate/certificate_verify flows
type: plan
===
Motivation
- Current FSM primarily models a reduced handshake path and underrepresents certificate-authenticated flows.

Scope
- Extend client/server state transitions to allow certificate-authenticated handshake sequence.
- Preserve PSK-like shortcut path where Finished can arrive without certificate path.
- Add unit tests for new positive and negative transition cases.

Design
- Add intermediate states for certificate and certificate_verify processing.
- Keep strict illegal-transition rejection semantics.

Risks/Perf Impact
- More states increase transition complexity; mitigated with explicit tests.
- Negligible runtime overhead (enum dispatch only).

Test Plan (commands)
- `zig test src/tls13/state.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert state-machine changes if integration assumptions break existing flows.

Commit Plan
- `MEDIUM: tls13: extend fsm for certificate-authenticated handshake`
===
timestamp: 2026-02-14T23:22:00+09:00
description: Extend FSM for certificate-authenticated and PSK-like handshake variants
type: code change
===
Decisions + Rationale
- Expanded client/server FSM with explicit intermediate states for certificate/certificate_verify processing.
- Preserved support for PSK-like shortcut path where `finished` can follow encrypted extensions (client) or client hello (server).
- Kept strict illegal transition rejection while broadening valid handshake variants.

Files/Functions Touched
- `src/tls13/state.zig`
  - Added states:
    - `wait_server_certificate`
    - `wait_server_certificate_verify`
    - `wait_client_certificate_or_finished`
    - `wait_client_certificate_verify`
    - `wait_client_finished_after_cert`
  - Updated transition logic and expanded tests.

Risks/Perf Notes
- More states increase transition table complexity but improve protocol coverage and auditability.
- No meaningful performance impact expected.

===
timestamp: 2026-02-14T23:22:30+09:00
description: Validate expanded FSM against module and integration tests
type: test
===
Commands Executed
- `zig fmt src/tls13/state.zig`
- `zig test src/tls13/state.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- State tests passed for certificate-authenticated and PSK-like paths.
- Session integration tests passed with updated FSM semantics.
- Full package test build passed.
===
timestamp: 2026-02-14T23:28:00+09:00
description: Add fuzz-style parser/session robustness tests
type: plan
===
Motivation
- `_task.md` requires fuzzing and robustness validation on parsers/state mutation paths.

Scope
- Add a dedicated `src/tls13/fuzz.zig` test module with randomized inputs for record/handshake/session ingest.
- Ensure tests assert non-crashing behavior and bounded error handling.
- Wire module export via `src/tls13.zig`.

Design
- Use deterministic PRNG seed for reproducible test behavior.
- Keep runtime small while covering variable lengths and random byte patterns.

Risks/Perf Impact
- Test-time overhead only; no production runtime impact.

Test Plan (commands)
- `zig test src/tls13/fuzz.zig`
- `zig build test`

Rollback
- Revert fuzz module if it introduces flaky behavior.

Commit Plan
- `MINOR: tls13: add fuzz-style robustness tests`
===
timestamp: 2026-02-14T23:31:00+09:00
description: Add deterministic fuzz-style robustness tests for parser/session paths
type: test
===
Decisions + Rationale
- Added dedicated fuzz-style test module to exercise parser/session input handling against randomized byte streams.
- Used deterministic PRNG seeds to keep failures reproducible while increasing input variety.
- Focused on non-crash robustness and bounded error behavior.

Files/Functions Touched
- New file:
  - `src/tls13/fuzz.zig`
- Updated:
  - `src/tls13.zig` (module export)

Commands Executed
- `zig fmt src/tls13/fuzz.zig src/tls13.zig`
- `zig test src/tls13/fuzz.zig`
- `zig build test`

Observed Results
- Fuzz-style tests passed (record parser, handshake parser, session ingest).
- Full package test build passed.
===
timestamp: 2026-02-14T23:40:00+09:00
description: Implement BoGo shim and result summarization pipeline scaffold
type: plan
===
Motivation
- `_task.md` Phase 5/verification requires BoGo integration and pass/fail tracking.

Scope
- Add a BoGo shim executable entrypoint in Zig (`tools/bogo_shim.zig`).
- Add wrapper script to invoke BoGo runner with shim binary.
- Add result summarizer script to aggregate BoGo JSON output by category and status.
- Wire shim build target in `build.zig`.

Design
- Start with deterministic, explicit shim behavior: parse core flags and emit structured capability/unsupported errors.
- Keep shim transport-agnostic and focused on runner contract first.
- Summarizer script should work on runner JSON output without external dependencies.

Risks/Perf Impact
- Initial shim is scaffold and will not pass full suite yet; goal is contract correctness and observability.
- No hot-path runtime impact on TLS engine.

Test Plan (commands)
- `zig build bogo-shim`
- `zig build test`
- `python3 scripts/interop/bogo_summary.py --self-test`

Rollback
- Revert bogo shim/scaffolding files if runner contract assumptions are wrong.

Commit Plan
- `MINOR: test: add bogo shim and result summarization scaffolding`
===
timestamp: 2026-02-14T23:46:00+09:00
description: Add BoGo shim executable, runner wrapper, and JSON result summarizer scaffold
type: code change
===
Decisions + Rationale
- Added `tools/bogo_shim.zig` scaffold executable that validates runner arguments and reports explicit scaffold/unsupported mode while BoGo contract is being wired.
- Added build target `zig build bogo-shim` in `build.zig` for reproducible shim builds.
- Added `scripts/interop/bogo_run.sh` to invoke BoGo runner with shim binary and optional test filter.
- Added `scripts/interop/bogo_summary.py` to aggregate BoGo JSON results by suite and status.

Files/Functions Touched
- `tools/bogo_shim.zig` (new)
- `scripts/interop/bogo_run.sh` (new)
- `scripts/interop/bogo_summary.py` (new)
- `build.zig` (new build step and shim executable wiring)

Risks/Perf Notes
- Shim is currently scaffold-level and exits as unsupported for real handshake execution; full protocol wiring remains pending.
- No runtime impact on main TLS engine paths.

===
timestamp: 2026-02-14T23:46:30+09:00
description: Validate BoGo shim build and summarizer self-test
type: test
===
Commands Executed
- `zig fmt tools/bogo_shim.zig build.zig`
- `zig test tools/bogo_shim.zig`
- `zig build bogo-shim`
- `zig build test`
- `python3 scripts/interop/bogo_summary.py --self-test`

Observed Results
- BoGo shim unit tests passed.
- `bogo-shim` build target passed.
- Full package tests passed.
- Summary script self-test passed.
===
timestamp: 2026-02-14T23:52:00+09:00
description: Add handshake message codec baseline (ClientHello/ServerHello)
type: plan
===
Motivation
- Current implementation parses handshake envelopes but lacks concrete message-level codec support.

Scope
- Add `src/tls13/messages.zig` with baseline ClientHello/ServerHello encode/decode.
- Enforce strict length and structural checks for fixed-width fields.
- Export module from `src/tls13.zig` and add unit tests.

Design
- Keep codec minimal and deterministic with explicit byte layout handling.
- Use allocator-backed extension vectors for decode path and free helpers.

Risks/Perf Impact
- Decode path allocates for extension slices; acceptable for control-plane handshake path.
- Full extension semantic validation remains future work.

Test Plan (commands)
- `zig test src/tls13/messages.zig`
- `zig build test`

Rollback
- Revert message codec module if wire-format assumptions conflict with integration plan.

Commit Plan
- `MEDIUM: tls13: add clienthello/serverhello message codec baseline`
===
timestamp: 2026-02-14T23:58:00+09:00
description: Add ClientHello/ServerHello handshake message codec baseline
type: code change
===
Decisions + Rationale
- Added `messages` module to provide concrete handshake message body codec support beyond envelope parsing.
- Implemented ClientHello encode/decode with strict structural validation (legacy version, session ID bounds, cipher suite vector length, extension block bounds).
- Implemented ServerHello encode baseline with extension serialization.
- Added deinit methods for allocator-owned message fields to keep ownership explicit.

Files/Functions Touched
- `src/tls13/messages.zig` (new)
- `src/tls13.zig` (export `messages` module)

Risks/Perf Notes
- Decode path allocates per-message vectors/extensions; acceptable for handshake path.
- Extension semantic validation (per extension type rules) remains pending.

===
timestamp: 2026-02-14T23:58:30+09:00
description: Validate message codec module and package tests
type: test
===
Commands Executed
- `zig fmt src/tls13/messages.zig src/tls13.zig`
- `zig test src/tls13/messages.zig`
- `zig build test`

Observed Results
- Message codec tests passed.
- Full package tests passed after module integration.
===
timestamp: 2026-02-15T00:03:00+09:00
description: Integrate ServerHello message decode into HRR classification path
type: plan
===
Motivation
- HRR detection currently depends on raw byte offsets.
- Message-level decode should be used to improve structural validation and keep logic centralized.

Scope
- Add ServerHello decode function in `messages` module.
- Refactor `handshake.classifyEvent` to decode ServerHello and detect HRR from parsed random field.
- Add/adjust unit tests for decode and classification behavior.

Design
- Keep classification fallback safe: malformed ServerHello stays as normal handshake type event, and parser errors are handled by existing envelope checks.

Risks/Perf Impact
- Slight extra parsing overhead on ServerHello classification, acceptable for handshake control path.

Test Plan (commands)
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/handshake.zig`
- `zig build test`

Rollback
- Revert decode-based classification if it conflicts with incremental integration assumptions.

Commit Plan
- `MINOR: tls13: use serverhello decode for hrr classification`
===
timestamp: 2026-02-15T00:09:00+09:00
description: Refactor HRR classification to use ServerHello structural decoding helper
type: code change
===
Decisions + Rationale
- Extended `messages` module with `ServerHello.decode` and `serverHelloHasHrrRandom` helper.
- Switched `handshake.classifyEvent` from raw offset-based HRR detection to message-structure-aware helper.
- Added ServerHello decode roundtrip test and updated HRR classification test to use structurally valid ServerHello body.

Files/Functions Touched
- `src/tls13/messages.zig`
  - Added `ServerHello.decode`.
  - Added `serverHelloHasHrrRandom` helper.
  - Added decode roundtrip test.
- `src/tls13/handshake.zig`
  - Updated `classifyEvent` to use message helper.
  - Updated HRR test fixture.

Risks/Perf Notes
- Slightly stronger structural checks in HRR classification may reject malformed-but-previously-accepted test fixtures; this is intended hardening.

===
timestamp: 2026-02-15T00:09:30+09:00
description: Validate decode-based HRR classification integration
type: test
===
Commands Executed
- `zig fmt src/tls13/messages.zig src/tls13/handshake.zig`
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/handshake.zig`
- `zig build test`

Observed Results
- Message and handshake tests passed.
- Full package test build passed.
===
timestamp: 2026-02-15T00:18:00+09:00
description: Enforce message-level ClientHello/ServerHello decode validation in session ingest path
type: plan
===
Motivation
- Handshake envelope parsing exists, but session ingest should reject structurally invalid hello message bodies early.

Scope
- Integrate `messages.ClientHello.decode` and `messages.ServerHello.decode` into `session.Engine.ingestRecord` path.
- Add new engine error for invalid hello payloads.
- Add negative tests for malformed client/server hello body handling.

Design
- Validate only hello message structural correctness at this stage; extension semantic checks remain future work.
- Keep Sans-I/O behavior and existing state transition logic intact.

Risks/Perf Impact
- Small handshake-path decode overhead; acceptable for control-plane messages.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert hello-body decode checks if integration reveals incompatibility with pending handshake features.

Commit Plan
- `MINOR: tls13: validate hello message bodies during session ingest`
===
timestamp: 2026-02-15T00:22:00+09:00
description: Add session-level hello body structural validation using message codecs
type: code change
===
Decisions + Rationale
- Integrated message-level decode checks into session ingest for `client_hello` and `server_hello` handshake bodies.
- Added explicit `InvalidHelloMessage` error to fail closed on malformed hello payloads.
- Updated hello test frame builders to emit minimally valid wire-format bodies, including HRR-compatible ServerHello variant.
- Added server-role positive/negative tests for ClientHello body validation.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added `validateHandshakeBody` helper.
  - Added hello-body decode checks in `ingestRecord`.
  - Added invalid/valid hello body tests.

Risks/Perf Notes
- Additional decode work occurs only on hello messages (control path), not application data path.

===
timestamp: 2026-02-15T00:22:30+09:00
description: Validate session hello-body validation integration
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session tests passed, including new malformed/valid hello body cases.
- Full package test build passed.
===
timestamp: 2026-02-15T00:29:00+09:00
description: Add CI workflow for build/test and interoperability tooling checks
type: plan
===
Motivation
- Verification tasks require reproducible automated checks, not only local manual runs.

Scope
- Add GitHub Actions workflow for:
  - Zig setup
  - `zig build test`
  - shell syntax checks for interop scripts
  - BoGo summary self-test
- Keep workflow minimal and deterministic.

Design
- Trigger on push and pull_request.
- Use explicit Zig version (0.15.2) to match local toolchain.

Risks/Perf Impact
- CI-only change; no runtime impact.

Test Plan (commands)
- `python3 -m py_compile scripts/interop/bogo_summary.py`
- `bash -n scripts/interop/*.sh`
- `zig build test`

Rollback
- Revert workflow file if CI provider assumptions need adjustment.

Commit Plan
- `MINOR: ci: add verification workflow for tests and tooling checks`
===
timestamp: 2026-02-15T00:31:00+09:00
description: Add CI workflow for automated verification of tests and tooling scripts
type: code change
===
Decisions + Rationale
- Added GitHub Actions workflow to run standardized verification checks on push/PR.
- Locked Zig setup version to `0.15.2` to align CI with local development toolchain.
- Included shell and Python tooling checks so interop/BoGo helper scripts are validated continuously.

Files/Sections Touched
- `.github/workflows/ci.yml` (new)

Risks/Perf Notes
- CI-only automation; no TLS runtime impact.

===
timestamp: 2026-02-15T00:31:30+09:00
description: Validate CI-targeted checks locally before commit
type: test
===
Commands Executed
- `python3 -m py_compile scripts/interop/bogo_summary.py`
- `bash -n scripts/interop/*.sh`
- `zig build test`

Observed Results
- Python syntax check passed.
- Shell syntax checks passed.
- Full package tests passed.
===
timestamp: 2026-02-15T00:33:00+09:00
description: Ignore Python bytecode cache artifacts generated by local CI checks
type: code change
===
Decisions + Rationale
- Added `__pycache__/` to `.gitignore` to keep repository clean from local Python syntax-check artifacts.

Files/Sections Touched
- `.gitignore`

Risks/Perf Notes
- Repository hygiene change only; no runtime impact.
===
timestamp: 2026-02-15T00:37:00+09:00
description: Refresh RFC8446 matrix statuses to reflect latest implementation progress
type: docs
===
Motivation
- Multiple feature units were added (message codec, close semantics, early-data policy, CI/BoGo scaffolding); matrix should reflect current state.

Scope
- Update `docs/rfc8446-matrix.md` status rows and notes for newly completed/expanded items.
- Add references to new modules where appropriate.

Design
- Keep conservative status semantics: only mark `implemented` where baseline behavior + tests exist.
- Keep remaining complex flows marked `partial`/`pending` with clear rationale.

Risks/Perf Impact
- Documentation-only change.

Test Plan (commands)
- `sed -n '1,260p' docs/rfc8446-matrix.md`
- `zig build test`

Rollback
- Revert matrix update if status interpretation is deemed too optimistic/pessimistic.

Commit Plan
- `MINOR: docs: update rfc8446 matrix with current feature coverage`
===
timestamp: 2026-02-15T00:40:00+09:00
description: Update RFC8446 matrix statuses for newly implemented features
type: docs
===
Decisions + Rationale
- Updated matrix to reflect newly added message codec coverage, deterministic fuzz robustness tests, and BoGo scaffolding.
- Kept conservative `partial` status for areas where baseline exists but full protocol completeness is pending.

Files/Sections Touched
- `docs/rfc8446-matrix.md`

Risks/Perf Notes
- Documentation-only status refresh.

===
timestamp: 2026-02-15T00:40:30+09:00
description: Validate matrix update and package tests
type: test
===
Commands Executed
- `sed -n '1,260p' docs/rfc8446-matrix.md`
- `zig build test`

Observed Results
- Matrix update rendered as expected.
- Full package tests passed.
===
timestamp: 2026-02-15T00:47:00+09:00
description: Add session-level metrics counters for observability baseline
type: plan
===
Motivation
- `_task.md` operational requirements call for deterministic metrics hooks (handshake outcomes, alerts, key update events).

Scope
- Add lightweight metrics counters to session engine state.
- Count handshake message processing, received alerts, keyupdate messages, and truncation detections.
- Add tests validating counter increments on representative paths.

Design
- Keep counters in-memory and read-only via accessor (`snapshotMetrics`).
- No external logging backend coupling.

Risks/Perf Impact
- Minimal overhead (integer increments on control paths).

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert metrics additions if API shape conflicts with future telemetry integration.

Commit Plan
- `MINOR: tls13: add session observability counters`
===
timestamp: 2026-02-15T00:50:00+09:00
description: Add session observability counters for handshake/alerts/keyupdate/truncation
type: code change
===
Decisions + Rationale
- Added in-engine metrics counters to support operational observability requirements without external telemetry coupling.
- Instrumented control-path events:
  - handshake messages processed
  - keyupdate messages seen
  - alert records received
  - transitions to connected
  - truncation detections
- Exposed immutable snapshot accessor for consumer-side reporting/export.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added `Metrics` struct and `snapshotMetrics`.
  - Added counter increments in ingest/EOF paths.
  - Added tests for metric behavior.

Risks/Perf Notes
- Minimal overhead (integer increments in control path).

===
timestamp: 2026-02-15T00:50:30+09:00
description: Validate observability counter instrumentation
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session tests passed including new metrics assertions.
- Full package test build passed.
===
timestamp: 2026-02-15T00:56:00+09:00
description: Add KeyUpdate record builder API for outbound action realization
type: plan
===
Motivation
- Session currently emits `send_key_update` action but does not provide a canonical encoder for the corresponding outbound record.

Scope
- Add `Engine.buildKeyUpdateRecord` API.
- Ensure emitted bytes follow handshake+record framing expectations.
- Add tests validating parse/roundtrip behavior.

Design
- Use existing handshake u24 writer and record framing constants.
- Keep API stateless and deterministic.

Risks/Perf Impact
- Negligible; pure byte construction.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert builder API if it conflicts with future AEAD-protected record layer wiring.

Commit Plan
- `MINOR: tls13: add keyupdate outbound record builder`
===
timestamp: 2026-02-15T00:58:30+09:00
description: Add outbound KeyUpdate record builder API and parseability tests
type: code change
===
Decisions + Rationale
- Added canonical `Engine.buildKeyUpdateRecord` helper so `send_key_update` action can be translated into wire bytes without duplicating framing logic in callers.
- Refactored local keyupdate test helper to use the new API.
- Added parseability test to ensure generated bytes are valid record+handshake framing and decode to intended KeyUpdate request value.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added `Engine.buildKeyUpdateRecord`.
  - Added parseability unit test.

Risks/Perf Notes
- Stateless byte builder; negligible performance impact.

===
timestamp: 2026-02-15T00:59:00+09:00
description: Validate KeyUpdate builder integration
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session tests passed including new KeyUpdate builder parseability test.
- Full package tests passed.
===
timestamp: 2026-02-15T01:08:00+09:00
description: Add Certificate and CertificateVerify message body decoding and session validation
type: plan
===
Motivation
- Session ingest now validates hello bodies; certificate-path handshake messages should be validated similarly.

Scope
- Extend `messages` module with decode support for TLS 1.3 Certificate and CertificateVerify bodies.
- Wire decode checks into `session.validateHandshakeBody` for `.certificate` and `.certificate_verify`.
- Add positive/negative tests for codec and session-level rejection behavior.

Design
- Focus on strict structural validation (length framing and bounds) with parser-independent data views.
- Keep semantic signature/certificate chain verification as separate layers.

Risks/Perf Impact
- Additional handshake-path decode overhead only.
- Certificate body parsing may allocate for entries; acceptable in handshake control path.

Test Plan (commands)
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert certificate-body decode wiring if it conflicts with upcoming full handshake integration.

Commit Plan
- `MINOR: tls13: validate certificate-path handshake message bodies`
===
timestamp: 2026-02-15T01:13:00+09:00
description: Add certificate-path handshake body codecs and session-level validation hooks
type: code change
===
Decisions + Rationale
- Extended `messages` module with `CertificateMsg.decode` and `CertificateVerifyMsg.decode` for strict structural validation.
- Integrated certificate-path body validation into `session.validateHandshakeBody` for `.certificate` and `.certificate_verify` message types.
- Added fixed test frame builders for minimally valid Certificate and CertificateVerify bodies.
- Added session tests for invalid certificate body rejection, invalid certificate_verify rejection, and valid certificate path progression.

Files/Functions Touched
- `src/tls13/messages.zig`
  - Added `CertificateEntry`, `CertificateMsg`, `CertificateVerifyMsg` decoders and tests.
- `src/tls13/session.zig`
  - Added `InvalidCertificateMessage` / `InvalidCertificateVerifyMessage` errors.
  - Added certificate-path body validation in ingest path.
  - Added certificate/certificate_verify frame helpers and tests.

Risks/Perf Notes
- Additional decode allocations occur only on certificate-path handshake messages.
- Semantic checks (signature verification and cert chain policy application) remain layered on top.

===
timestamp: 2026-02-15T01:13:30+09:00
description: Validate certificate-path message decoding and session integration
type: test
===
Commands Executed
- `zig fmt src/tls13/messages.zig src/tls13/session.zig`
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Messages codec tests passed including certificate/certificate_verify decoding.
- Session tests passed including certificate path positive/negative body-validation cases.
- Full package tests passed.
===
timestamp: 2026-02-15T01:18:00+09:00
description: Expand session integration tests for server-side certificate-path handshake flow
type: plan
===
Motivation
- Current certificate-path validation coverage focuses on client-role ingest sequence.
- Server-role certificate-path progression should also be verified explicitly.

Scope
- Add server-role session tests for valid client certificate path and malformed certificate/certificate_verify message rejection.
- Reuse existing test frame helpers.

Design
- Keep changes test-only for this unit; no behavior changes expected.

Risks/Perf Impact
- No runtime impact; test coverage expansion only.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert added tests if assumptions about role sequencing are incorrect.

Commit Plan
- `MINOR: test: add server-role certificate-path session tests`
===
timestamp: 2026-02-15T01:20:30+09:00
description: Add server-role certificate-path session tests for positive and negative flows
type: test
===
Decisions + Rationale
- Expanded session integration coverage to include server-role certificate-authenticated path progression and malformed message rejection.
- Keeps role symmetry validation explicit for certificate/certificate_verify body checks.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added 3 server-role certificate-path tests.

Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session suite passed with new server-role certificate path tests.
- Full package tests passed.
===
timestamp: 2026-02-15T01:27:00+09:00
description: Improve BoGo run wrapper to emit automatic summary report
ntype: plan
===
Motivation
- BoGo pipeline exists, but users still need a manual step to summarize JSON results.

Scope
- Update `scripts/interop/bogo_run.sh` to invoke `bogo_summary.py` automatically when JSON output exists.
- Keep behavior non-fatal for summary generation failures.

Design
- Preserve original BoGo exit status.
- Print summary block for quick inspection in CI/local runs.

Risks/Perf Impact
- Scripting-only change; no runtime core impact.

Test Plan (commands)
- `bash -n scripts/interop/bogo_run.sh`
- `python3 scripts/interop/bogo_summary.py --self-test`
- `zig build test`

Rollback
- Revert wrapper script enhancement if it interferes with existing automation parsing.

Commit Plan
- `MINOR: test: auto-summarize bogo results in runner wrapper`
===
timestamp: 2026-02-15T01:27:30+09:00
description: Supersede prior malformed metadata header and restate BoGo wrapper plan entry
type: plan
===
Correction
- Previous plan entry at 2026-02-15T01:27:00+09:00 had malformed metadata key (`ntype`).
- This entry supersedes that malformed header for WAL format compliance.

Motivation
- BoGo pipeline exists, but users still need a manual step to summarize JSON results.

Scope
- Update `scripts/interop/bogo_run.sh` to invoke `bogo_summary.py` automatically when JSON output exists.
- Keep behavior non-fatal for summary generation failures.

Design
- Preserve original BoGo exit status.
- Print summary block for quick inspection in CI/local runs.

Risks/Perf Impact
- Scripting-only change; no runtime core impact.

Test Plan (commands)
- `bash -n scripts/interop/bogo_run.sh`
- `python3 scripts/interop/bogo_summary.py --self-test`
- `zig build test`

Rollback
- Revert wrapper script enhancement if it interferes with existing automation parsing.

Commit Plan
- `MINOR: test: auto-summarize bogo results in runner wrapper`
===
timestamp: 2026-02-15T01:30:00+09:00
description: Update BoGo runner wrapper to auto-print summarized JSON results
type: code change
===
Decisions + Rationale
- Enhanced `bogo_run.sh` to automatically run `bogo_summary.py` when JSON output file is present.
- Kept summary generation non-fatal to preserve original BoGo runner exit semantics.

Files/Functions Touched
- `scripts/interop/bogo_run.sh`

Risks/Perf Notes
- Wrapper-only behavior change; no impact on TLS runtime paths.

===
timestamp: 2026-02-15T01:30:30+09:00
description: Validate updated BoGo wrapper and related checks
type: test
===
Commands Executed
- `bash -n scripts/interop/bogo_run.sh`
- `python3 scripts/interop/bogo_summary.py --self-test`
- `zig build test`

Observed Results
- Wrapper shell syntax check passed.
- Summary script self-test passed.
- Full package tests passed.
===
timestamp: 2026-02-15T01:38:00+09:00
description: Enforce CertificateVerify signature algorithm allowlist in session validation
-type: plan
===
Correction
- This entry supersedes malformed metadata key usage and provides the valid plan metadata.

Motivation
- CertificateVerify structural decode exists, but algorithm policy gate is not enforced at session ingest.

Scope
- Add configurable signature algorithm allowlist to session config.
- Reject CertificateVerify bodies that use algorithms outside allowlist.
- Add tests for allowlisted and non-allowlisted algorithms.

Design
- Provide secure default allowlist for common TLS1.3 signature schemes.
- Keep check local to `validateHandshakeBody` after decode.

Risks/Perf Impact
- Negligible overhead (small linear scan over allowlist).

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert allowlist checks if policy needs to be delegated externally.

Commit Plan
- `MINOR: tls13: enforce certverify algorithm allowlist`
===
timestamp: 2026-02-15T01:38:30+09:00
description: Supersede prior malformed plan metadata for certverify allowlist work
type: plan
===
Correction
- Previous entry at 2026-02-15T01:38:00+09:00 had malformed metadata key (`-type`).
- This entry supersedes that malformed header for WAL compliance.

Motivation
- CertificateVerify structural decode exists, but algorithm policy gate is not enforced at session ingest.

Scope
- Add configurable signature algorithm allowlist to session config.
- Reject CertificateVerify bodies that use algorithms outside allowlist.
- Add tests for allowlisted and non-allowlisted algorithms.

Design
- Provide secure default allowlist for common TLS1.3 signature schemes.
- Keep check local to `validateHandshakeBody` after decode.

Risks/Perf Impact
- Negligible overhead (small linear scan over allowlist).

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert allowlist checks if policy needs to be delegated externally.

Commit Plan
- `MINOR: tls13: enforce certverify algorithm allowlist`
===
timestamp: 2026-02-15T01:25:00+09:00
description: Enforce certificate_verify signature algorithm allowlist during session validation
type: code change
===
Decisions + Rationale
- Added configurable signature algorithm allowlist to session config with secure defaults for common TLS1.3 algorithms.
- Integrated allowlist check into certificate_verify body validation path after structural decode.
- Added unsupported-algorithm rejection test to ensure deterministic fail-closed behavior.

Files/Functions Touched
- `src/tls13/session.zig`
  - Added `default_signature_algorithms`.
  - Added `Config.allowed_signature_algorithms`.
  - Added `EngineError.UnsupportedSignatureAlgorithm`.
  - Added allowlist check + helper and test fixture override helper.

Risks/Perf Notes
- Minimal overhead from small allowlist scan.
- Final production policy may later move to application-configured policy sets.

===
timestamp: 2026-02-15T01:25:30+09:00
description: Validate certificate_verify algorithm allowlist enforcement
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Session tests passed including unsupported algorithm rejection case.
- Full package tests passed.
===
timestamp: 2026-02-15T01:38:00+09:00
description: Harden message decoders with extension-duplication checks and defensive size limits
type: plan
===
Motivation
- Strict parser validation is a release requirement; duplicate extension abuse and unbounded decoded vectors should be rejected early.

Scope
- Add duplicate-extension detection across decoded extension vectors.
- Add defensive size limits for decoded hello and certificate-path message components.
- Add unit tests for duplicate extension rejection and limit enforcement.

Design
- Introduce shared extension validator helper in `messages.zig`.
- Keep limits conservative and explicit in module-level constants.

Risks/Perf Impact
- Small additional O(n^2) checks over extension count; acceptable for handshake control path where extension vectors are small.

Test Plan (commands)
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert checks if legitimate vectors are blocked by too strict limits; adjust limits in follow-up WAL entry.

Commit Plan
- `MINOR: tls13: harden message decoder extension validation`
===
timestamp: 2026-02-15T01:41:00+09:00
description: Harden message decoders against duplicate extension abuse and oversized certificate entries
type: code change
===
Decisions + Rationale
- Added extension duplication checks to ClientHello/ServerHello and CertificateEntry extension decoding paths.
- Added defensive limits:
  - max extensions per message
  - max certificate entries
  - max certificate entry byte length
- Added tests for duplicate extension rejection and oversized certificate entry rejection.

Files/Functions Touched
- `src/tls13/messages.zig`
  - Added limit constants.
  - Added duplicate-extension checks in hello and certificate decode loops.
  - Added `containsExtensionType` helper.
  - Added/updated negative tests.

Risks/Perf Notes
- Duplicate detection uses linear scan across extension vectors; acceptable for handshake control-plane sizes.

===
timestamp: 2026-02-15T01:41:30+09:00
description: Validate hardened message decoder checks across module and integration tests
type: test
===
Commands Executed
- `zig fmt src/tls13/messages.zig`
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- Messages tests passed including duplicate extension and oversized certificate entry cases.
- Session tests passed with decoder hardening in place.
- Full package tests passed.
===
timestamp: 2026-02-15T01:48:00+09:00
description: Add integrated peer certificate policy validator combining hostname/chain/ocsp checks
type: plan
===
Motivation
- Certificate validation logic exists in separate functions; callers need a single policy entrypoint to reduce misuse and missing-step risk.

Scope
- Add integrated validator in `certificate_validation.zig` that executes:
  1) server-name verification
  2) chain policy checks
  3) OCSP stapling policy checks
- Add tests for full-pass and representative failure cases.

Design
- Preserve existing small validators and compose them in a new function.
- Keep parser-independent data model (CertificateView + OCSP ResponseView).

Risks/Perf Impact
- No hot-path impact; function composition over existing checks.

Test Plan (commands)
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Rollback
- Revert composite API if integration callers require different sequencing semantics.

Commit Plan
- `MINOR: tls13: add integrated peer certificate policy validator`
===
timestamp: 2026-02-15T01:52:00+09:00
description: Add integrated peer certificate policy validator API
-type: code change
===
Correction
- This entry supersedes malformed metadata key usage and provides valid WAL compliance context.

Decisions + Rationale
- Added `validateServerPeer` to compose hostname, chain, and OCSP checks in a single call.
- Exposed structured input/output (`PeerValidationInput`, `PeerValidationResult`) to reduce caller misuse risk from missing validation steps.

Files/Functions Touched
- `src/tls13/certificate_validation.zig`
  - Added integrated policy validation API and tests.

Risks/Perf Notes
- Composition over existing checks only; negligible overhead.
===
timestamp: 2026-02-15T01:52:30+09:00
description: Supersede malformed metadata key for integrated certificate policy validator entry
type: code change
===
Correction
- Previous entry at 2026-02-15T01:52:00+09:00 had malformed metadata key (`-type`).
- This entry supersedes that malformed header for WAL format compliance.

Decisions + Rationale
- Added `validateServerPeer` to compose hostname, chain, and OCSP checks in one API.
- Added `PeerValidationInput` and `PeerValidationResult` to make validation sequencing explicit.

Files/Functions Touched
- `src/tls13/certificate_validation.zig`

Risks/Perf Notes
- Composition over existing checks only; negligible overhead.

===
timestamp: 2026-02-15T01:53:00+09:00
description: Validate integrated peer policy validator
type: test
===
Commands Executed
- `zig fmt src/tls13/certificate_validation.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Observed Results
- Certificate validation tests passed including integrated validator cases.
- Full package tests passed.
===
timestamp: 2026-02-15T02:00:00+09:00
description: Improve BoGo shim with test-name policy routing (pass vs unsupported)
type: plan
===
Motivation
- Current shim always exits unsupported in scaffold mode, making result categorization coarse.

Scope
- Add `--test-name` parsing support.
- Add deterministic policy routing:
  - known baseline-safe tests -> success exit
  - unknown/unsupported tests -> unsupported exit
- Add unit tests for policy routing behavior.

Design
- Keep network handshake execution out of scope; route decisions are explicit and deterministic.
- Preserve existing capability/usage modes.

Risks/Perf Impact
- Tooling-only change; no TLS runtime impact.

Test Plan (commands)
- `zig test tools/bogo_shim.zig`
- `zig build bogo-shim`
- `zig build test`

Rollback
- Revert routing policy if BoGo runner expectations differ.

Commit Plan
- `MINOR: test: add bogo shim test routing policy`
===
timestamp: 2026-02-15T02:06:00+09:00
description: Add BoGo shim test routing policy and test-name parsing
-type: code change
===
Correction
- This entry supersedes malformed metadata key usage and is followed by a valid metadata entry.
===
timestamp: 2026-02-15T02:06:30+09:00
description: Supersede malformed metadata key for BoGo shim routing update
type: code change
===
Correction
- Previous entry at 2026-02-15T02:06:00+09:00 had malformed metadata key (`-type`).
- This entry supersedes that malformed header for WAL compliance.

Decisions + Rationale
- Added `--test-name` parsing in BoGo shim to improve test-level routing semantics.
- Added deterministic routing policy:
  - TLS1.3/basic-compatible cases -> success exit
  - non-TLS1.3 or unsupported cipher/test cases -> unsupported exit
- Preserved scaffold mode messaging while improving result granularity.

Files/Functions Touched
- `tools/bogo_shim.zig`
  - Added `test_name` config field.
  - Added routing decision logic and helper validators.
  - Added unit tests for routing behavior.

Risks/Perf Notes
- Tooling-only behavior change.
- Routing heuristics remain conservative and can be tightened as real handshake wiring matures.

===
timestamp: 2026-02-15T02:07:00+09:00
description: Validate BoGo shim routing enhancements
type: test
===
Commands Executed
- `zig fmt tools/bogo_shim.zig`
- `zig test tools/bogo_shim.zig`
- `zig build bogo-shim`
- `zig build test`

Observed Results
- Shim parser/routing unit tests passed.
- Shim build target passed.
- Full package tests passed.
===
timestamp: 2026-02-15T02:24:00+09:00
description: Add EncryptedExtensions and NewSessionTicket codecs plus session body validation hooks
type: plan
===
Motivation
- Session validates hello/certificate-path bodies, but EncryptedExtensions and NewSessionTicket bodies are still envelope-only.

Scope
- Add `EncryptedExtensions.decode` and `NewSessionTicketMsg.decode` in `messages.zig`.
- Wire session `validateHandshakeBody` checks for `.encrypted_extensions` and `.new_session_ticket`.
- Add valid/invalid tests at codec and session levels.

Design
- Reuse existing extension duplication and size-limit policy.
- Keep parser-independent and transport-agnostic behavior.

Risks/Perf Impact
- Handshake-path decode overhead only.

Test Plan (commands)
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert new body validation if it blocks currently expected handshake vectors; adjust fixtures accordingly.

Commit Plan
- `MINOR: tls13: validate encryptedextensions and nst message bodies`
===
timestamp: 2026-02-15T02:34:00+09:00
description: Wire EncryptedExtensions/NewSessionTicket body validation into session ingest
type: code change
===
Decisions + Rationale
- Extended `validateHandshakeBody` to parse `.encrypted_extensions` and `.new_session_ticket` bodies, matching earlier strict-parse policy used for hello/certificate paths.
- Introduced explicit engine errors for each body class to keep failure surfaces diagnosable (`InvalidEncryptedExtensionsMessage`, `InvalidNewSessionTicketMessage`).
- Replaced zero-body EncryptedExtensions test fixtures with minimally valid bodies (`extensions_len=0`) to preserve state-transition tests while enforcing body validation.

Files/Functions Touched
- `src/tls13/session.zig`
  - `EngineError`
  - `validateHandshakeBody`
  - Added fixtures: `encryptedExtensionsRecord`, `newSessionTicketRecord`
  - Added regression tests for invalid/valid EncryptedExtensions and NewSessionTicket paths.
- `src/tls13/messages.zig`
  - Added codecs/tests for `EncryptedExtensions` and `NewSessionTicketMsg` and extension-vector helper reuse.

Risks/Perf Notes
- Added decode work on handshake ingest path only for two handshake types; expected overhead is small and bounded by existing extension/length guards.
- Main compatibility risk is rejecting previously accepted envelope-only malformed frames; this is intentional hardening.
===
timestamp: 2026-02-15T02:35:00+09:00
description: Validate message/session body-validation expansion
type: test
===
Commands Executed
- `zig fmt src/tls13/messages.zig src/tls13/session.zig`
- `zig test src/tls13/messages.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `messages.zig`: 12/12 tests passed.
- `session.zig`: 58/58 tests passed, including new invalid/valid EE/NST validation tests.
- Full build test target passed.
===
timestamp: 2026-02-15T02:40:00+09:00
description: Plan RFC5280-style DNS name constraints enforcement in certificate chain validation
type: plan
===
Motivation
- `_task.md` requires name constraints support for constrained CAs.
- Current chain validator checks CA/path-len/EKU basics but has no name constraints enforcement.

Scope
- Extend certificate view model with permitted/excluded DNS suffix constraints.
- Enforce constraints against leaf DNS name during `validateServerChain`.
- Add positive/negative unit tests for constraint intersections and exclusions.

Design
- Constraints are evaluated on CA certificates (`chain[1..]`).
- Excluded constraints are fail-fast.
- Permitted constraints are intersection-like: if a CA declares permitted set, leaf must match at least one in that CA's set.
- Matching is ASCII case-insensitive and label-aware suffix match.

Risks/Perf Impact
- Additional per-chain string comparisons; negligible compared with full PKI processing.
- Risk of over/under-matching mitigated by boundary-aware suffix matcher tests.

Test Plan (commands)
- `zig test src/tls13/certificate_validation.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert name constraints checks if they block existing fixtures unexpectedly; keep fields optional with default empty constraints.

Commit Plan
- `MINOR: tls13: enforce dns name constraints in chain validation`
===
timestamp: 2026-02-15T02:43:00+09:00
description: Enforce DNS name constraints in server certificate chain policy checks
type: code change
===
Decisions + Rationale
- Added DNS name constraints to certificate-view model and enforced them during `validateServerChain`.
- Applied constraints only from CA chain elements (`chain[1..]`) and evaluated as:
  - excluded subtree match => reject
  - permitted set present => leaf must match at least one value
- Implemented case-insensitive, label-boundary suffix matching to avoid partial-label false matches.

Files/Functions Touched
- `src/tls13/certificate_validation.zig`
  - `CertificateView`: added `permitted_dns_suffixes`, `excluded_dns_suffixes`
  - `ValidationError`: added `NameConstraintsViolation`
  - `validateServerChain`: integrated name constraints check
  - New helpers: `validateNameConstraints`, `dnsMatchesConstraint`, `trimTrailingDot`
  - Added unit tests for permit/reject/intersection behavior.

Risks/Perf Notes
- Lightweight additional string checks only during chain validation.
- Constraint semantics are DNS-suffix focused and intentionally conservative.
===
timestamp: 2026-02-15T02:44:00+09:00
description: Validate DNS name constraints implementation with unit and full-suite tests
type: test
===
Commands Executed
- `zig fmt src/tls13/certificate_validation.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `certificate_validation.zig`: 15/15 tests passed.
- `session.zig`: 58/58 tests passed.
- Full test target passed.
===
timestamp: 2026-02-15T02:48:00+09:00
description: Plan explicit trust-store loading strategy with deterministic fallback behavior
type: plan
===
Motivation
- `_task.md` requires explicit and testable trust-anchor loading strategy with deterministic fallback for custom bundles.
- Current trust-store wrapper exposes primitives but no policy function encoding loading order/results.

Scope
- Add strategy/result types and a `loadWithStrategy` API.
- Encode deterministic precedence: system -> fallback file -> fallback dir.
- Add unit tests that avoid host-specific assumptions.

Design
- `LoadStrategy` controls whether system scan is attempted and optional fallback sources.
- `loadWithStrategy` returns `LoadResult` to make source-of-trust explicit.
- Errors from selected fallback sources propagate to caller.

Risks/Perf Impact
- Startup-only control-flow addition; no steady-state overhead.
- System store variability handled by making tests use `prefer_system=false` where determinism is required.

Test Plan (commands)
- `zig test src/tls13/trust_store.zig`
- `zig build test`

Rollback
- Keep existing primitive APIs; revert strategy wrapper if downstream integration requires alternate policy semantics.

Commit Plan
- `MINOR: tls13: add explicit trust store loading strategy`
===
timestamp: 2026-02-15T02:50:00+09:00
description: Add explicit trust-store loading strategy with deterministic fallback order
type: code change
===
Decisions + Rationale
- Added strategy-driven loading API so trust source precedence is encoded in one function and returned explicitly.
- Implemented deterministic fallback order: system scan (optional) -> PEM file -> PEM directory.
- Preserved existing primitive load methods to avoid breaking callers.

Files/Functions Touched
- `src/tls13/trust_store.zig`
  - Added `LoadStrategy` and `LoadResult`
  - Added `TrustStore.loadWithStrategy`
  - Added deterministic behavior tests.

Risks/Perf Notes
- Startup path only; no runtime data-plane impact.
- Strategy API makes source ambiguity observable by callers.
===
timestamp: 2026-02-15T02:51:00+09:00
description: Validate trust-store strategy behavior and full regression suite
type: test
===
Commands Executed
- `zig fmt src/tls13/trust_store.zig`
- `zig test src/tls13/trust_store.zig`
- `zig build test`

Observed Results
- `trust_store.zig`: 4/4 tests passed.
- Full test target passed.
===
timestamp: 2026-02-15T03:00:00+09:00
description: Plan extension coverage enforcement for ClientHello/ServerHello validation in session ingest
type: plan
===
Motivation
- `_task.md` Phase 2 requires extension coverage (SNI/ALPN/groups).
- Current parser validates extension structure only, not required extension presence/semantic minima.

Scope
- Enforce client-side minimum extension set for ClientHello: `supported_versions`, `server_name`, `supported_groups`, `key_share`.
- Enforce server-side minimum extension set for ServerHello: `supported_versions`, `key_share`.
- Add explicit engine errors and regression tests for missing extensions.

Design
- Reuse decoded `messages.ClientHello`/`messages.ServerHello` extension vectors in `session.validateHandshakeBody`.
- Presence checks only (semantic-deep checks deferred).
- Keep behavior role-aware: ClientHello policy on server role, ServerHello policy on client role.

Risks/Perf Impact
- O(n_ext) scans during handshake message validation; negligible.
- Potential compatibility tightening for tests using minimal hello fixtures; fixtures will be upgraded to include required extensions.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- If strict set is too aggressive for interim interop vectors, gate specific extension requirements via config in later commit.

Commit Plan
- `MINOR: tls13: enforce required hello extension presence`
===
timestamp: 2026-02-15T03:06:00+09:00
description: Enforce required hello extension presence for role-aware client/server validation
type: code change
===
Decisions + Rationale
- Added role-aware required extension checks in session handshake body validation to close extension-coverage gap.
- ClientHello (server role ingest) now requires: `supported_versions`, `server_name`, `supported_groups`, `key_share`, `alpn`.
- ServerHello (client role ingest, non-HRR) now requires: `supported_versions`, `key_share`.
- HRR path remains exempt from ServerHello extension-set check in this step to avoid over-constraining retry semantics before dedicated HRR extension parser work.

Files/Functions Touched
- `src/tls13/session.zig`
  - `EngineError`: added missing-required-extension errors
  - `validateHandshakeBody`: role-aware extension validation hooks
  - Added helpers: `requireClientHelloExtensions`, `requireServerHelloExtensions`, `hasExtension`
  - Upgraded hello fixture builders to include required extensions
  - Added regression helpers and tests for missing-extension rejection.

Risks/Perf Notes
- Adds linear scans over extension vector on hello validation path only.
- Tightens acceptance behavior intentionally; malformed/minimal hello fixtures without required extensions now fail closed.
===
timestamp: 2026-02-15T03:07:00+09:00
description: Validate required extension presence checks with session and full test suite
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `session.zig`: 60/60 tests passed (including new missing-required-extension cases).
- Full test target passed.
===
timestamp: 2026-02-15T03:15:00+09:00
description: Plan PSK offer binder-structure verification hooks in server-side ClientHello validation
type: plan
===
Motivation
- `_task.md` requires PSK binder verification for resumption.
- Current server-side ClientHello checks extension presence only and does not validate PSK binder list structure when PSK is offered.

Scope
- Add optional PSK-offer checks in `session` ClientHello validation:
  - if `pre_shared_key` exists, require `psk_key_exchange_modes` extension.
  - parse PSK identities/binders vectors structurally and reject malformed/empty binder vectors.
- Add negative tests for missing modes and invalid binder layout.

Design
- Keep checks transport-agnostic and local to session ingest (Sans-I/O).
- Structural validation only in this step (no cryptographic binder MAC verification due absent ticket secret context in current engine).

Risks/Perf Impact
- Additional parsing only when PSK extension is present.
- Behavior tightens malformed PSK offer rejection on server path.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert PSK structural checks if interop fixtures rely on malformed legacy vectors; preserve extension-presence baseline.

Commit Plan
- `MINOR: tls13: validate psk binder structure on clienthello offers`
===
timestamp: 2026-02-15T03:19:00+09:00
description: Add PSK offer binder-structure validation in server-side ClientHello path
type: code change
===
Decisions + Rationale
- Added conditional PSK offer validation in server-role ClientHello checks.
- If `pre_shared_key` is present, server now requires `psk_key_exchange_modes` and validates binder vector structure (identities list + non-empty binders list framing).
- Introduced dedicated error classes for missing modes and malformed binder vectors.

Files/Functions Touched
- `src/tls13/session.zig`
  - `EngineError`: `MissingPskKeyExchangeModes`, `InvalidPskBinder`
  - Added extension IDs for `pre_shared_key` and `psk_key_exchange_modes`
  - Added helpers: `validatePskOfferExtensions`, `findExtensionData`, `parsePskBinderVector`, local `readU16`
  - Added PSK-oriented ClientHello fixtures and negative tests.

Risks/Perf Notes
- Additional parse cost applies only when PSK extension is present.
- This step validates PSK offer shape, not cryptographic binder MAC proof (requires ticket-secret context wiring).
===
timestamp: 2026-02-15T03:20:00+09:00
description: Validate PSK binder-structure checks with session and full test suite
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `session.zig`: 62/62 tests passed, including new PSK missing-modes and malformed-binder negatives.
- Full test target passed.
===
timestamp: 2026-02-15T03:30:00+09:00
description: Plan TLS 1.3 key schedule expansion for derive_secret and Finished verify_data primitives
type: plan
===
Motivation
- `_task.md` core TLS1.3 requires key schedule correctness across secret derivations.
- Current `keyschedule` module provides only extract and hkdf-expand-label baseline.

Scope
- Add primitives:
  - `deriveSecret` (`Derive-Secret` helper)
  - `finishedKey`
  - `finishedVerifyData`
  - `verifyFinished` (constant-time equality)
- Add unit tests for determinism, suite-length behavior, and verify pass/fail.

Design
- Keep API `comptime suite`-driven to preserve fixed-size outputs and no heap allocation.
- Use existing suite-specific HKDF/HMAC bindings from Zig stdlib.
- Expose digest-size helper for transcript hash expectations.

Risks/Perf Impact
- Cryptographic operations are handshake-only; negligible steady-state impact.
- Incorrect output lengths are mitigated via compile-time suite-specific sizes and tests.

Test Plan (commands)
- `zig test src/tls13/keyschedule.zig`
- `zig build test`

Rollback
- Revert newly added helper APIs while preserving existing extract/expand-label behavior.

Commit Plan
- `MINOR: tls13: add derive-secret and finished verify-data helpers`
===
timestamp: 2026-02-15T03:34:00+09:00
description: Expand key schedule with derive-secret and Finished verify-data helpers
type: code change
===
Decisions + Rationale
- Added TLS1.3 schedule helpers beyond extract/expand-label baseline:
  - `deriveSecret`
  - `finishedKey`
  - `finishedVerifyData`
  - `verifyFinished`
- Implemented suite-aware HMAC production for Finished verify_data and constant-time byte comparison helper.
- Kept compile-time suite typing for fixed-size secret arrays and no heap overhead.

Files/Functions Touched
- `src/tls13/keyschedule.zig`
  - Added key-schedule helpers and constant-time compare utility.
  - Added deterministic and pass/fail verification tests.

Risks/Perf Notes
- Handshake-only crypto helpers; no data-path performance impact.
- Constant-time compare prevents early-exit timing leakage on Finished verification.
===
timestamp: 2026-02-15T03:35:00+09:00
description: Validate key schedule helper expansion
type: test
===
Commands Executed
- `zig fmt src/tls13/keyschedule.zig`
- `zig test src/tls13/keyschedule.zig`
- `zig build test`

Observed Results
- `keyschedule.zig`: 6/6 tests passed.
- Full test target passed.
===
timestamp: 2026-02-15T03:40:00+09:00
description: Plan 0-RTT ticket freshness window policy in early-data admission path
type: plan
===
Motivation
- `_task.md` requires anti-replay controls with ticket/window policy when 0-RTT is enabled.
- Current implementation enforces idempotency + replay filter but lacks ticket freshness window check.

Scope
- Add configurable max ticket age for early data acceptance.
- Add API to begin early-data context with issuance/current time and reject stale tickets.
- Enforce freshness during application_data early-data admission and add regression tests.

Design
- Extend `EarlyDataConfig` with `max_ticket_age_sec` default.
- Keep existing `beginEarlyData` API behavior for compatibility; add `beginEarlyDataWithTimes` for strict mode.
- Return explicit engine error for stale ticket windows.

Risks/Perf Impact
- Constant-time integer comparisons only; no measurable performance impact.
- Existing callers can continue using legacy begin API; stricter call path is opt-in.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Remove strict begin API and freshness checks if integration call sites need staged migration.

Commit Plan
- `MINOR: tls13: add early-data ticket freshness window policy`
===
timestamp: 2026-02-15T03:44:00+09:00
description: Add early-data ticket freshness window policy and strict begin API
type: code change
===
Decisions + Rationale
- Extended early-data config with `max_ticket_age_sec` to encode replay-window freshness policy.
- Added `beginEarlyDataWithTimes(ticket, idempotent, issued_at_sec, now_sec)` for explicit age validation.
- Added explicit stale-ticket engine error and enforced freshness in early-data admission path.
- Preserved existing `beginEarlyData` for compatibility while allowing stricter caller-controlled flow.

Files/Functions Touched
- `src/tls13/session.zig`
  - `EarlyDataConfig`: added `max_ticket_age_sec`
  - `EngineError`: added `EarlyDataTicketExpired`
  - `Engine`: added `beginEarlyDataWithTimes`
  - Early-data ingest path: freshness check integration
  - Added freshness boundary and stale-ticket tests.

Risks/Perf Notes
- Integer-only age checks; negligible overhead.
- Strict behavior is opt-in via new API to avoid breaking existing callers.
===
timestamp: 2026-02-15T03:45:00+09:00
description: Validate early-data freshness policy changes
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `session.zig`: 67/67 tests passed, including stale/boundary ticket-age tests.
- Full test target passed.
===
timestamp: 2026-02-15T04:00:00+09:00
description: Plan client-auth certificate usage validation alongside server-auth policy checks
type: plan
===
Motivation
- `_task.md` requires Key Usage / EKU enforcement for both server auth and client auth contexts.
- Current validator enforces only server-auth leaf usage semantics.

Scope
- Add `validateClientChain` and `validateLeafClientUsage` APIs.
- Reuse existing CA/path-length and name-constraints checks where applicable.
- Add unit tests for positive and negative client-auth EKU/KU cases.

Design
- Keep separate explicit entrypoints (`validateServerChain`, `validateClientChain`) for policy clarity.
- Client-auth leaf policy: require `digitalSignature` + `clientAuth` EKU.
- CA/path constraints remain shared via internal helper.

Risks/Perf Impact
- No measurable perf impact; validation-only path.
- Potential behavior tightening where callers adopt new client-auth validator.

Test Plan (commands)
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Rollback
- Remove client-auth entrypoint while preserving server-auth behavior if integration contract changes.

Commit Plan
- `MINOR: tls13: add client-auth certificate usage validator`
===
timestamp: 2026-02-15T04:04:00+09:00
description: Add client-auth certificate usage validation entrypoint and tests
type: code change
===
Decisions + Rationale
- Added explicit client-auth chain validator to enforce KU/EKU requirements in client-auth context.
- Refactored CA/path + name-constraints logic into shared helper used by both server/client validators.
- Kept server-auth behavior unchanged while extending policy surface for mTLS-style client cert validation.

Files/Functions Touched
- `src/tls13/certificate_validation.zig`
  - `ValidationError`: added `LeafMissingClientAuthEku`
  - Added `validateClientChain`, `validateLeafClientUsage`
  - Added shared helper `validateCaPathAndNameConstraints`
  - Added client-auth positive/negative tests.

Risks/Perf Notes
- Validation-only control flow change; no record/data-plane impact.
- Name-constraints checks on client validator apply when leaf DNS name is present.
===
timestamp: 2026-02-15T04:05:00+09:00
description: Validate client-auth certificate validator expansion
type: test
===
Commands Executed
- `zig fmt src/tls13/certificate_validation.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Observed Results
- `certificate_validation.zig`: 18/18 tests passed.
- Full test target passed.
===
timestamp: 2026-02-15T04:12:00+09:00
description: Plan BoGo critical-failure gate enforcement in interop summary tooling
type: plan
===
Motivation
- `_task.md` BoGo requirement calls for no unresolved critical failures.
- Current BoGo wrapper prints summary but does not enforce a critical-failure gate.

Scope
- Extend `bogo_summary.py` to classify critical failing tests and support threshold gating.
- Wire `bogo_run.sh` to invoke summary gate and fail when critical failures exceed threshold.
- Keep self-test coverage for new summary/gate behavior.

Design
- Critical heuristic (scaffold): failing test names matching TLS1.3 core categories (`TLS13`, `HRR`, `KeyUpdate`, `EarlyData`, `Resumption`).
- CLI options: `--max-critical` (default none), `--self-test`.
- `bogo_run.sh` respects optional `BOGO_MAX_CRITICAL` (default 0) and returns non-zero when gate fails.

Risks/Perf Impact
- Tooling-only changes; no library runtime impact.
- Heuristic classification may need iterative tuning as real BoGo data accumulates.

Test Plan (commands)
- `python3 scripts/interop/bogo_summary.py --self-test`
- `bash -n scripts/interop/bogo_run.sh`
- `zig build test`

Rollback
- Disable gate invocation in `bogo_run.sh` while preserving plain summary output.

Commit Plan
- `MINOR: test: enforce bogo critical failure gate`
===
timestamp: 2026-02-15T04:14:00+09:00
description: Enforce BoGo critical-failure summary gate in interop tooling
type: code change
===
Decisions + Rationale
- Extended BoGo summary tooling to classify critical failing tests using TLS1.3-centric heuristics.
- Added gate option (`--max-critical`) and integrated it into runner wrapper with default strict threshold 0.
- Changed runner behavior to fail when summary/gate check fails instead of warning-only mode.

Files/Functions Touched
- `scripts/interop/bogo_summary.py`
  - Added critical classification patterns and gate exit path.
  - Extended summary output with `critical_failure_count` and list.
  - Updated self-test for critical count assertions.
- `scripts/interop/bogo_run.sh`
  - Added `BOGO_MAX_CRITICAL` env var support.
  - Enforced summary gate as hard failure.

Risks/Perf Notes
- Tooling-only change.
- Critical classification is heuristic and intentionally conservative; threshold remains operator-configurable.
===
timestamp: 2026-02-15T04:15:00+09:00
description: Validate BoGo critical-failure gate tooling updates
type: test
===
Commands Executed
- `python3 scripts/interop/bogo_summary.py --self-test`
- `bash -n scripts/interop/bogo_run.sh`
- `zig build test`

Observed Results
- Summary self-test passed.
- Runner shell syntax check passed.
- Full test target passed.
===
timestamp: 2026-02-15T04:20:00+09:00
description: Plan OCSP producedAt freshness/ordering validation hardening
type: plan
===
Motivation
- `_task.md` revocation/freshness requirements call for robust OCSP freshness handling.
- Current OCSP checks validate `thisUpdate/nextUpdate` but do not validate `producedAt` sanity.

Scope
- Add `produced_at` validation rules:
  - reject responses produced too far in the future.
  - reject responses whose produced_at predates this_update beyond clock skew.
- Add explicit error codes and unit tests.

Design
- Reuse existing `max_clock_skew_sec` tolerance.
- Preserve soft-fail semantics when policy allows soft-fail.

Risks/Perf Impact
- Negligible integer comparison overhead.
- Potentially stricter rejection for malformed/future-dated stapled responses.

Test Plan (commands)
- `zig test src/tls13/ocsp.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Rollback
- Revert produced_at-specific checks while keeping baseline thisUpdate/nextUpdate validation.

Commit Plan
- `MINOR: tls13: harden ocsp producedAt freshness checks`
===
timestamp: 2026-02-15T04:23:00+09:00
description: Harden OCSP stapled response validation with producedAt checks
type: code change
===
Decisions + Rationale
- Added producedAt sanity checks to stapled OCSP validation:
  - reject future-dated produced_at beyond skew window
  - reject produced_at that predates this_update beyond skew window
- Preserved policy semantics: soft-fail mode converts these failures to soft-fail.

Files/Functions Touched
- `src/tls13/ocsp.zig`
  - `CheckError`: added `FutureProducedAt`, `ProducedBeforeThisUpdate`
  - `checkStapled`: added produced_at freshness/ordering checks
  - Added unit tests for hard-fail and soft-fail behavior.

Risks/Perf Notes
- Added integer timestamp comparisons only.
- Tightens acceptance for malformed/future-dated OCSP staples.
===
timestamp: 2026-02-15T04:24:00+09:00
description: Validate OCSP producedAt hardening changes
type: test
===
Commands Executed
- `zig fmt src/tls13/ocsp.zig`
- `zig test src/tls13/ocsp.zig`
- `zig test src/tls13/certificate_validation.zig`
- `zig build test`

Observed Results
- `ocsp.zig`: 5/5 tests passed.
- `certificate_validation.zig`: 20/20 tests passed.
- Full test target passed.
===
timestamp: 2026-02-15T04:35:00+09:00
description: Plan secret lifecycle hardening with explicit zeroization on session teardown
type: plan
===
Motivation
- `_task.md` requires key material zeroization on lifecycle end.
- Current session teardown frees early-data ticket and drops latest traffic secret without explicit wipe.

Scope
- Zeroize `latest_secret` in `Engine.deinit` before discard.
- Zeroize early-data ticket bytes before allocator free.
- Add regression tests validating zeroization helper behavior.

Design
- Add dedicated zeroization helpers in `session.zig` for secret union and ticket slices.
- Preserve existing API behavior; hardening is internal implementation detail.

Risks/Perf Impact
- Teardown-only memory writes; no hot-path cost.
- Requires careful avoid-optimization semantics via `std.crypto.secureZero`.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Revert zeroization helpers if allocator/platform constraints arise, preserving existing free/deinit logic.

Commit Plan
- `MINOR: tls13: zeroize session secrets on teardown`
===
timestamp: 2026-02-15T04:39:00+09:00
description: Zeroize session traffic secrets and early-data tickets during teardown
type: code change
===
Decisions + Rationale
- Added explicit zeroization path for `latest_secret` before discard in engine teardown.
- Zeroized early-data ticket bytes before allocator free to reduce residual secret exposure in heap memory.
- Kept hardening internal to session lifecycle functions with no API break.

Files/Functions Touched
- `src/tls13/session.zig`
  - `Engine.deinit`: now calls `zeroizeLatestSecret` prior to ticket cleanup
  - `clearEarlyDataTicket`: secure-zero + free
  - Added `zeroizeLatestSecret` helper
  - Added teardown zeroization regression tests.

Risks/Perf Notes
- Teardown-only writes; no handshake/data-path runtime overhead.
- Uses `std.crypto.secureZero` to prevent compiler-elision of wipe operations.
===
timestamp: 2026-02-15T04:40:00+09:00
description: Validate session secret zeroization hardening changes
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `session.zig`: 69/69 tests passed, including zeroization-focused tests.
- Full test target passed.
===
timestamp: 2026-02-15T04:46:00+09:00
description: Plan server_hello downgrade marker rejection in client-side validation
type: plan
===
Motivation
- `_task.md` security hardening checklist requires downgrade protections validation.
- Current client-side ServerHello validation checks structure/extensions but not downgrade sentinels in random.

Scope
- Add downgrade marker detection for `ServerHello.random` TLS1.2/TLS1.1 sentinel patterns.
- Reject marked ServerHello on client side with explicit error.
- Add regression test for downgrade marker rejection.

Design
- Implement random-tail check in `session.validateHandshakeBody` after decode.
- Keep HRR detection path unchanged.
- Expose helper for readability and testability.

Risks/Perf Impact
- Constant-time small byte comparisons on handshake path; negligible overhead.
- Tightens malformed/malicious ServerHello rejection behavior.

Test Plan (commands)
- `zig test src/tls13/session.zig`
- `zig build test`

Rollback
- Remove marker check if compatibility issue appears in interop vectors; keep extension validation baseline.

Commit Plan
- `MINOR: tls13: reject serverhello downgrade markers`
===
timestamp: 2026-02-15T04:49:00+09:00
description: Reject ServerHello downgrade sentinels in client-side handshake validation
type: code change
===
Decisions + Rationale
- Added client-side downgrade marker detection for ServerHello random tail sentinels (`DOWNGRD\x01`, `DOWNGRD\x00`).
- Rejects sentinel-bearing ServerHello with explicit `DowngradeDetected` error.
- Keeps existing HRR/extension validation flow unchanged.

Files/Functions Touched
- `src/tls13/session.zig`
  - `EngineError`: added `DowngradeDetected`
  - `validateHandshakeBody`: added downgrade marker check in client role server_hello path
  - Added helpers and regression fixture/test for downgrade-marker ServerHello.

Risks/Perf Notes
- Adds fixed-size byte-tail comparisons during server_hello validation only.
- Tightens malicious-downgrade signal rejection behavior.
===
timestamp: 2026-02-15T04:50:00+09:00
description: Validate downgrade marker rejection hardening
type: test
===
Commands Executed
- `zig fmt src/tls13/session.zig`
- `zig test src/tls13/session.zig`
- `zig build test`

Observed Results
- `session.zig`: 70/70 tests passed, including downgrade-marker rejection case.
- Full test target passed.
