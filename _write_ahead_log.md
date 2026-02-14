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
