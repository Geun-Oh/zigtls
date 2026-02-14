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
