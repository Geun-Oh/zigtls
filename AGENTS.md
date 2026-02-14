# Project Agent Instructions

These instructions are **binding** for the CLI coding agent.

## Hard gates (must pass before any code changes)

1. **Write-Ahead Log first**
   - Before changing anything, create/update `_write_ahead_log.md` with:
     - motivation, scope, design, risks/perf impact, test plan (commands), rollback, commit plan
   - If WAL is missing/incomplete: **STOP and request WAL completion**.

   ### WAL immutability / append-only (HARD)
   - **Existing WAL contents must never be edited, reordered, or deleted.**
   - **WAL updates must be strictly append-only**: add new content **only at the tail**.
   - If an update would require modifying prior entries: **STOP** and append a new entry that corrects/supersedes prior info.

   ### WAL entry metadata format (HARD)
   - Every WAL append must start with the following metadata header block:

     ```

     ===
     timestamp: ~~
     description: ~~
     type: test | code change | ...
     ===

     Main Content
     ```

   - Rules:
     - `timestamp`: ISO-8601 with timezone (e.g., `2026-02-13T10:05:00+09:00`)
     - `description`: one-line summary of what is being logged
     - `type`: one of (extendable but consistent):
       - `plan` | `analysis` | `design` | `code change` | `refactor` | `test` | `benchmark` | `docs` | `review` | `release` | `rollback`
     - The body must include (as applicable):
       - decisions + rationale (why)
       - commands executed (esp. tests/benchmarks) + observed results
       - files/functions touched (for code changes)
       - risks/perf notes (hot-path impact)

2. **Tests are mandatory**
   - Bug fix: reproduction + regression test
   - Feature: normal/error/boundary cases
   - All tests must be runnable via commands recorded in WAL.

3. **Commit discipline**
   - Commit by feature unit; keep commits revert-friendly.
   - No mixing refactor/formatting with behavior changes.

## Commit message format (patch-style)

Use HAProxy-like patch subjects and a why-centric body:

Subject:

- `BUG/<SEVERITY>: <area>: <short summary>` or `<SEVERITY>: <area>: <short summary>`
- Severities: `MINOR`, `MEDIUM`, `MAJOR` (and `BUG/MINOR`, `BUG/MEDIUM`, `BUG/MAJOR`)

Body (required sections):

- Context, Root cause (for bugs), Fix, Impact, Tests (commands)

## Coding style

- Prefer simple, reviewable code over clever abstractions.
- Make small, conservative changes; protect performance/hot paths.
- Comments should explain **why**, not what.

## Pre-work checklist (agent must validate)

- [ ] WAL exists and is complete for this task
- [ ] Risks/perf impact considered
- [ ] Test plan is executable and documented
- [ ] Commit plan is feature-unit and patch-style

