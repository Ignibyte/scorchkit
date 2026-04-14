# Work Pipeline: cargo-deny hygiene — license allowlist + documented advisory ignores

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | COMPLETE |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /complete |
| **Next Step** | — (pipeline archived) |
| **Blocked** | No |
| **Forge Ticket** | #99 |
| **Forge Ticket ID** | 019d8d20-46b6-7269-ba2d-49df4fc4f83f |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec

- **Title:** cargo-deny hygiene — license allowlist + documented advisory ignores
- **Type:** Infrastructure
- **Scope:** Update `deny.toml` so `cargo deny check` exits 0. Add `MPL-2.0` to the license allowlist (affects 5 transitive crates via scraper + colored). Add `[advisories.ignore]` entries for 4 pre-existing advisories with inline `# JUSTIFICATION` comments. Zero Rust code changes; zero `Cargo.lock` changes; zero test count changes.
- **Files Expected:** 1 — `deny.toml`.
- **Dependencies:** None.
- **Risks:**
  - **License policy drift** — future MPL-2.0 deps will also pass silently. Accepted: MPL-2.0 is file-level copyleft, we don't redistribute the sources, standard industry practice.
  - **Advisory staleness** — ignored advisories won't alert if they escalate. Mitigated via per-ignore JUSTIFICATION comments that point to upstream trackers. Revisit on a cadence.
  - **Tooling divergence** — `cargo audit` doesn't read `deny.toml`, so it will still show the same findings. This is documented behavior, not a regression.
- **Acceptance Criteria:**
  - `cargo deny check` exits 0 (`advisories ok, bans ok, licenses ok, sources ok`).
  - `cargo deny check licenses` exits 0.
  - `cargo deny check advisories` exits 0.
  - `cargo fmt --check` / `cargo clippy -- -D warnings` / `cargo test` unchanged (479 passed).
  - Every new `[[advisories.ignore]]` entry and every new license added to `allow = [...]` has an inline `# JUSTIFICATION: <reason>` comment.
  - Architecture decision `security.license-policy` recorded in Forge.

### Preflight Results

| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK |
| Security tools | OK (cargo-deny 0.19.0, cargo-audit 0.22.1, semgrep, tarpaulin all installed) |
| Hooks wired | OK (8/8) |
| cargo check | OK |
| cargo test | OK (479 passed, 0 failed) |

### Known Pitfalls (from RLM)

- **`cargo audit` ≠ `cargo deny check advisories`** — different tools, different config. Audit reads `Cargo.lock` and has no built-in ignore mechanism (unless you pass `--ignore`). Deny reads `deny.toml`. Green deny does not mean green audit. Document this up front so future pipelines don't chase the wrong tool.
- **MPL-2.0 is not GPL.** File-level copyleft, OSI-approved, FSF-Free, compatible with MIT-licensed projects as a dependency. Every reviewer will ask; the answer is documented once here and again in the architecture decision.
- **DL-015 (never modify published migrations)** — N/A (no schema changes).
- **Rationale comments are mandatory** per Constitution §14 for `#[allow]` — same principle applies to `deny.toml` ignores. Treat them the same way.

### Human Confirmed
- [x] Spec reviewed; continuing autonomously per user directive "continue on whatever you want to do"

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — project context
2. **Recall** — targeted lessons
3. **Learn** — record findings
4. **Search-architecture-docs** — before code

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Approach

One file touched: `deny.toml`. Two surgical changes:

1. **Licenses.** Add `"MPL-2.0"` to the `allow = [...]` list in `[licenses]`. No `exceptions` block needed — MPL-2.0 is now unconditionally allowed. Covers colored, cssparser, cssparser-macros, selectors, and any future MPL deps.

2. **Advisories.** Replace the empty `ignore = []` in `[advisories]` with a list of four entries, each `{ id = "RUSTSEC-...", reason = "..." }`. Cargo-deny's ignore syntax supports an explicit `reason` field which renders in the config output — this is the equivalent of the `// JUSTIFICATION:` pattern used for `#[allow]`.

No dependency bumps. No `cargo update`. No Cargo.lock changes. No Rust code touched.

### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `deny.toml` | Modify | Add MPL-2.0 to license allowlist; add 4 documented advisory ignores. |

### Decisions

1. **No dep bumps attempted in this pipeline.** The three "no safe upgrade available" advisories (fxhash, number_prefix, rand) can't be fixed by bumping — they require either their consumers (scraper, indicatif, tungstenite/quinn/governor) to switch crates or for us to swap the consumer. Both are bigger pipelines. Today's job is policy; tomorrow's is evolution.
2. **rsa advisory (RUSTSEC-2023-0071) is transitively present but unused.** `sqlx` includes it behind the `mysql` feature; we only enable `postgres`. A cleaner fix would be to confirm the mysql feature stays off (it already does per Cargo.toml), which means the `rsa` crate sits in `Cargo.lock` but is never linked. Ignoring the advisory is honest.
3. **`reason` field on ignores.** cargo-deny 0.14+ supports `{ id, reason }` struct form. 0.19.0 is installed. Use it.
4. **No new test count.** This pipeline should keep test counts exactly stable — any drift indicates an unrelated change slipped in.

### Testing Strategy

Tests are tool-level, not Rust-level:
- `cargo deny check` must exit 0 and print `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo deny check licenses` must exit 0.
- `cargo deny check advisories` must exit 0.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` must pass unchanged (479 lib + 42 integration + 7 doctests).

### Regression Test Plan

| # | "Test Name" (command invocation) | Verifies |
|---|----------------------------------|----------|
| 1 | `cargo deny check` exits 0 | Overall gate passes |
| 2 | `cargo deny check licenses` exits 0 | MPL-2.0 acceptance wired correctly |
| 3 | `cargo deny check advisories` exits 0 | All 4 RUSTSECs ignored with rationale |
| 4 | `cargo test` → 479 passed | No Rust regressions |
| 5 | `cargo fmt --check` exits 0 | No incidental fmt changes |
| 6 | `cargo clippy -- -D warnings` exits 0 | No incidental clippy changes |

### Deferred Items

- **Upstream tracking** for the three unmaintained-crate advisories. Each ignore's `reason` field points to the GitHub issue; no pipeline action required today.
- **Swapping scraper → a maintained alternative** that doesn't drag fxhash/MPL-2.0 crates. Would be its own pipeline (touches HTML parsing across multiple modules).
- **Dropping sqlx's mysql feature explicitly** — already off per Cargo.toml. Re-checked during this pipeline.

### Issues Found
None during design.

### Knowledge Recorded
- Lessons: 1 (design rationale — recorded via `learn` when implement runs)
- Failures: 0
- Component Types: infrastructure, security

### Human Confirmed
- [x] Design reviewed (continuing autonomously)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Files Modified
| File | Change |
|------|--------|
| `deny.toml` | Added `"MPL-2.0"` to `[licenses].allow` with inline `# JUSTIFICATION`. Replaced empty `[advisories].ignore = []` with 4 documented entries (rsa, fxhash, number_prefix, rand) each with `reason` fields + `# JUSTIFICATION` block comments. |

### Quality Gates
- **cargo deny check:** PASS — `advisories ok, bans ok, licenses ok, sources ok` (exit 0). One non-fatal warning: `RUSTSEC-2026-0097` flagged `advisory-not-detected` because cargo-deny's advisory DB is slightly behind cargo-audit's; the ignore entry is correct and will activate on next DB refresh. Not blocking.
- **cargo fmt --check:** PASS (no code changes)
- **cargo clippy -- -D warnings:** PASS (no code changes)
- **cargo test:** PASS — 479 passed, 0 failed (identical to baseline)

### Notes
- Zero Rust code touched. Zero Cargo.lock touched. Only `deny.toml` modified.
- `cargo-deny 0.19.0` supports the `{ id, reason }` struct form for ignore entries — used throughout.
- cargo-deny reported one `advisory-not-detected` warning for RUSTSEC-2026-0097. Its advisory DB is a day or so behind cargo-audit's. The entry is present and correctly formatted; it activates once the DB refreshes. This is expected and harmless.

### Knowledge Recorded
- Lessons: 1 (implementation — via `learn` below)
- Failures: 0
- Component Types: infrastructure, security

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Entry Verification (independent re-run)

| Gate | Result |
|------|--------|
| `cargo deny check` | PASS (exit 0) — `advisories ok, bans ok, licenses ok, sources ok` |
| `cargo deny check licenses` | PASS — MPL-2.0 now accepted |
| `cargo deny check advisories` | PASS — 4 ignores all matched (except RUSTSEC-2026-0097 with a benign "advisory-not-detected" warning due to DB lag) |
| `cargo fmt --check` | PASS (exit 0) |
| `cargo clippy -- -D warnings` | PASS (exit 0) |
| `cargo test` | PASS — 479 lib + 42 integration + 7 doctests, 0 failed |
| `#[ignore]` / ``` ```ignore ``` | CLEAN |

### Code Review

- `deny.toml` changes reviewed: every new entry has an inline `# JUSTIFICATION:` comment following the same pattern used for `#[allow]` attributes. MPL-2.0 allow includes a rationale citing OSI/FSF status and file-level copyleft semantics. Each advisory ignore includes a `reason` field that duplicates the justification in a machine-readable form for cargo-deny itself to render.
- No change to Rust code → no standards/workaround/security review needed at the source-tree level.
- Semgrep not re-run (no code changes).

### Test Results
- Cargo test count unchanged at 479 lib + 42 integration + 7 doctests.
- All regression-test-plan items from Phase 2 pass:
  1. `cargo deny check` exits 0 — YES
  2. `cargo deny check licenses` exits 0 — YES
  3. `cargo deny check advisories` exits 0 — YES
  4. 479 tests pass — YES
  5. `cargo fmt --check` — YES
  6. `cargo clippy` — YES

### Knowledge Recorded
- Lessons: 1 (validation — via `learn` below)
- Failures: 0
- Component Types: infrastructure, security

## Phase 5: Verify
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Full Test Suite
- lib: 479 / 0
- integration: 42 / 0
- doctests: 7 / 0
- TOTAL: 528 passed, 0 failed.

### Regression vs Phase 4: zero. Counts identical.

### Knowledge Recorded
- Lessons: 1 (verify clean)
- Failures: 0
- Component Types: infrastructure, security

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Documentation Updates
- `CHANGELOG.md` — bullet under `[Unreleased]`/`Changed` noting the cargo-deny policy update.
- Architecture decision `security.license-policy` recorded in Forge.

### Self-Reflection
1. **Workarounds?** None. Every ignore is a documented, scoped policy decision with a `reason` field + `# JUSTIFICATION` comment. No advisories silenced without trace.
2. **Cleanest version?** Yes. One file, two localised changes, every entry justified. Considered attempting dep bumps (rand, indicatif, scraper) — ruled out because upstream has no safe upgrade for the unmaintained deps and the work is better scoped as its own pipeline when/if replacements appear.
3. **Senior dev approval?** The MPL-2.0 allow is the standard Rust-ecosystem move. The four advisory ignores each pass the three-part review: (a) is the vuln reachable in our deployment? (b) is there a safe upgrade? (c) is the rationale recorded? Any future auditor can re-evaluate each in under a minute.

### Final Pipeline Checklist
- [x] Ticket #99 valid
- [x] Phases 1–5 = PASS
- [x] Code quality gates: fmt/clippy/test all green
- [x] No new `#[allow]`, no `#[ignore]`, no ``` ```ignore ```
- [x] `bootstrap`, `recall`, `learn`, `architecture-set`, `save-generation-trace` called
- [x] `CHANGELOG.md` updated
- [x] Pipeline archived
- [x] Ticket #99 closed as Done

### Knowledge Recorded
- Lessons: 4 across pipeline
- Failures: 0
- Architecture Decisions: 1 (`security.license-policy`)
- Generation Trace: saved
- Component Types: infrastructure, security
