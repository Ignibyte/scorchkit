# Work Pipeline: Combined DAST+SAST — `--code` Flag on Run Command

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` for Phase 4 |
| **Blocked** | No |
| **Forge Ticket** | #91 |
| **Forge Ticket ID** | 019d8c3d-bd5e-739f-9947-7928452ff350 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec
- **Title:** Combined DAST+SAST: `--code` flag on run command
- **Type:** Feature
- **Scope:** Add `--code <path>` flag to the `run` CLI command so users can run DAST and SAST in a single invocation. Runs both orchestrators concurrently via `tokio::join!`, merges findings into one `ScanResult`. Also adds `Engine::full_scan(url, code_path)` to the facade.
- **Files Expected:** ~4 (modify `src/cli/args.rs`, modify `src/cli/runner.rs`, modify `src/facade.rs`, possible `src/engine/scan_result.rs` merge helper)
- **Dependencies:** Orchestrator, CodeOrchestrator, ScanResult, Engine facade (WORK-089)
- **Risks:**
  - ScanResult merge — DAST and SAST produce separate ScanResults that need combining (findings, summaries, timing)
  - CLI argument interactions — `--code` must work with `--profile`, `--modules`, `--analyze`, etc.
  - Reporting — merged results must render cleanly in all 4 output formats
- **Acceptance Criteria:**
  - `scorchkit run <url> --code <path>` runs DAST+SAST concurrently
  - Findings from both are merged into a single ScanResult
  - `--code` without a URL is an error (SAST-only uses `code` subcommand)
  - `Engine::full_scan(url, code_path)` available in facade
  - All existing `run` flags continue to work
  - Tests verify merge logic and CLI arg parsing
  - `cargo test` passes, `cargo clippy` clean, `cargo fmt` clean

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK (cargo 1.94.0, rustc 1.94.0) |
| Security tools | OK |
| Hooks wired | OK (8/8) |
| cargo check | OK |
| cargo test | OK (493 passed, 0 failed) |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- Re-read pipeline docs after context continuation
- Multiple active pipeline docs confuse enforce-agent-scope.sh

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=[...])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` for project patterns before writing code

These are enforced by `enforce-completion.sh`. Skipping them blocks the conversation from ending.

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Architecture

**Approach:**
Add `--code <path>` optional flag to the `run` CLI command. When present, run DAST and SAST orchestrators concurrently via `tokio::join!`, then merge their `ScanResult`s into one. The merged result flows through the existing reporting/storage/AI pipeline unchanged. Also add `Engine::full_scan()` to the library facade.

The merge is simple: concatenate findings, concatenate modules_run/modules_skipped, keep the DAST target (primary), recompute summary. This works because `Finding` is the universal type shared by both DAST and SAST.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/cli/args.rs` | Modify | Add `--code <path>` optional flag to Run variant |
| 2 | `src/cli/runner.rs` | Modify | Pass `code_path` through to `run_scan()`, add concurrent SAST execution + merge |
| 3 | `src/engine/scan_result.rs` | Modify | Add `ScanResult::merge()` method |
| 4 | `src/facade.rs` | Modify | Add `Engine::full_scan(url, code_path)` method |

**Type and Trait Changes:**
- New method `ScanResult::merge(other: ScanResult)` — consumes `other`, extends `self.findings`, `self.modules_run`, `self.modules_skipped`, recomputes `self.summary`.
- New `Engine::full_scan(&self, url: &str, code_path: &Path) -> Result<ScanResult>` in facade.
- New `code: Option<PathBuf>` field in `Commands::Run` in args.rs.
- `run_scan()` gains `code_path: Option<&Path>` parameter.

**Error Handling Strategy:**
- If DAST scan fails, the entire scan fails (DAST is the primary operation).
- If SAST scan fails but DAST succeeds, log the SAST error and return DAST results only (graceful degradation — code path might not exist or have issues).
- `tokio::join!` returns both results; handle each independently.

**Architectural Decisions:**

1. **`tokio::join!` not `tokio::spawn`.** Both orchestrators run on the current task. `join!` is simpler — no need for `Send` bounds on the future, no JoinHandle management. Both scans complete before proceeding. This is correct because we need both results before merging.

2. **SAST failure is non-fatal.** If the user runs `scorchkit run https://example.com --code ./nonexistent`, the DAST scan should still succeed. The `--code` flag is additive — it never degrades the DAST scan. SAST errors are printed as warnings.

3. **Merge into DAST result, not new result.** `ScanResult::merge()` mutates `self` by extending its vectors. The DAST result is the base because it has the correct `Target` (URL-based). SAST findings get appended. The summary is recomputed from the merged findings.

4. **`run_scan` parameter addition, not new function.** Adding `code_path: Option<&Path>` to the existing `run_scan` is cleaner than creating a separate `run_combined_scan`. All the reporting/persistence/AI logic stays in one place.

5. **CLI flag is `--code`, not `--sast` or `--code-path`.** Matches the existing `code` subcommand name. Intuitive: "also scan the code at this path."

**Testing Strategy:**
- `ScanResult::merge()` — test finding concatenation, module list merge, summary recomputation
- CLI args — test `--code` flag parses correctly alongside other flags
- Facade — test `Engine::full_scan()` with empty dir (SAST produces 0 findings, DAST is mocked away)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_merge_results` | `src/engine/scan_result.rs` | Findings + modules combined, summary recomputed |
| 2 | `test_merge_empty` | `src/engine/scan_result.rs` | Merging empty result is no-op |
| 3 | `test_cli_code_flag` | `tests/cli.rs` | `--code` flag accepted in help output |

### Deferred Items
- None.

### Issues Found
- None.

### Knowledge Recorded
- **Lessons:** 1 (design)
- **Failures:** 0
- **Component Types:** cli, runner, engine, facade, sast

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started
**Started:**
**Completed:**

### Files Created
| File | Path |
|------|------|

### Files Modified
| File | Change |
|------|--------|

### Quality Gates
- **cargo fmt --check:**
- **cargo clippy:**
- **cargo test:**

### Notes

### Knowledge Recorded
- **Lessons:**
- **Failures:**
- **Component Types:**

---

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started
**Started:**
**Completed:**

### Entry Verification (independently run)
- **cargo fmt --check:**
- **cargo clippy:**
- **cargo test:**
- **```ignore check:**
- **#[ignore] check:**
- **#[allow] workaround check:**

### Code Review
- **Standards Compliance:**
- **Workaround Detection:**
- **Security Review (semgrep):**

### Test Results
- **Cargo Test Count:**
- **Doctest Count:**
- **Coverage:**

### Regression Test Plan Compliance

### Knowledge Recorded
- **Lessons:**
- **Failures:**
- **Component Types:**

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** Not Started
**Started:**
**Completed:**

- **Cargo Test Full Suite:**
- **Cargo Test Count:**
- **Cargo Test Regressions:**
- **Integration Tests:**

### Knowledge Recorded
- **Lessons:**
- **Failures:**
- **Component Types:**

---

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
**Started:**
**Completed:**

- **Documentation Updated:**
- **Changelog Updated:**
- **Pipeline Doc Archived:**

### Self-Reflection
1. Did any phase use workarounds?
2. Was the implementation the cleanest version?
3. Would a senior developer approve?

### After-Action Review (MANDATORY)
- **Generation Trace Saved:**
- **Lessons Recorded:**
- **Failures Recorded:**
- **Component Types Tagged:**
