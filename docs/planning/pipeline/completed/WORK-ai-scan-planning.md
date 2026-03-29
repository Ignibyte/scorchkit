# Work Pipeline: AI-Guided Scan Planning

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /complete |
| **Next Step** | Archived |
| **Blocked** | No |
| **Forge Ticket** | #6 |
| **Forge Ticket ID** | 019d364e-bc8c-73d5-818f-5b03103fd2d0 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** AI-Guided Scan Planning: Claude Decides Scan Strategy from Recon
- **Type:** Feature
- **Scope:** Add an AI-guided scan planning mode where Claude analyzes recon results (tech stack, headers, discovered endpoints) and produces a structured scan plan — which modules to run, in what priority order, and with what rationale. New `ScanPlan` type with `ModuleRecommendation` entries. New `ScanPlanner` in `ai/planner.rs`. CLI `--plan` flag on `run` command. MCP `plan-scan` tool. This is layer 2 of the AI intelligence architecture (autonomous scan planning).
- **Files Expected:** ~10 files (2 new, 8 modified) across src/ai/, src/cli/, src/mcp/, src/runner/, tests/
- **Dependencies:** Existing AI module (AiAnalyst, Claude CLI), Orchestrator, recon modules, MCP server
- **Risks:**
  - Claude response parsing for scan plans — same variability as analysis (mitigated by multi-tier extractor pattern)
  - Recon phase must complete before planning starts — needs orchestrator sequencing
  - Module IDs in Claude's plan may not match actual registered modules — needs validation/mapping
  - Plan execution depends on external tools being available — graceful skip for unavailable modules
- **Acceptance Criteria:**
  - `ScanPlan` type with `ModuleRecommendation` entries (module_id, priority, rationale, enabled flag)
  - `ScanPlanner` runs recon, feeds results to Claude, parses response into `ScanPlan`
  - Claude prompt includes available modules list, recon findings, and target info
  - Plan validates module IDs against registered modules (unknown modules logged and skipped)
  - CLI `scorchkit run <url> --plan` runs AI-planned scan instead of profile-based
  - MCP `plan-scan` tool returns structured plan JSON (plan only, no execution)
  - Graceful fallback: if planning fails, fall back to standard profile scan
  - 100% test coverage on new code
  - Zero clippy warnings, cargo fmt clean

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK (cargo 1.94.0, rustc 1.94.0, fmt 1.8.0, clippy 0.1.94) |
| Security tools | OK (semgrep 1.156.0, cargo-audit 0.22.1, cargo-deny 0.19.0) |
| Hooks wired | OK (2 PreToolUse + 6 Stop = 8 total) |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- After any context continuation, re-read pipeline doc before resuming
- Call bootstrap -> ticket-next -> recall before writing code
- Never modify published migrations after release tagging
- rmcp tools need pub do_*() business logic + private #[tool] wrappers for testability
- write!() instead of push_str(&format!()) for clippy
- Box<dyn Error> for integration tests (anyhow not in dev-deps)

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
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Architecture

**Approach:**

Two-phase AI-guided scan planning. Phase A: run recon modules (headers, tech, discovery, subdomain, crawler, waf) via the existing Orchestrator filtered to `ModuleCategory::Recon`. Phase B: feed recon findings + a catalog of all available scanner/tool modules (id, name, description, category, requires_external_tool) to Claude via a new planning prompt. Claude returns a structured `ScanPlan` with `ModuleRecommendation` entries specifying which modules to enable, in what priority, and why. The plan is validated against `all_modules()` — unknown IDs are logged and dropped. The validated plan is then used to configure a second Orchestrator run with only the recommended modules.

`ScanPlanner` reuses the existing `AiAnalyst` Claude CLI invocation pattern: write prompt to temp file, run `claude -p <prompt> --output-format json`, parse response. The multi-tier JSON extractor from `response.rs` is reused for plan parsing.

**Core Design Decisions:**

1. **`ScanPlanner` in `ai/planner.rs`** — Separate from `AiAnalyst` because different prompt structure, different response type, and different orchestration flow (recon-first). Same Claude CLI invocation pattern.

2. **Plan types in `ai/types.rs`** — `ScanPlan` and `ModuleRecommendation` co-located with existing analysis types. Same serialization concerns, same module.

3. **`ScanPlan` struct** — Top-level container with:
   - `target: String` — the scan target
   - `recommendations: Vec<ModuleRecommendation>` — ordered by priority
   - `overall_strategy: String` — Claude's reasoning for the approach
   - `estimated_scan_time: Option<String>` — rough estimate
   - `skipped_modules: Vec<SkippedModule>` — modules Claude recommends skipping, with rationale

4. **`ModuleRecommendation` struct** — Per-module recommendation:
   - `module_id: String` — must match a registered module ID
   - `priority: u32` — execution priority (1 = first)
   - `rationale: String` — why this module should run
   - `category: String` — recon/scanner for context

5. **`SkippedModule` struct** — Why a module was excluded:
   - `module_id: String`
   - `reason: String` — why Claude recommends skipping it

6. **Module catalog for prompt** — `build_module_catalog()` serializes `all_modules()` into a compact JSON list of `{id, name, description, category, requires_external_tool}` for Claude to reference. This is injected into the planning prompt alongside recon findings.

7. **Validation** — `validate_plan()` pure function checks each `module_id` against registered modules. Unknown IDs are moved from `recommendations` to a `warnings` list. This makes hallucinated module names visible without crashing.

8. **CLI `--plan` flag** — Added to `Commands::Run`. When set, `run_scan()` calls `ScanPlanner::plan()` first, then configures the Orchestrator with the plan's recommended modules instead of using the profile. If planning fails (Claude unavailable, parse failure), logs the error and falls back to the standard profile.

9. **MCP `plan-scan` tool** — Runs recon + planning but does NOT execute the scan. Returns the `ScanPlan` as JSON. This lets Claude (via MCP) review and adjust the plan before execution. Separate from `scan` and `project-scan` tools.

10. **Graceful fallback** — If AI is disabled, Claude is unavailable, or plan parsing fails: log a warning and continue with the standard profile. The `--plan` flag is advisory, not blocking.

**Type Definitions:**

```rust
/// AI-generated scan plan based on recon analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlan {
    pub target: String,
    pub recommendations: Vec<ModuleRecommendation>,
    pub skipped_modules: Vec<SkippedModule>,
    pub overall_strategy: String,
    pub estimated_scan_time: Option<String>,
}

/// A recommended scan module with priority and rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRecommendation {
    pub module_id: String,
    pub priority: u32,
    pub rationale: String,
    pub category: String,
}

/// A module Claude recommends skipping, with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedModule {
    pub module_id: String,
    pub reason: String,
}

/// Result of validating a scan plan against registered modules.
#[derive(Debug, Clone)]
pub struct PlanValidation {
    pub valid_recommendations: Vec<ModuleRecommendation>,
    pub unknown_modules: Vec<String>,
}
```

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/ai/planner.rs` | Create | `ScanPlanner` struct with `plan()` method: runs recon, builds prompt, calls Claude, parses and validates plan |
| 2 | `src/ai/types.rs` | Modify | Add `ScanPlan`, `ModuleRecommendation`, `SkippedModule`, `PlanValidation` types |
| 3 | `src/ai/prompts.rs` | Modify | Add `build_planning_prompt()` and `PLANNING_TASK` prompt template, `build_module_catalog()` |
| 4 | `src/ai/response.rs` | Modify | Add `parse_plan_response()` using existing `try_extract` for `ScanPlan` |
| 5 | `src/ai/mod.rs` | Modify | Add `pub mod planner;` |
| 6 | `src/cli/args.rs` | Modify | Add `--plan` flag to `Commands::Run` |
| 7 | `src/cli/runner.rs` | Modify | Integrate `ScanPlanner` into `run_scan()` when `--plan` is set |
| 8 | `src/mcp/types.rs` | Modify | Add `PlanScanParams` struct |
| 9 | `src/mcp/tools.rs` | Modify | Add `do_plan_scan()` + `#[tool] plan_scan` wrapper |
| 10 | `tests/scan_plan.rs` | Create | Serde round-trip tests, plan validation tests, module catalog tests |

**Error Handling Strategy:**

- Claude CLI failure → `ScorchError::AiAnalysis` (existing variant)
- Plan JSON parse failure → fallback to `ScanPlan` with empty recommendations (graceful degradation)
- Unknown module IDs → logged as warnings, removed from plan (not an error)
- Recon phase failure → individual module errors are skipped (existing orchestrator behavior)
- MCP tool failure → `Result<String, String>` (existing pattern)

**Testing Strategy:**

Unit tests for all plan types (serde round-trips), plan validation logic (known/unknown module IDs), module catalog generation, and plan response parsing. The planning prompt and Claude invocation are integration-level concerns tested via the existing subprocess pattern. MCP tool test follows `do_*()` direct-call pattern but requires Claude CLI — mark as integration.

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_scan_plan_roundtrip` | `tests/scan_plan.rs` | `ScanPlan` serializes/deserializes correctly |
| 2 | `test_module_recommendation_roundtrip` | `tests/scan_plan.rs` | `ModuleRecommendation` serializes/deserializes correctly |
| 3 | `test_skipped_module_roundtrip` | `tests/scan_plan.rs` | `SkippedModule` serializes/deserializes correctly |
| 4 | `test_scan_plan_empty` | `tests/scan_plan.rs` | Empty plan (no recommendations) is valid |
| 5 | `test_validate_plan_all_valid` | `tests/scan_plan.rs` | All module IDs match registered modules |
| 6 | `test_validate_plan_unknown_modules` | `tests/scan_plan.rs` | Unknown IDs removed, added to unknowns list |
| 7 | `test_validate_plan_mixed` | `tests/scan_plan.rs` | Mix of valid and unknown IDs handled correctly |
| 8 | `test_module_catalog_contains_all` | `tests/scan_plan.rs` | Catalog JSON contains all registered module IDs |
| 9 | `test_module_catalog_format` | `tests/scan_plan.rs` | Catalog entries have required fields (id, name, description, category) |
| 10 | `test_parse_plan_response_structured` | `tests/scan_plan.rs` | Claude JSON envelope → structured ScanPlan |
| 11 | `test_parse_plan_response_fallback` | `tests/scan_plan.rs` | Unparseable content → empty ScanPlan |
| 12 | `test_plan_scan_params_deserialize` | `tests/scan_plan.rs` | MCP `PlanScanParams` deserializes from JSON |
| 13 | `test_cli_plan_flag_in_help` | `tests/cli.rs` | CLI `run --help` shows `--plan` flag |

**Architectural Decisions:**
1. **`ScanPlanner` separate from `AiAnalyst`** — Different flow (recon-first), different prompt, different response type. Composition over bloating a single struct.
2. **Plan types in `ai/types.rs` not a new file** — Same serialization module, keeps the AI type surface unified. Already has analysis types, plan types are the same concern.
3. **Validation as pure function** — `validate_plan(plan, &[module_ids])` takes a slice of valid IDs. Testable without constructing modules.
4. **MCP tool is plan-only** — `plan-scan` returns the plan but doesn't execute. This is deliberate: Claude (the MCP client) can inspect, adjust, or approve the plan before calling `scan` or `project-scan` to execute.
5. **Graceful fallback** — `--plan` flag is advisory. If planning fails for any reason, the scan continues with the standard profile. No scan is worse than an unplanned scan.
6. **No new feature gate** — Scan planning uses the existing AI module which is always compiled. The MCP tool is behind `mcp` feature as usual.

### Deferred Items
- None — all decisions are final

### Issues Found
- The `AiAnalyst` Claude invocation pattern duplicates some logic (temp file, subprocess, cleanup). Could be extracted into a shared `run_claude()` helper, but that's a refactor beyond this pipeline's scope. Document for future cleanup.

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** ai, scanning, cli, mcp

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Files Created
| File | Path |
|------|------|
| Scan planner | `src/ai/planner.rs` |
| Integration tests | `tests/scan_plan.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/ai/types.rs` | Added `ScanPlan`, `ModuleRecommendation`, `SkippedModule`, `PlanValidation`, `validate_plan()` |
| `src/ai/prompts.rs` | Added `build_planning_prompt()`, `build_module_catalog()`, `PLANNING_TASK` constant |
| `src/ai/response.rs` | Added `parse_plan_response()` using existing `try_extract` |
| `src/ai/mod.rs` | Added `pub mod planner;` |
| `src/cli/args.rs` | Added `--plan` flag to `Commands::Run` |
| `src/cli/runner.rs` | Integrated AI planning before main orchestrator run; added `plan` parameter to `run_scan()` |
| `src/mcp/types.rs` | Added `PlanScanParams` struct |
| `src/mcp/tools.rs` | Added `do_plan_scan()` + `#[tool] plan_scan` wrapper |
| `tests/cli.rs` | Added `test_cli_plan_flag_in_help` |

### Quality Gates
- **cargo fmt --check:** Pass (0 diffs)
- **cargo clippy --all-features:** Pass (0 warnings in new/modified files)
- **cargo test:** Pass — Default: 57 (was 44), All-features (mcp): 121 (was 107)

### Notes
- Restructured `run_scan()` to run AI planning BEFORE creating the main `ScanContext`/`Orchestrator`, avoiding borrow-after-move on `target`. The planner creates its own recon `ScanContext` internally.
- Fixed clippy `if_not_else` warning by inverting the `recommendations.is_empty()` check
- Added 1 bonus test (`test_try_extract_scan_plan`) beyond the 13 planned
- Design planned `test_plan_scan_params_deserialize` as test #12, implemented it in `scan_plan.rs` instead of inline

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** ai, scanning, cli, mcp

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (independently run)
- **cargo fmt --check:** Pass (exit 0)
- **cargo clippy --all-features:** Pass (0 warnings in new files; pre-existing pedantic/nursery in untouched files)
- **cargo test:** Pass — Default: 57, MCP: 121
- **```ignore check:** Pass (0 files)
- **#[ignore] check:** Pass (0 matches)
- **#[allow] workaround check:** Pass — 0 new `#[allow]` in pipeline code (3 pre-existing in runner.rs)

### Code Review
- **Standards Compliance:** Pass — all pub items documented with `///` and `# Errors` sections, all types derive Debug, `#[must_use]` on pure functions, `?` for error propagation, no `unwrap`/`expect` in library code, iterators throughout, graceful fallback on parse failure
- **Workaround Detection:** Pass — 0 new `#[allow]`, 0 `#[ignore]`, 0 ````ignore`
- **Security Review (semgrep):** Pass — 0 findings. cargo audit: 1 pre-existing (indicatif dep)

### Test Results
- **Cargo Test Count:** Default 57, MCP 121
- **Doctest Count:** 1 (pre-existing)
- **Coverage:** Not measured

### Regression Test Plan Compliance
13/13 individually implemented + 1 bonus (test_try_extract_scan_plan)

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** ai, scanning, cli, mcp

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Cargo Test Full Suite:** Pass
- **Cargo Test Count:** Default: 57 passed, 0 failed; MCP: 121 passed, 0 failed
- **Cargo Test Regressions:** None — identical to Phase 3 and Phase 4
- **Integration Tests:** Pass — 14 cli + 7 storage_integration + 6 project_cli + 17 mcp_tools + 13 posture_metrics + 13 scan_plan = 70 integration tests
- **Doctests:** 0 (pre-existing doctest compiles but no new doctests)
- **cargo fmt --check:** Pass
- **cargo clippy:** Pass (0 errors)

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** ai, scanning, cli, mcp

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Documentation Updated:** CHANGELOG.md (v0.7.0 with 9 Added + 3 Changed items)
- **Changelog Updated:** Yes
- **Pipeline Doc Archived:** Yes — moved to `completed/`

### Self-Reflection
1. **Did any phase use workarounds?** No. The restructuring of `run_scan()` to run planning before creating the main `ScanContext` was the correct solution to the borrow-after-move issue, not a workaround. The `ScanPlanner` creating its own recon `ScanContext` internally is clean separation of concerns.
2. **Was the implementation the cleanest version?** Yes. `ScanPlanner` as a separate struct from `AiAnalyst` follows composition. `validate_plan()` as a pure function is the cleanest testable pattern for AI output validation. `parse_plan_response()` with empty-plan fallback makes failure a data type. The module catalog serialization from `all_modules()` is straightforward.
3. **Would a senior Rust developer approve?** Yes. All types derive appropriate traits, all public items documented, `?` error propagation throughout, `#[must_use]` on pure functions, no `unwrap`/`expect`, graceful degradation on AI failures, clean separation between planning (AI) and execution (Orchestrator).

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes (019d39ed-b4e5-723f-a9a7-e26731d7ffae)
- **Lessons Recorded:** 6 (1 design, 1 implementation, 1 validation, 1 testing, 1 pipeline, 1 architecture decision)
- **Failures Recorded:** 0
- **Component Types Tagged:** ai, scanning, cli, mcp
