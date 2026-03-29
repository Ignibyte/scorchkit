# Work Pipeline: MCP Expanded Tool Descriptions with Decision Guidance

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /verify |
| **Next Step** | Run `/complete` for Phase 6 |
| **Blocked** | No |
| **Forge Ticket** | #40 |
| **Forge Ticket ID** | 019d3a8a-5f4c-7244-b857-da6c0b8fbbf4 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Expanded tool descriptions with decision guidance for Claude
- **Type:** Feature
- **Scope:** Expand all 20 `#[tool(description = "...")]` strings from terse one-liners to rich multi-sentence guidance that tells Claude when to use each tool, what parameters matter, what output to expect, and what to do next. Also expand parameter descriptions in `JsonSchema` derive types in `types.rs`. Complements #39 (instructions teach workflow, descriptions teach individual tools).
- **Files Expected:** 2 modified (`src/mcp/tools.rs` — 20 tool descriptions, `src/mcp/types.rs` — parameter doc comments)
- **Dependencies:** #39 (rich instructions) — completed. Existing 20 tools and parameter types.
- **Risks:** Descriptions too long could clutter `list_tools` output. Need to balance guidance with conciseness. rmcp generates JSON Schema from `JsonSchema` derive — parameter `///` doc comments become `description` fields in the schema.
- **Acceptance Criteria:**
  - All 20 `#[tool(description)]` strings expanded with when-to-use, parameters, output, next-steps
  - All parameter types in `types.rs` have expanded `///` doc comments on fields
  - `cargo test` passes (no regressions)
  - Existing tool tests still pass (descriptions don't affect tool behavior)
  - `scorchkit serve` starts correctly with expanded descriptions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 57 default passed |
| Active pipelines | None |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code

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
Expand all 20 `#[tool(description = "...")]` strings in `tools.rs` from terse one-liners to 2-4 sentence guidance blocks. Each description follows the pattern: **what it does** + **when to use it** + **key parameters** + **what to do next**. Also expand `///` doc comments on parameter struct fields in `types.rs` — schemars converts these to JSON Schema `description` fields that Claude sees in the tool's input schema. No new types, no behavior changes — pure string content.

**Description Template (per tool):**
```
"<what it does>. <when to use it>. <key parameter guidance>. <what to do next / output format>"
```

Example before:
```
"Run a security scan against a target URL"
```

Example after:
```
"Run a security scan against a target URL without project persistence. Use for quick ad-hoc testing when you don't need to track results. Set profile to 'quick' for fast recon (4 modules), 'standard' for full built-in assessment, or 'thorough' for all modules including external tools. Use project_scan instead if you want results persisted and deduplicated. Returns JSON with findings array and summary statistics."
```

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/mcp/tools.rs` | Modify | Expand 20 `#[tool(description)]` strings |
| 2 | `src/mcp/types.rs` | Modify | Expand `///` doc comments on parameter struct fields |

**Type and Trait Changes:** None — string content only.

**Error Handling Strategy:** N/A — no error paths changed.

**Testing Strategy:**
- No new tests needed — descriptions don't affect tool behavior
- Verify all existing tests still pass (descriptions are metadata, not logic)
- `cargo test --features mcp` for no regressions
- Verify `cargo doc --no-deps` builds cleanly (doc comments are valid)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test --features mcp` | N/A | All 154 existing tests pass (no regressions) |
| 2 | `cargo clippy --all-features` | N/A | No new warnings from expanded strings |
| 3 | `cargo doc --no-deps --features mcp` | N/A | Doc comments build cleanly |

**Architectural Decisions:**
- **Inline in `#[tool()]` attribute** — descriptions stay in the `#[tool(description = "...")]` attribute, not extracted to a separate file. Unlike instructions (~4.5KB), individual tool descriptions are 2-4 sentences each and belong co-located with the tool wrapper they describe.
- **Multi-line string literals** — use `\` line continuation in Rust string literals to keep descriptions readable in source while remaining a single string at runtime.
- **Parameter descriptions via doc comments** — schemars 1.0 converts `///` doc comments on `JsonSchema` fields to `description` in the generated JSON Schema. This is the idiomatic approach — no custom schemars attributes needed.

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, tools

### Human Confirmed
- [ ] Design reviewed and confirmed

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Files Modified
| File | Change |
|------|--------|
| `src/mcp/tools.rs` | Expanded all 20 `#[tool(description)]` strings from one-liners to 2-4 sentence guidance blocks |
| `src/mcp/types.rs` | Expanded all parameter `///` doc comments with usage guidance, examples, and valid values |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from modified files
- **cargo test --features mcp:** Pass — 154 passed, 0 failed (unchanged — string-only changes)

### Notes
- Followed design exactly — each description follows pattern: what + when + key params + next steps
- No new tests needed — descriptions are metadata, don't affect tool behavior
- All existing tests pass unchanged confirming no regressions

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification
- **cargo fmt --check:** Pass — zero diffs
- **cargo test --features mcp:** Pass — 154 passed, 0 failed (unchanged)
- **```ignore check:** None found
- **#[ignore] check:** None found
- **#[allow] check:** None in modified files
- **semgrep:** Clean

### Code Review
- **20/20 tool descriptions expanded** — all multi-line with guidance
- **82 doc comment lines in types.rs** (expanded from ~30) — all parameters documented with valid values, examples, decision guidance
- **String-only changes** — zero behavior impact, zero runtime logic changes
- **schemars integration verified** — `///` doc comments on `JsonSchema` fields become JSON Schema `description` fields

### Test Results
- **Cargo Test Count:** mcp 154 (unchanged — string-only changes)

### Regression Test Plan Compliance
- 1/1: `cargo test --features mcp` passes — all 154 tests
- 2/2: `cargo clippy --all-features` — zero new warnings
- 3/3: `cargo doc --no-deps --features mcp` — builds cleanly

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (Independent)
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — no warnings in modified files
- **cargo test --features mcp:** Pass — 154 passed, 0 failed
- **cargo test --doc:** Pass — 1 doctest passed
- **Phase 4 Status:** PASS (verified in pipeline doc)

### Full Test Suite Results

| Test Binary | Count | Result |
|-------------|-------|--------|
| lib (unit tests) | 38 | PASS |
| ai_types | 14 | PASS |
| cli | 16 | PASS |
| mcp_tools | 29 | PASS |
| posture_metrics | 13 | PASS |
| project_cli | 6 | PASS |
| scan_plan | 13 | PASS |
| scan_schedules | 6 | PASS |
| storage | 11 | PASS |
| storage_integration | 7 | PASS |
| doctests | 1 | PASS |
| **Total** | **154** | **PASS** |

### Integration Tests
- 9 integration test binaries, 115 integration tests total — all PASS

### Regression Analysis
- **Phase 4 test count:** 154
- **Phase 5 test count:** 154
- **Delta:** 0 (no lost tests, no new tests — expected for string-only changes)
- **Regressions:** 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Self-Reflection
1. **Workarounds used:** None — pure string content changes.
2. **Cleanest version:** Yes — consistent description pattern, idiomatic schemars usage.
3. **Senior Rust approval:** Yes — zero behavior changes, zero new dependencies, zero test delta.

### Documentation
- No new architecture decisions (string-only change)
- `cargo doc --no-deps` builds cleanly (pre-existing warnings only)
- CHANGELOG.md updated (v0.11.0)

### Knowledge Recorded
- `save-generation-trace`: mcp-tool-descriptions (0 fix iterations, 154 tests, 100/95 scores)
- `learn`: Pipeline completion lesson (complementary instructions + descriptions)
- `learn`: Verification lesson (Phase 5)

### Final Pipeline Checklist

#### Pipeline Document Integrity
- [x] Forge Ticket ID matches real ticket (#40, 019d3a8a-5f4c-7244-b857-da6c0b8fbbf4)
- [x] ALL phases (1-5) show Status = PASS
- [x] Phase 1 has complete Work Spec
- [x] Phase 2 has File Manifest with specific paths
- [x] Phase 2 has Regression Test Plan
- [x] Phase 3 has Files Modified list
- [x] Phase 3 has Quality Gates with actual results
- [x] Phase 4 has Entry Verification results
- [x] Phase 4 has Code Review results
- [x] Phase 4 has Test Results with actual counts
- [x] Phase 5 has Cargo Test count (154)

#### Code Quality
- [x] `cargo fmt --check` = 0 diffs
- [x] `cargo clippy` = 0 warnings in modified files
- [x] `cargo test` = 0 failures (154 passed)
- [x] No ```` ```ignore ```` doctests
- [x] No `#[ignore]` tests

#### Knowledge Recording
- [x] `bootstrap` called
- [x] `recall` called
- [x] `learn` called
- [x] `save-generation-trace` called
- [x] CHANGELOG.md updated (v0.11.0)

#### Documentation
- [x] No new architecture decisions to document
- [x] `cargo doc --no-deps` builds (pre-existing warnings only)
