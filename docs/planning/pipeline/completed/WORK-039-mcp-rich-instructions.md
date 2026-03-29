# Work Pipeline: MCP Rich System Instructions for Claude-as-Operator

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #39 |
| **Forge Ticket ID** | 019d3a8a-51f3-7083-b675-995e80bcf66b |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Rich system instructions with pentest methodology for Claude-as-operator
- **Type:** Feature
- **Scope:** Replace the minimal `ServerInfo.instructions` string with a comprehensive pentest methodology guide that teaches Claude the engagement workflow, tool sequencing, decision framework, profile selection, finding interpretation, and resource vs tool usage. The single cheapest change with the highest impact on Claude's effectiveness as the primary operator.
- **Files Expected:** ~2-3 files modified (server.rs instructions string, possibly a new instructions module or const file)
- **Dependencies:** Existing MCP server, all 20 tools and 6 resources
- **Risks:** Instruction text too long could bloat MCP handshake. Need to balance comprehensiveness with token efficiency.
- **Acceptance Criteria:**
  - Instructions cover: engagement workflow, tool sequencing, profile selection, finding interpretation, resource browsing
  - Instructions reference all 20 tools by name with usage guidance
  - Instructions include pentest methodology (OWASP, PTES phases)
  - `cargo test` still passes (no regressions)
  - `scorchkit serve` still starts correctly with new instructions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0, rustc 1.94.0 |
| Security tools | OK — semgrep 1.156.0, cargo-audit 0.22.1, cargo-deny 0.19.0 |
| Hooks wired | OK — 2 PreToolUse + 6 Stop = 8 total |
| cargo check | OK — compiles clean |
| cargo test | OK — 57 default passed, 0 failed |
| gh CLI | OK — 2.87.3 |

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
Create `src/mcp/instructions.rs` containing a `pub const INSTRUCTIONS: &str` with comprehensive pentest methodology. Update `server.rs` to import and use the const instead of the inline string. The instructions teach Claude 7 sections: identity/role, engagement workflow (PTES-adapted), tool reference by category, scan profile selection, finding interpretation, resource browsing, and safety/scope. Separate file keeps the ~3KB text out of `server.rs`. Const `&str` avoids runtime `String` allocation.

**Instructions Content Outline:**

1. **Identity** — "You are a security testing assistant powered by ScorchKit..."
2. **Engagement Workflow** (7 steps):
   - Step 1: Project setup (`project_create`, `target_add`)
   - Step 2: Recon (`scan` with quick profile, `list_modules`)
   - Step 3: Plan (`plan_scan` for AI-guided module selection)
   - Step 4: Targeted scan (`project_scan` with planned modules)
   - Step 5: Analysis (`analyze_findings` with focus modes)
   - Step 6: Triage (`finding_update_status`, `project_findings`)
   - Step 7: Report (`project_status` for posture, `analyze_findings` with remediate focus)
3. **Tool Categories** — scanning (4), project mgmt (6), findings (3), targets (3), scheduling (2), AI (1), infrastructure (1), with when-to-use guidance
4. **Scan Profiles** — quick (fast recon, 4 modules), standard (full built-in), thorough (all including external tools)
5. **Finding Interpretation** — severity levels, lifecycle states, prioritization strategy
6. **Resources vs Tools** — browse with resources (read-only discovery), act with tools (mutations/scans)
7. **Safety** — only scan authorized targets, respect scope, don't modify findings without user direction

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/mcp/instructions.rs` | Create | `pub const INSTRUCTIONS: &str` with full methodology |
| 2 | `src/mcp/mod.rs` | Modify | Add `pub mod instructions;` |
| 3 | `src/mcp/server.rs` | Modify | Replace inline string with `instructions::INSTRUCTIONS` |

**Type and Trait Changes:** None — only a const string and an import change.

**Error Handling Strategy:** N/A — no error paths. Const string is infallible.

**Testing Strategy:**
- Verify `INSTRUCTIONS` const is non-empty and contains key sections
- Verify `get_info()` returns the new instructions (existing test `test_server_creation` checks `get_info()`)
- Verify all 20 tool names appear in the instructions text
- `cargo test` for no regressions

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_instructions_not_empty` | `src/mcp/instructions.rs` | Const is non-empty |
| 2 | `test_instructions_contains_workflow` | `src/mcp/instructions.rs` | Contains engagement workflow steps |
| 3 | `test_instructions_contains_all_tools` | `src/mcp/instructions.rs` | All 20 tool names referenced |
| 4 | `test_instructions_contains_profiles` | `src/mcp/instructions.rs` | Scan profiles documented |
| 5 | `test_server_uses_instructions` | `tests/mcp_tools.rs` | `get_info().instructions` contains "ScorchKit" |
| 6 | `cargo test` | N/A | No regressions |

**Architectural Decisions:**
- **Separate file** — `instructions.rs` keeps the ~3KB text out of `server.rs`. Same pattern as `prompts.rs` in the `ai/` module.
- **Const `&str`** — No runtime allocation. `get_info()` calls `.to_string()` once per MCP session initialization (acceptable).
- **All tool names in instructions** — Even though tool descriptions exist separately, the instructions need tool names for workflow sequencing ("first call `project_create`, then `target_add`"). Testable assertion.

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, instructions

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
| MCP instructions const | `src/mcp/instructions.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/mcp/mod.rs` | Added `pub mod instructions;` |
| `src/mcp/server.rs` | Replaced inline instructions string with `super::instructions::INSTRUCTIONS.to_string()` |
| `tests/mcp_tools.rs` | Added `test_server_uses_rich_instructions` integration test |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from new code
- **cargo test:** Pass — default 57 (unchanged), mcp 154 (was 149, +5 new)

### Notes
- Followed design exactly — 7-section methodology in const &str
- 4 unit tests in instructions.rs: non-empty, workflow steps, all 20 tools, profiles
- 1 integration test in mcp_tools.rs: get_info() returns rich instructions
- Instructions text is ~4.5KB — substantial but not bloated

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, instructions

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (independently run)
- **cargo fmt --check:** Pass — zero diffs
- **cargo test --features mcp:** Pass — 154 passed, 0 failed
- **```ignore check:** Pass — none found
- **#[ignore] check:** Pass — none found
- **#[allow] workaround check:** Pass — none in new code
- **semgrep:** Pass — clean

### Code Review
- **Standards Compliance:** Pass
  - `//!` module doc on instructions.rs
  - `///` doc comment on `pub const INSTRUCTIONS`
  - Zero `unwrap()`/`expect()` (const string only)
  - Zero `unsafe`, zero dead code
  - Clean import in server.rs via `super::instructions::INSTRUCTIONS`
  - `pub mod instructions;` in alphabetical order in mod.rs
- **Workaround Detection:** Pass — no workarounds
- **Security Review (semgrep):** Pass — clean

### Test Results
- **Cargo Test Count:** default 57 (unchanged), mcp 154 (was 149, +5)
- **Doctest Count:** 1 (unchanged)

### Regression Test Plan Compliance
- 5/5 tests implemented and passing:
  1. `instructions_not_empty` — verifies >1000 bytes
  2. `instructions_contains_workflow` — verifies all 7 PTES steps
  3. `instructions_contains_all_tools` — verifies all 20 tool names present
  4. `instructions_contains_profiles` — verifies quick/standard/thorough
  5. `test_server_uses_rich_instructions` — verifies get_info() returns rich instructions
- Test quality: `instructions_contains_all_tools` is the strongest — enumerates all 20 tool names, will catch sync drift if tools are added/renamed

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, instructions

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Cargo Test Full Suite:** Pass
- **Cargo Test Count:** default 57 (unchanged), mcp 154 (identical to Phase 4)
- **Cargo Test Regressions:** None — zero tests lost, zero newly failing
- **Integration Tests:** Pass — 29 mcp_tools tests, all binaries clean
- **cargo fmt --check:** Clean

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, instructions

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Documentation Updated:** CHANGELOG.md (v0.10.0), architecture decision recorded in Forge (mcp.instructions)
- **Changelog Updated:** Yes — v0.10.0
- **Pipeline Doc Archived:** Yes — moved to `completed/`

### Self-Reflection
1. **Did any phase use workarounds?** No. Pure const string, no runtime logic, no workarounds needed.
2. **Was the implementation the cleanest version?** Yes. Separate file for large text, const avoids allocation, test enumerates all tool names for sync safety.
3. **Would a senior Rust developer approve?** Yes. Minimal code change (const + import), maximum impact on Claude's decision-making.

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes (019d3a99-402d-72cc-8f76-5220a3d29111)
- **Lessons Recorded:** 5 (design + implementation + validation + testing + pipeline)
- **Failures Recorded:** 0
- **Component Types Tagged:** mcp, instructions
