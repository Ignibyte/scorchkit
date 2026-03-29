# Work Pipeline: Architecture Doc — MCP Server Design

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Chore (documentation) |
| **Status** | Phase 6: Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #9 |
| **Forge Ticket ID** | 019d364e-e67f-71d4-9fb7-5d20164cde9e |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Architecture doc — MCP server design (`docs/architecture/mcp.md`)
- **Type:** Chore (documentation)
- **Scope:** Create a comprehensive architecture document for the MCP server layer covering: server struct, tool dispatch via rmcp macros, resource browsing, transport, feature gating, testing strategy, and how MCP relates to the CLI and storage layers. This is the capstone documentation for the project.
- **Files Expected:** 1 new (`docs/architecture/mcp.md`), 1 modified (`docs/architecture/overview.md` — add MCP to the system diagram)
- **Dependencies:** All existing architecture docs (overview, storage, ai, cli), Forge architecture decisions (mcp.server-implementation, mcp.resources), CHANGELOG entries for v0.4.0-v0.9.0
- **Risks:** Low — documentation only, no code changes. Risk is incompleteness, which the user has asked to mitigate with two review passes.
- **Acceptance Criteria:**
  - `docs/architecture/mcp.md` covers: server struct, tools (20), resources (6 URIs + 5 templates), transport, feature gating, testing strategy, architecture decisions
  - `docs/architecture/overview.md` updated to show MCP in the system diagram
  - All 15 Forge architecture decisions referenced where relevant
  - Two review passes during validate phase for completeness
  - `cargo doc --no-deps` still builds cleanly
  - No code changes — docs only

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
- NEVER modify a published migration after it has been tagged in a release

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
Write `docs/architecture/mcp.md` following the established style of `storage.md` and `ai.md` (decision + rationale + file structure + diagrams + alternatives). Document must cover the full MCP layer: server struct, 20 tools organized by category, 6 resource URIs with 5 templates, stdio transport, feature gating (`mcp` implies `storage`), the `do_*` testing pattern, and architecture decisions. Update `overview.md` to add MCP as an alternative entry point alongside CLI in the system diagram.

**Document Outline for `docs/architecture/mcp.md`:**
1. **Header** — title, date, pipeline reference
2. **Decision** — MCP server via rmcp, feature-gated, tools + resources
3. **Rationale** — why MCP, why rmcp, why feature-gated
4. **Architecture Diagram** — CLI vs MCP entry points converging on Orchestrator/Storage
5. **Server Structure** — `ScorchKitServer` struct, `ServerHandler` impl, `#[tool_handler]`/`#[tool_router]` macros
6. **Tools (20)** — table organized by category (scanning, project management, finding lifecycle, scheduling, AI, infrastructure)
7. **Resources (6 URIs + 5 templates)** — URI scheme, resource list, templates, read dispatch
8. **Transport** — stdio via `rmcp::transport::io::stdio`, `scorchkit serve` command
9. **Feature Gating** — `mcp` feature implies `storage`, Cargo.toml structure, conditional compilation
10. **Testing Strategy** — `do_*` public method pattern, direct method calls, `DATABASE_URL` skip pattern
11. **Dependencies** — rmcp, schemars, what `mcp` feature adds
12. **Alternatives Considered** — table of rejected approaches

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `docs/architecture/mcp.md` | Create | Comprehensive MCP server architecture document |
| 2 | `docs/architecture/overview.md` | Modify | Add MCP server to the system diagram as alternative entry point |

**Type and Trait Changes:** None — documentation only.

**Error Handling Strategy:** N/A — documentation only.

**Testing Strategy:**
- No code tests since this is docs-only
- Verify `cargo test` still passes (no regressions from doc changes)
- Verify `cargo doc --no-deps` builds cleanly
- Two review passes during validate for completeness:
  - Pass 1: Verify all 20 tools listed, all 6 resource URIs, all architectural decisions referenced
  - Pass 2: Cross-reference against actual source code for accuracy

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` | N/A | No regressions from doc-only changes |
| 2 | `cargo doc --no-deps --features mcp` | N/A | Docs build cleanly |
| 3 | Manual: all 20 tools listed | `docs/architecture/mcp.md` | Tool table matches `#[tool]` annotations in `tools.rs` |
| 4 | Manual: all 6 resource URIs listed | `docs/architecture/mcp.md` | URI table matches `ResourceKind` enum in `resources.rs` |
| 5 | Manual: overview diagram includes MCP | `docs/architecture/overview.md` | MCP shown as entry point |

**Architectural Decisions:**
- Follow existing doc style exactly (storage.md and ai.md as templates)
- No code changes — pure documentation
- Overview diagram update is minimal — add MCP as parallel entry point to CLI, not a restructure

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, documentation

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
| MCP architecture document | `docs/architecture/mcp.md` |

### Files Modified
| File | Change |
|------|--------|
| `docs/architecture/overview.md` | Added MCP server to system architecture diagram as parallel entry point alongside CLI. Added Storage layer to diagram. Added cross-reference to mcp.md. |

### Quality Gates
- **cargo fmt --check:** N/A (docs only)
- **cargo clippy:** N/A (docs only)
- **cargo test:** Pass — 57 default, 0 failed (unchanged)
- **cargo doc --no-deps --features mcp:** 2 warnings (pre-existing, unrelated to new docs)

### Notes
- Followed design exactly — 12 sections as specified
- All 20 tools listed and categorized (scanning 4, project mgmt 6, findings 3, targets 3, scheduling 2, AI 1, infrastructure 1)
- All 6 resource URIs and 5 templates documented
- Architecture diagram shows CLI and MCP as parallel entry points
- Feature gating cascade documented (default -> storage -> mcp)
- Testing strategy (do_* pattern, DATABASE_URL skip) documented
- Alternatives considered table with 7 entries
- Style matches storage.md and ai.md

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, documentation

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (independently run)
- **cargo fmt --check:** Pass — zero diffs
- **cargo test:** Pass — 57 default, 0 failed (unchanged)
- **```ignore check:** Pass — none found
- **#[ignore] check:** Pass — none found
- **semgrep:** Pass — clean

### Doc Review (Two Passes)

**Pass 1 — Completeness:**
- 20/20 tools listed in doc match 20 `#[tool]` annotations in `tools.rs`
- 6/6 resource URIs match 6 `ResourceKind` enum variants in `resources.rs`
- 5/5 templates match `resource_templates()` function
- Feature gating cascade documented, matches `Cargo.toml`
- Architecture diagram present in both `mcp.md` and updated `overview.md`
- 7 alternatives considered with rejection rationale
- Test strategy with actual code examples

**Pass 2 — Source Code Accuracy:**
- `ScorchKitServer` struct fields match `server.rs:26-32` exactly
- Feature gate `mcp = ["storage", "dep:rmcp", "dep:schemars"]` matches `Cargo.toml:75`
- `#[tool_handler]` insight (only generates call_tool/list_tools) verified against rmcp macro source
- `serve()` function pattern matches `server.rs:62-71`
- `do_*` pattern accurately described
- Test counts (default 57, mcp 149) match Phase 5 verification from pipeline #8
- `ResourceKind` enum variants match source exactly
- Dependencies (rmcp 1.3, schemars 1.0) match Cargo.toml
- Claude Code integration JSON format is correct
- Overview diagram cross-reference to mcp.md present

### Regression Test Plan Compliance
- 1/1: `cargo test` passes — no regressions
- 2/2: `cargo doc --no-deps --features mcp` — 2 warnings (pre-existing, not from new docs)
- 3/3: All 20 tools listed — verified against `#[tool]` annotations
- 4/4: All 6 resource URIs listed — verified against `ResourceKind` enum
- 5/5: Overview diagram includes MCP — verified

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, documentation

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Cargo Test Full Suite:** Pass
- **Cargo Test Count:** default 57 (unchanged), mcp 149 (identical to Phase 4)
- **Cargo Test Regressions:** None — zero tests lost, zero newly failing
- **Integration Tests:** Pass — all 10 binaries clean
- **cargo fmt --check:** Clean
- **cargo test --doc:** Pass

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp, documentation

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

- **Documentation Updated:** docs/architecture/mcp.md (created), docs/architecture/overview.md (diagram updated)
- **Changelog Updated:** N/A — docs-only chore, no user-facing feature change
- **Pipeline Doc Archived:** Yes — moved to `completed/`

### Self-Reflection
1. **Did any phase use workarounds?** No. Pure documentation, no code changes, no workarounds needed.
2. **Was the implementation the cleanest version?** Yes. Follows established style from storage.md and ai.md. Shows actual code patterns (struct fields, enum variants, function signatures) making the doc verifiable against source.
3. **Would a senior Rust developer approve?** Yes. Comprehensive coverage of the MCP layer, accurate cross-references, and the two-pass validation caught nothing because the doc was written from actual source code, not memory.

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes (019d3a7e-ee37-720a-9313-627688a9acbe)
- **Lessons Recorded:** 5 (1 design + 1 implementation + 1 validation + 1 testing + 1 pipeline)
- **Failures Recorded:** 0
- **Component Types Tagged:** mcp, documentation
