# Work Pipeline: MCP Prompt Templates + Finding Correlation Tool

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #44 + #45 (merged pipeline) |
| **Forge Ticket ID** | 019d3a8a-9fcb-73b3-b560-4f41e331dbbd (#44), 019d3a8a-aeae-73c1-ba79-39c9bdfe1d77 (#45) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** MCP prompt templates for pentest workflows + finding correlation tool
- **Type:** Feature
- **Scope:** Two MCP server extensions, both feature-gated behind `mcp`:
  1. **Prompt Templates** (#44) — Enable MCP prompts capability via rmcp `ServerHandler` (`list_prompts`, `get_prompt`). Add 5 workflow templates: full-web-assessment, investigate-finding, remediation-plan, compare-scans, executive-summary. Each template returns structured prompt messages with arguments that Claude can use as workflow starting points. New file `src/mcp/prompts.rs` with prompt logic, modifications to `src/mcp/server.rs` for capability + handler overrides.
  2. **Finding Correlation** (#45) — New `correlate_findings` MCP tool that groups related findings into attack chains using rule-based CWE/OWASP relationships. Example: missing CSP + reflected XSS + cookie without HttpOnly = "session hijacking via XSS" chain. Returns structured attack narratives with severity escalation. New `do_correlate_findings` method on `ScorchKitServer` + `#[tool]` wrapper, parameter type in `types.rs`.
- **Files Expected:** ~4 files (new `src/mcp/prompts.rs`, modify `src/mcp/server.rs`, modify `src/mcp/tools.rs`, modify `src/mcp/types.rs`)
- **Dependencies:** Existing `ScorchKitServer`, rmcp `ServerHandler` trait, storage CRUD for findings
- **Risks:**
  - rmcp prompt support may have specific API constraints (need to check ServerHandler trait methods)
  - Attack chain correlation rules need careful design to avoid false positive chains
  - Prompts are a different MCP primitive than tools — different handler methods
- **Acceptance Criteria:**
  - MCP `list_prompts` returns 5 prompt templates
  - MCP `get_prompt` returns structured messages for each template
  - `correlate_findings` tool groups related findings into attack chains
  - Parameter types in `types.rs` with `JsonSchema` derives
  - Tests in `tests/mcp_tools.rs` for prompt listing and correlation
  - `cargo test --features mcp` passes with no regressions
  - MCP server now exposes 19 tools + 5 prompts

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 151 default passed |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- MCP tools are feature-gated behind `mcp` — tests must use `--features mcp`
- rmcp #[tool] macro generates JSON Schema from schemars — parameter types need JsonSchema derive
- tools.rs is already 1000+ lines — keep correlation logic clean

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
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Architecture

**Approach:**

**Feature 1: MCP Prompt Templates (#44)**
Manual `ServerHandler` method overrides for `list_prompts` and `get_prompt` — same pattern as resources, avoids macro conflict with existing `#[tool_handler]`. Five workflow templates:
1. `full-web-assessment` — Complete pentest workflow for a target URL (arg: target)
2. `investigate-finding` — Deep dive into a specific finding (arg: finding_id)
3. `remediation-plan` — Prioritized fix plan for a project (arg: project)
4. `compare-scans` — Analyze changes between scans (args: project, scan_id_a, scan_id_b)
5. `executive-summary` — Client-ready posture summary (arg: project)

Each prompt returns `Vec<PromptMessage>` with User/Assistant role messages that give Claude structured starting points.

**Feature 2: Finding Correlation (#45)**
New `correlate_findings` MCP tool — rule-based attack chain detection. Loads project findings, applies correlation rules based on module_id + OWASP category + CWE combinations, groups into `AttackChain` structs with narrative, severity escalation, and chain members. Example rules:
- XSS + missing CSP + cookie without HttpOnly = "Session Hijacking via XSS"
- SQLi + exposed DB port + no WAF = "Database Compromise"
- SSRF + cloud metadata exposure = "Cloud Credential Theft"

Returns JSON array of attack chains, each with: chain_name, severity, narrative, findings list, remediation_priority.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/mcp/prompts.rs` | Create | Prompt logic: do_list_prompts, do_get_prompt, prompt definitions |
| 2 | `src/mcp/server.rs` | Modify | Add prompt_router field, enable_prompts(), override list_prompts/get_prompt |
| 3 | `src/mcp/tools.rs` | Modify | Add do_correlate_findings + #[tool] wrapper |
| 4 | `src/mcp/types.rs` | Modify | Add CorrelateFindingsParams |
| 5 | `src/mcp/mod.rs` | Modify | Add `pub mod prompts;` |
| 6 | `tests/mcp_tools.rs` | Modify | Add prompt listing test + correlation params test |

**Type and Trait Changes:**
- `CorrelateFindingsParams` — `project: String` (derives Debug, Deserialize, JsonSchema)
- No new traits

**Error Handling:**
- Prompt methods return `Result<_, rmcp::ErrorData>` (same as resources)
- correlate_findings returns `Result<String, String>` (same as all tools)

**Testing Strategy:**
- `test_prompt_list` — verify 5 prompts returned
- `test_prompt_get_full_assessment` — verify prompt returns messages
- `test_tool_correlate_findings` — verify params deserialize
- Correlation rule logic tested via unit tests in prompts.rs

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test --features mcp` | N/A | All existing 251 mcp tests pass |
| 2 | `test_prompt_list` | `tests/mcp_tools.rs` | 5 prompts listed |
| 3 | `test_prompt_get` | `tests/mcp_tools.rs` | Prompt returns messages |
| 4 | `test_tool_correlate_findings` | `tests/mcp_tools.rs` | Params deserialize |
| 5 | `test_correlate_chains` | `src/mcp/prompts.rs` | Attack chain rule logic |

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** mcp

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Files Created
| # | File | Purpose |
|---|------|---------|
| 1 | `src/mcp/prompts.rs` | 5 prompt templates + attack chain correlation logic |

### Files Modified
| # | File | Change |
|---|------|--------|
| 1 | `src/mcp/mod.rs` | Added `pub mod prompts` |
| 2 | `src/mcp/server.rs` | Added `enable_prompts()`, `list_prompts`/`get_prompt` overrides |
| 3 | `src/mcp/tools.rs` | Added `do_correlate_findings` + `#[tool]` wrapper |
| 4 | `src/mcp/types.rs` | Added `CorrelateFindingsParams` |
| 5 | `tests/mcp_tools.rs` | Added 3 tests (correlate params, prompt list, prompt get) |

### Quality Gates
| Gate | Result |
|------|--------|
| `cargo fmt --check` | 0 diffs |
| `cargo clippy --all-features` | 0 new warnings |
| `cargo test --features mcp` | 260 passed, 0 failed (+9 new) |

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Entry Verification
- `cargo fmt --check` = 0 diffs
- `cargo clippy --all-features` = 0 new warnings
- `cargo test --features mcp` = 260 passed
- No banned patterns

### Code Review
- [x] All pub items documented, `#[must_use]` on list, `# Errors` on get
- [x] No unwrap/expect in library code
- [x] Correlation refactored to data-driven rules with `#[allow(too_many_lines)]` justified
- [x] Non-exhaustive struct constructors used (Prompt::new, PromptArgument::new)

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

- cargo test --features mcp: 260 passed, 0 failed
- Regressions: 0 (was 251, now 260 = +9 new)

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Final Pipeline Checklist
- [x] ALL phases (1-5) = PASS
- [x] Quality gates clean
- [x] Knowledge recorded
- [x] CHANGELOG updated (v0.24.0)
