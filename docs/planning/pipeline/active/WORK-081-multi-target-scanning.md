# Work Pipeline: Multi-Target Scanning

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 1: Plan |
| **Created** | 2026-04-03 |
| **Last Updated** | 2026-04-03 |
| **Last Command** | /work |
| **Next Step** | Human review spec, then run `/design` |
| **Blocked** | No |
| **Forge Ticket** | TBD |
| **Forge Ticket ID** | TBD |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-03
**Completed:** 2026-04-03

### Work Spec
- **Title:** Multi-Target Scanning (Target File Input)
- **Type:** Feature
- **Scope:** Add support for scanning multiple targets from a file. New `--targets-file` CLI flag accepts a file with one target per line. Targets are scanned sequentially or with configurable parallelism. Each target produces its own findings, and the combined report aggregates all results. Supports comments (#) and blank lines in target files.
- **Files Expected:** 4-6 files — modify `src/cli/args.rs` (new flag), modify `src/cli/runner.rs` (dispatch logic), modify `src/runner/orchestrator.rs` (multi-target loop), modify `src/engine/target.rs` (target file parsing), tests
- **Dependencies:** None — builds on existing orchestrator
- **Risks:** Medium. Memory usage with many targets. Need to handle individual target failures gracefully without aborting the entire batch. Report aggregation across targets needs careful design.
- **Acceptance Criteria:**
  - New `--targets-file <path>` CLI flag
  - Parses target file: one URL/domain per line, supports `#` comments and blank lines
  - Scans each target with the configured profile/modules
  - Individual target failures logged but don't abort batch
  - Combined JSON/HTML/SARIF report with per-target sections
  - Progress display shows current target N/total
  - `--targets-file` and positional `<target>` are mutually exclusive
  - All existing tests pass, new feature has unit + integration tests
  - `cargo clippy` zero warnings

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | TBD |
| Toolchain | TBD |
| Security tools | TBD |
| Hooks wired | TBD |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- TBD — recall at design phase

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
**Status:** Not Started

---

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started

---

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** Not Started

---

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
