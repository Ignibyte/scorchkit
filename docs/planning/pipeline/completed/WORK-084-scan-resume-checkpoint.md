# Work Pipeline: Scan Resume / Checkpoint

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-03 |
| **Last Updated** | 2026-04-04 |
| **Last Command** | /implement |
| **Next Step** | Quality gates |
| **Blocked** | No |
| **Forge Ticket** | #83 |
| **Forge Ticket ID** | 019d59a1-f134-7008-bbbc-ebb5be14aa94 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-03
**Completed:** 2026-04-03

### Work Spec
- **Title:** Scan Resume and Checkpoint System
- **Type:** Feature
- **Scope:** Enable interrupted scans to resume from where they left off. After each module completes, checkpoint its results to the storage layer. On resume, the orchestrator skips completed modules and restarts from the first incomplete one. New `--resume <scan-id>` CLI flag.
- **Files Expected:** 4-6 files — modify `src/runner/orchestrator.rs` (checkpoint logic), modify `src/storage/scans.rs` (per-module status persistence), modify `src/cli/args.rs` (resume flag), modify `src/cli/runner.rs` (resume dispatch), tests
- **Dependencies:** Storage layer (already exists with PostgreSQL)
- **Risks:** Medium. Must handle partial module results correctly. Module ordering must be deterministic for resume to work. Need to handle config changes between original and resume runs.
- **Acceptance Criteria:**
  - Each module completion checkpointed to storage with status + findings
  - New `--resume <scan-id>` CLI flag
  - Resume loads previous scan state and skips completed modules
  - Resume detects config changes and warns user
  - Interrupted scan (Ctrl+C) saves partial state via signal handler
  - Progress display shows "Resuming: N/M modules already complete"
  - Completed findings from previous run included in final report
  - All existing tests pass, resume logic has unit tests
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
