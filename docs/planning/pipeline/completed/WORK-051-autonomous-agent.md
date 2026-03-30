# Work Pipeline: Autonomous Scan Agent

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 3: Implement |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` for Phase 4 |
| **Blocked** | No |
| **Forge Ticket** | #51 |
| **Forge Ticket ID** | 019d3f0f-628c-727e-9e81-b1b147265bd2 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** Autonomous scan agent — recon→plan→scan→analyze loop
- **Type:** Feature
- **Scope:** New `agent run <target>` CLI command that drives the full autonomous pentest loop: (1) init/setup project, (2) run recon modules, (3) AI-plan scan strategy, (4) execute planned scan, (5) AI-analyze findings, (6) persist results + update intelligence, (7) display summary report. Calls existing internal functions directly (Orchestrator, ScanPlanner, AiAnalyst) — does NOT go through MCP. Respects AgentConfig safety constraints (authorized targets, rate limiting, no exploitation).
- **Files Expected:** 3-5 files (new src/agent/runner.rs, modify src/agent/mod.rs, src/cli/args.rs, src/cli/runner.rs)
- **Dependencies:** All three prior tickets (#48 doctor, #49 init, #50 intelligence) — complete
- **Risks:** Medium — orchestrates many subsystems but calls existing, tested functions. AI failures handled via graceful fallback (plan fails → use profile, analysis fails → skip).
- **Acceptance Criteria:**
  - `agent run <target>` executes the full recon→plan→scan→analyze loop
  - `agent run <target> --project <name>` persists results and updates intelligence
  - `agent run <target> --depth quick|standard|thorough` controls scan depth
  - Each phase prints progress to terminal with colored status
  - AI planner failure → graceful fallback to profile-based scanning
  - AI analysis failure → scan results still saved, analysis skipped
  - Respects AgentConfig safety: authorized_targets scope enforcement
  - Unit tests for phase orchestration logic (decision gates, fallback paths)
  - Zero clippy warnings, cargo fmt clean

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK |
| Security tools | OK |
| Hooks wired | OK (8 total) |
| cargo check | OK |
| cargo test | OK (185 passed) |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- After context continuation, re-read pipeline doc
- Never modify published migrations
- Must call bootstrap → recall before coding

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=[...])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` for project patterns before writing code

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
