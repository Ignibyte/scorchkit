# Work Pipeline: Finding Confidence Scores

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
- **Title:** Finding Confidence Scores
- **Type:** Feature
- **Scope:** Add a confidence score (0.0-1.0) to findings indicating false-positive likelihood. Each scanner module sets confidence based on detection method: confirmed exploitation = 1.0, response content match = 0.8, timing-based = 0.6, heuristic/pattern = 0.4, informational = 0.2. Confidence displayed in all report formats and filterable via CLI.
- **Files Expected:** 5-8 files — modify `src/engine/finding.rs` (add field + builder method), modify all scanner/recon modules to set confidence, modify report formats, modify CLI args for `--min-confidence` filter
- **Dependencies:** None — extends existing Finding struct
- **Risks:** Low for the engine change. Medium scope — touching every scanner module, but each change is a one-liner `.with_confidence(0.X)`.
- **Acceptance Criteria:**
  - `Finding` struct has `confidence: f64` field (0.0-1.0)
  - `Finding::new()` defaults to 0.5 (medium confidence)
  - `.with_confidence(f64)` builder method added
  - All existing scanner modules updated with appropriate confidence values
  - New `--min-confidence <float>` CLI flag filters findings below threshold
  - Confidence shown in terminal, JSON, HTML, SARIF, PDF reports
  - Storage layer persists confidence score
  - All existing tests pass, confidence values tested
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
