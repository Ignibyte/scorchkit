# Work Pipeline: Project Intelligence Layer

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 3: Implement |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /implement |
| **Next Step** | Run `/implement` for Phase 3 |
| **Blocked** | No |
| **Forge Ticket** | #50 |
| **Forge Ticket ID** | 019d3f0f-504e-7254-a56f-dc3b7c135dd7 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Architecture

**Approach:**
New `src/storage/intelligence.rs` module containing types and logic for per-project module effectiveness tracking. `ProjectIntelligence` struct stored as JSON in the existing `Project.settings` JSONB field — **no new migrations**. After each scan with `--project`, compute per-module stats via SQL aggregate query on tracked_findings grouped by module_id, merge with existing intelligence data, and persist back to Project.settings. CLI subcommand `project intelligence <name>` displays module ranking table. AI planner gets an optional intelligence context section appended to its prompt.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/storage/intelligence.rs` | Create | ProjectIntelligence, ModuleStats, TargetProfile types + compute/merge/read logic |
| 2 | `src/storage/mod.rs` | Modify | Add `pub mod intelligence;` |
| 3 | `src/storage/projects.rs` | Modify | Add `update_project_settings()` function |
| 4 | `src/cli/runner.rs` | Modify | After scan persistence, call `update_intelligence()` |
| 5 | `src/cli/project.rs` | Modify | Add `Intelligence` subcommand + handler |
| 6 | `src/ai/prompts.rs` | Modify | `build_planning_prompt()` gains optional intelligence context parameter |

**Key Types:**

```rust
/// Per-module effectiveness statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModuleStats {
    total_runs: u32,
    total_findings: u32,
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    info: u32,
    effectiveness_score: f64,  // total_findings / total_runs
}

/// Structured target fingerprint for machine use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetProfile {
    pub server: Option<String>,
    pub technologies: Vec<String>,
    pub cms: Option<String>,
    pub waf: Option<String>,
    pub is_https: bool,
}

/// Aggregated project intelligence stored in Project.settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectIntelligence {
    pub modules: HashMap<String, ModuleStats>,
    pub target_profile: Option<TargetProfile>,
    pub total_scans: u32,
    pub last_updated: Option<String>,  // ISO 8601 datetime
}
```

**Computation Flow:**

1. After scan persistence in `runner.rs`, call `intelligence::update_intelligence(pool, project_id, &scan_result)`
2. `update_intelligence()`:
   a. Read current `ProjectIntelligence` from `Project.settings` (or default if empty)
   b. For each module in `scan_result.modules_run`: increment `total_runs`
   c. For each finding in `scan_result.findings`: increment module's finding counts by severity
   d. Recompute `effectiveness_score = total_findings / total_runs` for each module
   e. Increment `total_scans`
   f. Set `last_updated` to now
   g. Serialize back to JSON and call `update_project_settings(pool, project_id, settings)`

**SQL for settings update:**
```sql
UPDATE projects SET settings = $2, updated_at = now() WHERE id = $1 RETURNING *
```

**CLI: `project intelligence <name>`:**
- Fetch project by name
- Deserialize `ProjectIntelligence` from `settings`
- Display table: module_id | runs | findings | critical | high | score
- Sort by effectiveness_score descending

**AI Planner Enhancement:**
- `build_planning_prompt()` signature changes to accept optional `intelligence: Option<&str>`
- If present, append section: `\n\nHISTORICAL MODULE EFFECTIVENESS:\n{intelligence}\n`
- Caller (planner.rs) reads ProjectIntelligence from DB when project context available, formats as compact JSON

**Error Handling:**
- Invalid JSON in settings → default ProjectIntelligence (graceful recovery)
- DB write failure → ScorchError::Database (propagated, non-fatal to scan)
- Missing project → skip intelligence update silently

**Testing Strategy:**
- Unit tests for ModuleStats merge logic (no DB needed)
- Unit test for ProjectIntelligence serialization roundtrip
- Unit test for effectiveness score computation
- Unit test for AI prompt with intelligence context
- No integration tests (DB-dependent)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_module_stats_merge` | `src/storage/intelligence.rs` | Merging new scan stats into existing stats |
| 2 | `test_effectiveness_score` | `src/storage/intelligence.rs` | Score = findings / runs, handles zero |
| 3 | `test_intelligence_serde_roundtrip` | `src/storage/intelligence.rs` | Serialize → deserialize preserves all fields |
| 4 | `test_intelligence_from_empty_settings` | `src/storage/intelligence.rs` | Empty JSON → default ProjectIntelligence |
| 5 | `test_intelligence_from_invalid_json` | `src/storage/intelligence.rs` | Malformed JSON → graceful default |
| 6 | `test_target_profile_serde` | `src/storage/intelligence.rs` | TargetProfile roundtrip |
| 7 | `test_planning_prompt_with_intelligence` | `src/ai/prompts.rs` | Prompt contains intelligence section when provided |
| 8 | `test_planning_prompt_without_intelligence` | `src/ai/prompts.rs` | Prompt unchanged when intelligence is None |

**Architectural Decisions:**
- **No new migrations** — uses existing Project.settings JSONB field (prevention rule compliance)
- **Merge-on-write** — compute new stats from ScanResult in-memory, merge with persisted data, write back. Avoids complex SQL aggregation on every read.
- **Graceful degradation** — malformed settings JSON falls back to default, never crashes
- **Intelligence in AI prompt is additive** — optional section appended to existing prompt, planner logic unchanged

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1 (architecture decision)
- **Failures:** 0
- **Component Types:** storage, ai, cli

### Human Confirmed
- [ ] Design reviewed and confirmed

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
