# Module Pipeline: {ModuleName}

| Field | Value |
|-------|-------|
| **Pipeline Type** | Module |
| **Module Type** | Scanner / Recon / Tool Wrapper / Report / Engine |
| **Status** | Phase 1: Plan |
| **Created** | {date} |
| **Last Updated** | {date} |
| **Last Command** | /work |
| **Next Step** | Human review spec, then run `/design` |
| **Blocked** | No |
| **Forge Ticket** | #{number} |
| **Forge Ticket ID** | {uuid} |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS | FAIL | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

### Module Spec
- **Name:** {ModuleName}
- **Category:** scanner | recon | tools | report | engine
- **Location:** `src/{category}/{module_name}.rs`
- **Trait:** ScanModule (for scanner/recon) | custom
- **Purpose:** {what this module does}
- **Dependencies:** {crates, other modules}
- **Acceptance Criteria:**
  - {criterion 1}
  - {criterion 2}
  - {criterion 3}

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | {OK/FAIL} |
| Toolchain | {OK/FAIL} |
| Hooks wired | {OK/FAIL} |

---

## Phase 2: Design
**Command:** /design
**Status:** PASS | FAIL | BLOCKED | Not Started

### Architecture
**Approach:** {description}

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | {path} | Create | {what it does} |

**Type Design:** {structs, enums, trait impls}

**Error Handling:** {error types, propagation}

**Testing Strategy:** {what to test}

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | {test_name} | {path} | {what} |

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS | FAIL | Not Started

### Files Created / Modified
{list}

### Quality Gates
- **cargo fmt:** {result}
- **cargo clippy:** {result}
- **cargo test:** {result — count}

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS | FAIL | Not Started

### Entry Verification
{independently run quality gates}

### Code Review
{checklist results}

### Test Results
{counts}

---

## Phase 5: Register
**Command:** /implement (registration step)
**Status:** PASS | FAIL | Not Started

- Module registered in `register_modules()`
- Module accessible via CLI `--modules` flag
- Module docs created in `docs/modules/` or `docs/tools/`

---

## Phase 6: Re-Validate
**Command:** /validate
**Status:** PASS | FAIL | Not Started

### Full Quality Gates (after registration)
- **cargo fmt:** {result}
- **cargo clippy:** {result}
- **cargo test:** {result — full count}

---

## Phase 7: Verify
**Command:** /verify
**Status:** PASS | FAIL | Not Started

### Full Suite
- **Cargo Test Count:** {N}
- **Regressions:** {none or list}

---

## Phase 8: Complete
**Command:** /complete
**Status:** PASS | Not Started

- **Documentation Updated:** {list}
- **Changelog Updated:** Yes | No
- **Pipeline Archived:** Yes | No

### Self-Reflection
{answers}

### After-Action Review
- **Generation Trace Saved:** Yes | No
- **Lessons/Failures Recorded:** {counts}
