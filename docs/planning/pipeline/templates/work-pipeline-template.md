# Work Pipeline: {Title}

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature / Integration / Infrastructure / Refactor |
| **Status** | Phase 1: Plan |
| **Created** | {date} |
| **Last Updated** | {date} |
| **Last Command** | /work |
| **Next Step** | Human review spec, then run `/design` |
| **Blocked** | No |
| **Forge Ticket** | #{number} |
| **Forge Ticket ID** | {uuid from ticket-create response} |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS | FAIL | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

### Work Spec
- **Title:** {descriptive title}
- **Type:** Feature | Integration | Infrastructure | Refactor
- **Scope:** {1-2 sentence summary of what this work accomplishes}
- **Files Expected:** {estimated count and locations}
- **Dependencies:** {what this depends on}
- **Risks:** {what could go wrong, or "Low risk"}
- **Acceptance Criteria:**
  - {criterion 1}
  - {criterion 2}
  - {criterion 3}

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | {OK/FAIL} |
| Toolchain | {OK/FAIL} |
| Security tools | {OK/WARN — list missing} |
| Hooks wired | {OK/FAIL — N/8} |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- {from recall — list applicable pitfalls, or "None found"}

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
**Status:** PASS | FAIL | BLOCKED | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

### Architecture

**Approach:**
- {high-level description of the solution approach}

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | {path} | Create / Modify | {what it does} |

**Testing Strategy:**
- {what tests to write, what to cover, edge cases}

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | {test_name} | {path} | {what it verifies} |

**Architectural Decisions:**
- {any deviations from standard patterns, with justification}

### Deferred Items
- {anything that couldn't be decided — if present, Status MUST be BLOCKED}

### Issues Found
- {any concerns or risks}

### Knowledge Recorded
- **Lessons:** {count}
- **Failures:** {count}
- **Component Types:** {list}

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS | FAIL | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

### Files Created
| File | Path |
|------|------|
| {description} | {path} |

### Files Modified
| File | Change |
|------|--------|
| {path} | {what was changed} |

### Quality Gates
- **cargo fmt --check:** Pass | Fail
- **cargo clippy:** Pass | Fail — {warning count}
- **cargo test:** Pass | Fail — {test count}

### Notes
- {any deviations from design, or "Followed design exactly"}

### Knowledge Recorded
- **Lessons:** {count}
- **Failures:** {count}
- **Component Types:** {list}

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS | FAIL | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

### Entry Verification (independently run)
- **cargo fmt --check:** {result}
- **cargo clippy:** {result}
- **cargo test:** {result — count}
- **```ignore check:** {result}
- **#[ignore] check:** {result}
- **#[allow] workaround check:** {result}

### Code Review
- **Standards Compliance:** Pass | Fail — {details}
- **Workaround Detection:** Pass | Fail — {details}
- **Security Review (semgrep):** Pass | Fail — {details}

### Test Results
- **Cargo Test Count:** {N passed, N failed}
- **Doctest Count:** {N passed, N failed}
- **Coverage:** {percentage or "not measured"}

### Regression Test Plan Compliance
- {Each test from Phase 2 plan: implemented / missing}

### Knowledge Recorded
- **Lessons:** {count}
- **Failures:** {count}
- **Component Types:** {list}

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS | FAIL | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

- **Cargo Test Full Suite:** Pass | Fail
- **Cargo Test Count:** {N passed, N failed}
- **Cargo Test Regressions:** {none or list — compare to Phase 4 count}
- **Integration Tests:** Pass | Fail — {count}

### Knowledge Recorded
- **Lessons:** {count}
- **Failures:** {count}
- **Component Types:** {list}

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS | Not Started
**Started:** {timestamp}
**Completed:** {timestamp}

- **Documentation Updated:** {list of docs updated, or "None needed"}
- **Changelog Updated:** Yes | No
- **Pipeline Doc Archived:** Yes | No — moved to `completed/`

### Self-Reflection
1. Did any phase use workarounds? {answer}
2. Was the implementation the cleanest version? {answer}
3. Would a senior developer approve? {answer}

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes | No
- **Lessons Recorded:** {count}
- **Failures Recorded:** {count}
- **Component Types Tagged:** {aggregated list}
