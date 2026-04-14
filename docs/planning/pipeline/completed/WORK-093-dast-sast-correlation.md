# Work Pipeline: DAST+SAST Cross-Domain Correlation Rules

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Quality gates |
| **Blocked** | No |
| **Forge Ticket** | #93 |
| **Forge Ticket ID** | 019d8c58-c12f-7058-a29f-e00163072dee |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec
- **Title:** DAST+SAST cross-domain correlation rules
- **Type:** Feature
- **Scope:** Add ~6 new cross-domain correlation rules to the existing `correlation_rules()` function in `src/mcp/prompts.rs`. Rules match DAST module findings with SAST module findings to identify compound attack chains that neither scan type alone would catch. Pure additive — extends existing rule system.
- **Files Expected:** ~2 (modify `src/mcp/prompts.rs` for rules, modify tests for new rule coverage)
- **Dependencies:** Existing `CorrelationRule` system, `correlate_attack_chains()`, `CorrelationFinding` type
- **Risks:**
  - Low — pure rule additions to an existing, tested system
  - Rules must correctly match SAST module_ids (semgrep, osv-scanner, gitleaks, bandit, gosec, checkov, grype, hadolint, eslint-security, phpstan, dep-audit)
- **Acceptance Criteria:**
  - ~6 new cross-domain correlation rules added
  - Rules cover: injection code+runtime, secrets code+exposure, vulnerable deps+exploit, IaC misconfig+runtime, auth weakness code+runtime
  - Each rule has trigger function, member filter, severity, narrative, and priority
  - Existing 6 DAST-only rules unchanged (backward compatible)
  - Tests verify new rules trigger on expected finding combinations
  - `cargo test` passes, `cargo clippy` clean

### Preflight Results
| Check | Status |
|-------|--------|
| All checks | OK (449 tests, hooks 8/8) |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- Re-read pipeline docs after context continuation
- AI scan planning has similar cross-module logic — reuse patterns

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context
2. **Recall** — `recall(agent, phase, component_types)` for targeted knowledge
3. **Learn** — `learn(summary, topic, component_types)` to record lessons
4. **Search** — `search-architecture-docs` before writing code

---

## Phase 2: Design
**Command:** /design
**Status:** Not Started

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started

## Phase 5: Verify
**Command:** /verify
**Status:** Not Started

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
