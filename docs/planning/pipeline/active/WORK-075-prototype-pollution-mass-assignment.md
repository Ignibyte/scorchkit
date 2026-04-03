# Work Pipeline: Prototype Pollution + Mass Assignment Scanners

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
- **Title:** Prototype Pollution and Mass Assignment Scanners
- **Type:** Feature
- **Scope:** Two new scanner modules. (1) Prototype pollution: detects client-side and server-side prototype pollution via `__proto__`, `constructor.prototype`, and `constructor` property injection in JSON bodies and query parameters. (2) Mass assignment: detects over-posting vulnerabilities by injecting extra privileged fields (`role`, `isAdmin`, `is_superuser`, `price`, `discount`) into POST/PUT/PATCH JSON bodies and checking if they persist.
- **Files Expected:** 4-5 files — `src/scanner/prototype_pollution.rs`, `src/scanner/mass_assignment.rs`, modify `src/scanner/mod.rs`, tests
- **Dependencies:** None — follows standard ScanModule trait pattern
- **Risks:** Low. Detection-only. Prototype pollution checks response for reflected polluted properties. Mass assignment checks subsequent GET for persisted fields.
- **Acceptance Criteria:**
  - **Prototype Pollution module:**
    - Tests `__proto__` injection in JSON body: `{"__proto__":{"polluted":true}}`
    - Tests `constructor.prototype` variants
    - Tests query param pollution: `?__proto__[polluted]=true`
    - Checks response body for evidence of pollution
    - CWE-1321 (Prototype Pollution), severity Medium
  - **Mass Assignment module:**
    - Tests extra field injection in POST/PUT/PATCH: `role`, `isAdmin`, `admin`, `is_staff`, `price`
    - Compares responses before/after injection to detect field acceptance
    - Tests JSON body and form-encoded body
    - CWE-915 (Mass Assignment), severity High
  - OWASP A08:2021 Software and Data Integrity for prototype pollution
  - OWASP A04:2021 Insecure Design for mass assignment
  - All existing tests pass, both modules have unit tests
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
