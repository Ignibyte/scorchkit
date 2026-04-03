# Work Pipeline: Certificate Transparency Recon Module

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
- **Title:** Certificate Transparency Log Subdomain Discovery
- **Type:** Feature
- **Scope:** New recon module that queries Certificate Transparency logs (crt.sh) to discover subdomains associated with the target domain. Supplements existing subdomain enumeration (subfinder/amass wrappers) with a built-in passive source.
- **Files Expected:** 2-3 files — `src/recon/cert_transparency.rs`, modify `src/recon/mod.rs`, tests
- **Dependencies:** None — uses crt.sh public API
- **Risks:** Low. Passive reconnaissance only — queries a public database. Rate limiting on crt.sh is the main concern.
- **Acceptance Criteria:**
  - Implements `ScanModule` trait (recon category)
  - Queries `https://crt.sh/?q=%25.{domain}&output=json` for subdomains
  - Deduplicates results and filters wildcards
  - Optionally resolves discovered subdomains to verify they're live
  - Generates informational findings for each discovered subdomain
  - Handles crt.sh rate limiting gracefully with retries
  - All existing tests pass, new module has unit tests
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
