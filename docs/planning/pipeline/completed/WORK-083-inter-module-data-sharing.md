# Work Pipeline: Inter-Module Data Sharing

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
| **Forge Ticket** | #82 |
| **Forge Ticket ID** | 019d594e-981f-72fb-907b-d8fc54302dd7 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-03
**Completed:** 2026-04-03

### Work Spec
- **Title:** Inter-Module Data Sharing (Scan Context Enrichment)
- **Type:** Feature
- **Scope:** Enable modules to share discovered data with downstream modules via an enriched `ScanContext`. Crawler-discovered URLs feed into injection/XSS/SSRF scanners. Tech detection results inform which scanner payloads to use. Subdomain discoveries feed into further scanning. Uses a typed data store in ScanContext with publish/subscribe semantics.
- **Files Expected:** 4-6 files — modify `src/engine/target.rs` or new `src/engine/shared_data.rs` (shared data store), modify `src/runner/orchestrator.rs` (pass results between phases), modify consumer modules to read shared data, tests
- **Dependencies:** None — extends existing ScanContext
- **Risks:** Medium. Concurrency concerns — shared data must be thread-safe (Arc<RwLock> or DashMap). Module execution ordering becomes important (recon before scanners). Must not break existing module independence.
- **Acceptance Criteria:**
  - `ScanContext` gains a typed shared data store
  - Modules can publish: discovered URLs, form endpoints, parameters, technologies, subdomains
  - Modules can subscribe: injection scanner reads crawler URLs, XSS scanner reads form endpoints
  - Thread-safe implementation (concurrent module execution preserved)
  - Orchestrator runs recon phase before scanner phase to populate shared data
  - Existing modules work unchanged if shared data is empty (backwards compatible)
  - Crawler module publishes discovered URLs and forms
  - Tech module publishes detected technologies
  - At least one scanner module (injection or XSS) consumes shared data
  - All existing tests pass, new data sharing has unit tests
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
