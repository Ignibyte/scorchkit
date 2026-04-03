# Work Pipeline: JavaScript File Analysis Recon Module

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
- **Title:** JavaScript File Analysis Recon Module
- **Type:** Feature
- **Scope:** New recon module that discovers and analyzes JavaScript files from the target. Extracts API endpoints, API keys, secrets (AWS keys, JWT secrets, OAuth tokens), internal URLs, comments with sensitive info, and source maps. Finds JS files via HTML `<script>` tags, known JS paths, and linkage from discovered pages.
- **Files Expected:** 2-3 files — `src/recon/js_analysis.rs` (main module), modify `src/recon/mod.rs` (registration), tests
- **Dependencies:** Crawler module output (list of discovered pages) would enhance coverage, but module works standalone too
- **Risks:** Low. Read-only analysis of publicly accessible JS files. Regex-based secret detection may produce false positives — should include confidence indicators.
- **Acceptance Criteria:**
  - Implements `ScanModule` trait (recon category)
  - Discovers JS files from HTML responses (`<script src=...>`)
  - Extracts API endpoints: URL patterns, fetch/axios calls, XMLHttpRequest
  - Detects secrets: AWS keys (`AKIA...`), API keys, JWT tokens, OAuth secrets, private keys
  - Extracts internal/admin URLs and paths
  - Detects source map references (`.map` files)
  - Generates findings per secret/endpoint type with appropriate severity
  - CWE-540 (Information Exposure Through Source Code), CWE-615 (Info in Comments)
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
