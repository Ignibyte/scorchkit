# Work Pipeline: HTTP Request Smuggling Scanner

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
- **Title:** HTTP Request Smuggling Scanner (CL.TE / TE.CL / TE.TE)
- **Type:** Feature
- **Scope:** New scanner module detecting HTTP request smuggling vulnerabilities. Tests Content-Length vs Transfer-Encoding desync between front-end and back-end servers. Covers CL.TE, TE.CL, and TE.TE (obfuscation) variants. Uses timing-based detection and differential response analysis.
- **Files Expected:** 2-3 files — `src/scanner/smuggling.rs` (main module), modify `src/scanner/mod.rs`, tests
- **Dependencies:** None — follows standard ScanModule trait pattern. Requires raw-ish HTTP (may need hyper or manual TCP for some tests since reqwest normalizes headers).
- **Risks:** Medium. reqwest may normalize Transfer-Encoding headers, limiting detection capability. May need raw HTTP for accurate CL.TE/TE.CL probes. Detection is timing-sensitive — false positives possible.
- **Acceptance Criteria:**
  - Implements `ScanModule` trait
  - Tests CL.TE desync: conflicting Content-Length and Transfer-Encoding headers
  - Tests TE.CL desync: reversed priority detection
  - Tests TE.TE obfuscation: `Transfer-Encoding: chunked` with whitespace/case variants
  - Uses timing differential to confirm smuggling (delayed response = desync)
  - Generates findings with severity Critical, CWE-444 (HTTP Request Smuggling)
  - OWASP A05:2021 Security Misconfiguration
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
