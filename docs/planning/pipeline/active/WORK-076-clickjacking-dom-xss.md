# Work Pipeline: Clickjacking + DOM XSS Scanners

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
- **Title:** Clickjacking and DOM-based XSS Scanners
- **Type:** Feature
- **Scope:** Two new scanner modules. (1) Clickjacking: active test beyond header checks — verifies missing `X-Frame-Options` AND `Content-Security-Policy frame-ancestors` together, tests with actual iframe-ability indicators. (2) DOM XSS: static analysis of JavaScript in responses for dangerous source-to-sink flows (e.g., `location.hash` → `document.write`, `innerHTML`, `eval`).
- **Files Expected:** 4-5 files — `src/scanner/clickjacking.rs`, `src/scanner/dom_xss.rs`, modify `src/scanner/mod.rs`, tests
- **Dependencies:** None — follows standard ScanModule trait pattern
- **Risks:** Low for clickjacking. Medium for DOM XSS — static JS analysis without a JS engine is inherently limited; will produce best-effort results based on pattern matching of known source/sink pairs.
- **Acceptance Criteria:**
  - **Clickjacking module:**
    - Checks for missing X-Frame-Options header
    - Checks for missing CSP frame-ancestors directive
    - Only flags when BOTH protections are absent
    - Tests multiple pages, not just root
    - CWE-1021 (Clickjacking), severity Medium
    - OWASP A05:2021 Security Misconfiguration
  - **DOM XSS module:**
    - Extracts inline and external JavaScript from HTML responses
    - Identifies sources: `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `postMessage`
    - Identifies sinks: `document.write`, `innerHTML`, `outerHTML`, `eval`, `setTimeout(string)`, `Function()`
    - Flags source-to-sink data flows
    - CWE-79 (DOM XSS), severity High
    - OWASP A07:2021 XSS
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
