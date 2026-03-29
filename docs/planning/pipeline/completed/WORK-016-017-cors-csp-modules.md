# Work Pipeline: CORS Deep Analysis + CSP Bypass Detection Modules

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /implement |
| **Next Step** | Run `/validate` for Phase 4 |
| **Blocked** | No |
| **Forge Ticket** | #16 + #17 (merged pipeline) |
| **Forge Ticket ID** | 019d3a83-aeaa-7026-b5a3-eceb73640c9a (CORS), 019d3a83-bbaa-72f0-aa71-568944cb39d3 (CSP) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** CORS deep analysis + CSP bypass detection modules
- **Type:** Feature
- **Scope:** Two new built-in scanner modules in one pipeline: `scanner/cors.rs` (deep CORS policy analysis) and `scanner/csp.rs` (CSP bypass detection). Both analyze HTTP security policy headers — complementary to existing checks in `misconfig.rs` (basic CORS origin reflection) and `recon/headers.rs` (CSP presence + unsafe-inline/eval). These go deeper: CORS tests preflight caching, method/header allowlists, subdomain wildcards, credential policies. CSP tests bypass-prone directives, missing critical directives (base-uri, object-src, frame-ancestors), nonce misuse, allowed CDN bypass paths, report-uri information leaks. No new dependencies — both use existing reqwest for HTTP requests and string parsing for header analysis.
- **Files Expected:** ~3 files (2 new scanner modules `scanner/cors.rs` + `scanner/csp.rs`, modification to `scanner/mod.rs`)
- **Dependencies:** Existing `ScanContext` with `http_client`, existing `ScanModule` trait. No new crate deps.
- **Risks:**
  - Boundary with misconfig.rs (CORS) and headers.rs (CSP) — must be clearly defined: existing modules = basic presence/reflection checks, new modules = deep policy analysis and bypass detection
  - CSP parsing complexity — directives have many variations (nonce, hash, host-source, keyword-source)
  - False positives on CSP — some "unsafe" patterns are intentional (e.g., Google Maps requires unsafe-eval)
- **Acceptance Criteria:**
  - `CorsModule` in `scanner/cors.rs` implements `ScanModule` — tests preflight cache, method allowlist, credential policy, subdomain patterns
  - `CspModule` in `scanner/csp.rs` implements `ScanModule` — tests bypass-prone directives, missing critical directives, nonce analysis, CDN bypass risk
  - Boundary with misconfig/headers clearly maintained (no overlap)
  - Pure functions for CORS policy parsing and CSP directive analysis
  - Unit tests for policy parsing and bypass detection logic
  - `cargo test` passes with no regressions
  - `cargo clippy` clean, `cargo fmt` clean
  - Registered as 26th and 27th built-in scanner modules

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 100 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap (misconfig.rs has basic CORS, headers.rs has basic CSP)

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
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Architecture

**Approach:**
Two new built-in scanner modules in one pipeline, both analyzing HTTP security policy headers:

**Module 1: `scanner/cors.rs` — CORS Deep Analysis**

Complements `misconfig.rs` which tests: origin reflection, wildcard+credentials, null origin. This module goes deeper with tests the misconfig module does NOT cover:

| # | Test | What it checks | Severity | CWE |
|---|------|---------------|----------|-----|
| 1 | Subdomain wildcard | Origin `https://evil.target.com` reflected → subdomain trust bypass | High | 942 |
| 2 | Preflight cache abuse | `Access-Control-Max-Age` > 2h → preflight caching attack window | Low | 525 |
| 3 | Method allowlist overly permissive | `Access-Control-Allow-Methods` includes PUT/DELETE/PATCH unnecessarily | Low | 942 |
| 4 | Header exposure | `Access-Control-Expose-Headers` leaks sensitive headers (Authorization, Set-Cookie, etc.) | Medium | 200 |
| 5 | Internal network origin | Origin `http://192.168.1.1` or `http://localhost` reflected → internal CORS bypass | High | 942 |

**Module 2: `scanner/csp.rs` — CSP Bypass Detection**

Complements `recon/headers.rs` which tests: CSP presence, `unsafe-inline`, `unsafe-eval`, wildcard. This module goes deeper with bypass-focused analysis:

| # | Test | What it checks | Severity | CWE |
|---|------|---------------|----------|-----|
| 1 | Missing `base-uri` | No `base-uri` directive → base tag injection for XSS bypass | Medium | 693 |
| 2 | Missing `object-src` | No `object-src` directive → Flash/plugin-based XSS bypass | Medium | 693 |
| 3 | Missing `frame-ancestors` | No `frame-ancestors` → clickjacking possible despite CSP | Medium | 1021 |
| 4 | Overly permissive `script-src` | Allows `data:`, `blob:`, or `https:` (any HTTPS) in script-src | High | 693 |
| 5 | `report-uri`/`report-to` info leak | Report endpoint URL reveals internal infrastructure | Low | 200 |
| 6 | `default-src` too permissive | `default-src *` or `default-src 'self' *` negates the policy | High | 693 |

**Key Design Decisions:**

- **Separate files, separate modules** — `cors.rs` and `csp.rs` are independent modules with own `ScanModule` implementations. Not combined into one file because they're distinct security domains with different test logic.
- **No overlap with existing modules** — misconfig.rs owns basic CORS (origin reflection, wildcard, null). headers.rs owns basic CSP (presence, unsafe-inline/eval, wildcard). New modules test deeper, bypass-focused scenarios only.
- **Pure functions for policy parsing** — CSP directive parsing (`parse_csp_directives()`) and CORS header analysis are pure functions, testable without HTTP.
- **No new dependencies** — both use existing reqwest for HTTP, string parsing for header values.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/cors.rs` | Create | `CorsModule` — deep CORS policy analysis (subdomain, preflight, methods, header exposure, internal origins) |
| 2 | `src/scanner/csp.rs` | Create | `CspModule` — CSP bypass detection (missing directives, permissive script-src, report leaks) |
| 3 | `src/scanner/mod.rs` | Modify | Add `mod cors;` + `mod csp;` and register both modules |

**Type and Trait Changes:**

Internal types in `csp.rs`:
- `CspDirectives` — `HashMap<String, Vec<String>>` parsed from CSP header value
- Pure functions: `parse_csp_directives()`, `has_directive()`, `directive_contains()`

Internal in `cors.rs`:
- Pure functions: `is_subdomain_of()`, `is_internal_origin()`

No public types. No trait changes.

**Error Handling Strategy:**
- `ScorchError::Http` for request failures (existing, `?` propagation)
- Missing headers → no findings (graceful, not an error)
- No new error variants

**Testing Strategy:**
- **CORS tests** (`scanner/cors.rs`):
  - `is_subdomain_of()` logic for various domain patterns
  - `is_internal_origin()` for RFC 1918 addresses, localhost, etc.
  - Preflight max-age threshold detection
  - Method allowlist analysis
- **CSP tests** (`scanner/csp.rs`):
  - `parse_csp_directives()` from realistic CSP header strings
  - Missing directive detection (base-uri, object-src, frame-ancestors)
  - Permissive script-src detection (data:, blob:, https:)
  - Report-uri info leak detection
  - Edge cases: empty CSP, malformed directives, multiple CSP headers

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 100+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_is_subdomain_of` | `src/scanner/cors.rs` | Subdomain matching logic |
| 4 | `test_is_internal_origin` | `src/scanner/cors.rs` | Internal IP/localhost detection |
| 5 | `test_preflight_max_age` | `src/scanner/cors.rs` | Max-Age threshold check |
| 6 | `test_parse_csp_directives` | `src/scanner/csp.rs` | CSP header parsing |
| 7 | `test_missing_directives` | `src/scanner/csp.rs` | Detects missing base-uri, object-src, frame-ancestors |
| 8 | `test_permissive_script_src` | `src/scanner/csp.rs` | data: blob: https: in script-src |
| 9 | `test_report_uri_detection` | `src/scanner/csp.rs` | Finds report-uri/report-to URLs |
| 10 | `test_csp_edge_cases` | `src/scanner/csp.rs` | Empty, malformed, multiple headers |
| 11 | `test_modules_list` | `tests/cli.rs` | cors + csp appear in module listing |

**Architectural Decisions:**
- **Two modules, one pipeline** — first merged pipeline in ScorchKit. Same domain (HTTP security headers), independent implementation, single commit.
- **Clear module ownership boundaries** — documented which checks live where to prevent future overlap creep.

### Deferred Items
- CDN bypass detection in CSP (checking if allowed domains host JSONP/open redirect) — requires maintaining a CDN bypass database
- CORS preflight request analysis (sending actual OPTIONS request) — more invasive, deferred

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** scanner

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Files Created
| File | Path |
|------|------|
| CORS deep analysis scanner | `src/scanner/cors.rs` |
| CSP bypass detection scanner | `src/scanner/csp.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/scanner/mod.rs` | Added `mod cors;` + `mod csp;` and registered `CorsModule` + `CspModule` |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from cors.rs/csp.rs
- **cargo test:** Pass — 112 passed, 0 failed (was 100, +5 CORS + 7 CSP = 12 new)

### Notes
- First merged pipeline — two modules, one pipeline
- Moved `is_internal_origin()` to test module (only used in tests, not runtime)
- `#[allow(too_many_arguments)]` on `test_origin()` — all 9 args are distinct, required
- `#[allow(cast_precision_loss)]` on hours display calculation

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
- All checks pass: fmt, clippy (0 warnings), tests (112 default), semgrep clean
- MCP: 209 passed (was 197, +12)
- Regression plan: 11/11 passing

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
- Phase 4→5 mcp 209→209, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS

### Self-Reflection
1. **Workarounds:** #[allow(too_many_arguments)] on test_origin — justified, all 9 args distinct. #[allow(cast_precision_loss)] on hours display.
2. **Cleanest version:** Yes — clean boundaries with existing modules, pure parsing functions, HashMap<directive, Vec<source>> for CSP.
3. **Senior Rust approval:** Yes — no unwrap/expect in library code, `?` propagation, idiomatic iterators.

### CHANGELOG: v0.17.0
### Knowledge: save-generation-trace + learn recorded
