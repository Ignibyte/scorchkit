# Work Pipeline: Subdomain Takeover Detection + Access Control Testing Modules

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
| **Forge Ticket** | #18 + #19 (merged pipeline) |
| **Forge Ticket ID** | 019d3a83-c8e3-73e8-9a56-800340cc3b57 (Subdomain), 019d3a83-d5a0-7228-aee9-b498a630b3dd (ACL) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Subdomain takeover detection + access control testing modules
- **Type:** Feature
- **Scope:** Two new built-in scanner modules in one pipeline:
  1. `scanner/subtakeover.rs` — Detects subdomain takeover vulnerabilities by checking CNAME records pointing to unclaimed cloud services (S3, Azure, GitHub Pages, Heroku, etc.). Fetches the subdomain and checks for known takeover fingerprints in the response (404 pages with specific provider error messages).
  2. `scanner/acl.rs` — Tests access control by probing for common authorization bypass patterns: HTTP method override (X-HTTP-Method-Override), path traversal to admin endpoints, HTTP verb tampering (GET vs POST on restricted endpoints), forced browsing to predictable resource IDs, and role-based endpoint discovery.
- **Files Expected:** ~3 files (2 new scanner modules, 1 mod.rs modification)
- **Dependencies:** Existing `ScanContext` with `http_client`. No new crate deps.
- **Risks:**
  - Subdomain takeover: needs target's CNAME records — uses HTTP approach (fetch subdomain, check response for takeover fingerprints) rather than DNS resolution (which would need a DNS crate)
  - ACL testing: false positives on 200 responses that are actually public pages
  - Subdomain takeover fingerprints change over time — need to maintain the fingerprint list
- **Acceptance Criteria:**
  - `SubdomainTakeoverModule` in `scanner/subtakeover.rs` implements `ScanModule`
  - `AclModule` in `scanner/acl.rs` implements `ScanModule`
  - Subtakeover: checks known cloud provider fingerprints in response bodies
  - ACL: tests method override, verb tampering, forced browsing, admin path probing
  - Pure functions for fingerprint matching and ACL test generation
  - Unit tests for fingerprint detection, path generation, method override detection
  - `cargo test` passes with no regressions
  - Registered as 28th and 29th built-in scanner modules

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 112 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap
- Merged pipelines work well for related modules (lesson from CORS+CSP)

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
Two new built-in scanner modules:

**Module 1: `scanner/subtakeover.rs` — Subdomain Takeover Detection**

HTTP-based approach: construct common subdomain URLs from the target domain, fetch them, and check response bodies against known cloud provider "unclaimed" fingerprints. No DNS resolution crate needed — the HTTP client handles DNS internally when fetching.

Discovery: generate common subdomain prefixes (`www`, `mail`, `admin`, `staging`, `dev`, `api`, `cdn`, `assets`, `blog`, `docs`, `app`, `test`, `beta`, `old`, `new`) prepended to the target domain. For each, make an HTTP GET request and check the response against a fingerprint database.

| # | Provider | Fingerprint (body contains) | Severity |
|---|----------|---------------------------|----------|
| 1 | GitHub Pages | "There isn't a GitHub Pages site here" | High |
| 2 | Heroku | "No such app" or "herokucdn.com/error-pages" | High |
| 3 | AWS S3 | "NoSuchBucket" or "The specified bucket does not exist" | Critical |
| 4 | Azure | "404 Web Site not found" and ".azurewebsites.net" | High |
| 5 | Shopify | "Sorry, this shop is currently unavailable" | Medium |
| 6 | Fastly | "Fastly error: unknown domain" | High |
| 7 | Pantheon | "404 error unknown site" | Medium |
| 8 | Tumblr | "There's nothing here" and "tumblr.com" | Medium |

**Module 2: `scanner/acl.rs` — Access Control Testing**

Probes for common authorization bypass patterns against the target:

| # | Test | Technique | Severity | CWE |
|---|------|-----------|----------|-----|
| 1 | Admin path discovery | Probe `/admin`, `/dashboard`, `/management`, `/config`, `/internal` | Medium | 425 |
| 2 | Method override bypass | Send `GET` with `X-HTTP-Method-Override: DELETE` | High | 650 |
| 3 | HTTP verb tampering | Send `PUT`/`PATCH` to endpoints that only check `POST` | Medium | 650 |
| 4 | Path traversal bypass | `//admin`, `/./admin`, `/%2e/admin` to bypass path-based auth | High | 22 |
| 5 | Forced browsing | Probe sequential IDs (`/api/users/1`, `/api/users/2`) | Medium | 425 |

**Key Design Decisions:**

- **HTTP-only subdomain detection** — No DNS crate needed. HTTP GET to `http://{subdomain}.{domain}` — if response contains takeover fingerprint, it's vulnerable. False positives are unlikely because fingerprints are provider-specific error pages.
- **Limited subdomain list** — Uses 15 common prefixes rather than full enumeration (which is the job of the existing `subdomain` recon module + subfinder/amass tool wrappers). This module checks for takeover on likely subdomains; full enumeration feeds into it via the scan pipeline.
- **ACL tests are non-destructive** — All probes use GET/HEAD or send override headers without actual mutations. The module discovers access control gaps without modifying data.
- **Pure functions for fingerprints and path generation** — testable without HTTP.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/subtakeover.rs` | Create | `SubdomainTakeoverModule` — subdomain probing + provider fingerprint matching |
| 2 | `src/scanner/acl.rs` | Create | `AclModule` — admin path discovery, method override, verb tampering, path traversal bypass, forced browsing |
| 3 | `src/scanner/mod.rs` | Modify | Add `mod subtakeover;` + `mod acl;` and register both |

**Type and Trait Changes:**

Internal types:
- `TakeoverFingerprint` — struct with `provider`, `fingerprints` (Vec of body patterns), `severity`
- Pure functions: `generate_subdomains()`, `takeover_fingerprints()`, `check_fingerprint()`, `generate_admin_paths()`, `generate_acl_bypass_paths()`

No public types. No trait changes.

**Error Handling Strategy:**
- HTTP failures → skip subdomain/path gracefully (connection refused = subdomain doesn't exist)
- No new error variants

**Testing Strategy:**
- **Subtakeover tests:**
  - `check_fingerprint()` against known provider responses
  - `generate_subdomains()` produces expected prefixes
  - Fingerprint database completeness
- **ACL tests:**
  - `generate_admin_paths()` produces expected paths
  - `generate_acl_bypass_paths()` produces bypass variants
  - Method override header list

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 112+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_check_fingerprint` | `src/scanner/subtakeover.rs` | Matches known provider error pages |
| 4 | `test_generate_subdomains` | `src/scanner/subtakeover.rs` | Expected subdomain prefixes |
| 5 | `test_fingerprint_database` | `src/scanner/subtakeover.rs` | All providers have non-empty fingerprints |
| 6 | `test_no_false_positive` | `src/scanner/subtakeover.rs` | Normal 200/404 pages don't match |
| 7 | `test_generate_admin_paths` | `src/scanner/acl.rs` | Expected admin paths |
| 8 | `test_generate_bypass_paths` | `src/scanner/acl.rs` | Path traversal bypass variants |
| 9 | `test_method_override_headers` | `src/scanner/acl.rs` | Override header list completeness |
| 10 | `test_modules_list` | `tests/cli.rs` | subtakeover + acl appear in listing |

### Deferred Items
- Full subdomain enumeration (existing recon/subdomain.rs + amass/subfinder wrappers handle this)
- DNS CNAME resolution for precise dangling record detection (would need a DNS crate)
- Horizontal privilege escalation (requires multi-credential AuthConfig)

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
- Files created: `src/scanner/subtakeover.rs`, `src/scanner/acl.rs`
- Files modified: `src/scanner/mod.rs`
- Quality: fmt clean, clippy clean (0 warnings), 119 default tests (+7)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
- MCP: 216 passed (was 209, +7). Semgrep clean. 10/10 regression plan passing.

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
- Phase 4→5 mcp 216→216, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS

### Self-Reflection
1. **Workarounds:** None.
2. **Cleanest version:** Yes — pure fingerprint matching, non-destructive ACL probes, clean separation.
3. **Senior Rust approval:** Yes — no unwrap/expect, `?` propagation, iterators throughout.

### CHANGELOG: v0.18.0
### Knowledge: save-generation-trace + learn recorded
