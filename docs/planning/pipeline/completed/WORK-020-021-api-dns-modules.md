# Work Pipeline: REST API Security + DNS/Email Security Modules

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
| **Forge Ticket** | #20 + #21 (merged pipeline) |
| **Forge Ticket ID** | 019d3a84-26cc-7313-9f56-3fb373d5e52e (API), 019d3a84-32e4-72d6-9a10-341cf85b0c02 (DNS) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** REST API security testing + DNS/email security modules
- **Type:** Feature
- **Scope:** Two new built-in modules in one pipeline:
  1. `scanner/api.rs` — REST API security testing based on OWASP API Top 10. Tests: broken object-level authorization (BOLA via sequential IDs on common API paths), mass assignment (POST with extra fields), excessive data exposure (response contains sensitive field names like password/ssn/secret), rate limiting absence on auth endpoints, security misconfiguration (CORS on API, missing auth headers), and injection via API parameters.
  2. `recon/dns.rs` — DNS and email security reconnaissance. Tests: SPF record presence and permissiveness, DMARC record presence and policy, DKIM selector probing, DNSSEC validation, MX record analysis, and zone transfer attempt. Uses HTTP-based DNS resolution via public DNS-over-HTTPS APIs (Cloudflare/Google) — no DNS crate needed.
- **Files Expected:** ~4 files (2 new modules `scanner/api.rs` + `recon/dns.rs`, modifications to `scanner/mod.rs` + `recon/mod.rs`)
- **Dependencies:** Existing `ScanContext` with `http_client`. No new crate deps. DNS module uses DoH (DNS-over-HTTPS) via reqwest — no DNS library needed.
- **Risks:**
  - API module overlap with existing injection/idor/graphql modules — must check boundaries
  - DNS-over-HTTPS rate limits from public resolvers (Google/Cloudflare)
  - SPF/DMARC parsing complexity — keep to presence + basic policy analysis
- **Acceptance Criteria:**
  - `ApiSecurityModule` in `scanner/api.rs` implements `ScanModule` — tests BOLA, mass assignment, data exposure, rate limiting, API misconfig
  - `DnsSecurityModule` in `recon/dns.rs` implements `ScanModule` — tests SPF, DMARC, DNSSEC, MX, zone transfer
  - Boundary with existing modules clear (api.rs = API-specific OWASP Top 10, not generic injection)
  - Pure functions for response analysis and DNS record parsing
  - Unit tests for API response analysis and DNS record parsing
  - `cargo test` passes with no regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 127 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap (injection, idor, graphql already exist)

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
Two new modules:

**Module 1: `scanner/api.rs` — REST API Security (OWASP API Top 10)**

Tests API-specific vulnerabilities distinct from existing modules. Boundary: `acl.rs` owns BOLA/forced browsing. `injection.rs` owns generic SQL/cmd injection. `api.rs` owns API-specific OWASP items:

| # | Test | OWASP API | Technique | Severity | CWE |
|---|------|-----------|-----------|----------|-----|
| 1 | Mass assignment | API6 | POST to common API paths with extra fields (`admin`, `role`, `is_staff`) | Medium | 915 |
| 2 | Excessive data exposure | API3 | GET API endpoints, check response for sensitive field names (`password`, `ssn`, `secret`, `token`, `credit_card`) | Medium | 213 |
| 3 | Shadow API discovery | API9 | Probe versioned API paths (`/api/v1/`, `/api/v2/`, `/api/v3/`, `/api/internal/`) | Low | 912 |
| 4 | API rate limiting | API4 | Rapid-fire 10 requests to `/api/login` or `/api/auth`, check for 429 response | Medium | 770 |
| 5 | Improper content negotiation | API8 | Send request with `Accept: application/xml` to JSON API, check if server returns XML (content type confusion) | Low | 436 |

**Module 2: `recon/dns.rs` — DNS & Email Security**

Uses DNS-over-HTTPS (DoH) via Cloudflare's `https://cloudflare-dns.com/dns-query` with `application/dns-json` — standard DoH JSON API, no DNS crate needed. Category: Recon (information gathering, not exploitation).

| # | Test | Technique | Severity | CWE |
|---|------|-----------|----------|-----|
| 1 | SPF record | DoH TXT query, parse `v=spf1`, check for `+all` (too permissive) | Medium | 290 |
| 2 | DMARC record | DoH TXT query for `_dmarc.{domain}`, check for `p=none` (no enforcement) | Medium | 290 |
| 3 | MX record presence | DoH MX query, report MX hosts found | Info | — |
| 4 | DNSSEC status | DoH query with `do=1` (DNSSEC OK), check `AD` flag in response | Low | 350 |
| 5 | Zone transfer attempt | HTTP-based AXFR probe (not actual DNS — check if common DNS management paths are exposed) | Medium | 200 |

**Key Design Decisions:**

- **DoH via Cloudflare JSON API** — `GET https://cloudflare-dns.com/dns-query?name={domain}&type=TXT` with `Accept: application/dns-json`. Returns JSON, parseable with `serde_json::Value`. No DNS crate needed. Alternative: Google `https://dns.google/resolve?name={domain}&type=TXT`.
- **API module does NOT test BOLA** — `acl.rs` already tests forced browsing on `/api/users/{id}`. API module focuses on mass assignment, data exposure, shadow APIs, rate limiting, content negotiation.
- **DNS module is Recon category** — information gathering, not exploitation. Goes in `recon/` not `scanner/`.
- **Pure functions for record parsing** — `parse_spf()`, `parse_dmarc()`, `has_sensitive_fields()` — all testable without HTTP/DNS.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/api.rs` | Create | `ApiSecurityModule` — OWASP API Top 10 tests |
| 2 | `src/recon/dns.rs` | Create | `DnsSecurityModule` — SPF/DMARC/DNSSEC/MX via DoH |
| 3 | `src/scanner/mod.rs` | Modify | Add `mod api;` and register |
| 4 | `src/recon/mod.rs` | Modify | Add `mod dns;` and register |

**Type and Trait Changes:**
No new public types. Internal: `DohResponse`, `DnsAnswer` for DoH JSON parsing. Pure functions for SPF/DMARC analysis.

**Error Handling:** Existing `ScorchError::Http` for request failures. DoH errors → skip gracefully.

**Testing Strategy:**
- API tests: `has_sensitive_fields()` detection, shadow API path generation, mass assignment field list
- DNS tests: `parse_spf()` permissiveness detection, `parse_dmarc()` policy analysis, DoH response parsing
- No live DNS/API integration tests

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 127+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_has_sensitive_fields` | `src/scanner/api.rs` | Detects password/ssn/secret/token in JSON |
| 4 | `test_shadow_api_paths` | `src/scanner/api.rs` | Versioned API path generation |
| 5 | `test_mass_assignment_fields` | `src/scanner/api.rs` | Extra field list completeness |
| 6 | `test_parse_spf` | `src/recon/dns.rs` | SPF permissiveness detection (+all, ~all, -all) |
| 7 | `test_parse_dmarc` | `src/recon/dns.rs` | DMARC policy analysis (none/quarantine/reject) |
| 8 | `test_doh_response_parsing` | `src/recon/dns.rs` | Cloudflare DoH JSON structure |
| 9 | `test_modules_list` | `tests/cli.rs` | api-security + dns-security in listing |

### Deferred Items
- BFLA (broken function-level auth) — requires multi-credential AuthConfig
- SSRF via API parameters — handled by existing ssrf.rs + interactsh OOB
- DKIM selector probing — would need a list of common selectors

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** scanner, recon

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
- Files created: `src/scanner/api.rs`, `src/recon/dns.rs`
- Files modified: `src/scanner/mod.rs`, `src/recon/mod.rs`
- Quality: fmt clean, clippy clean, 133 default tests (+6)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
- MCP: 230 passed (was 224, +6). Semgrep clean.

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
- Phase 4→5 mcp 230→230, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS

### Self-Reflection
1. **Workarounds:** None.
2. **Cleanest version:** Yes — DoH via reqwest (no DNS crate), pure SPF/DMARC parsers, clear API/ACL/injection boundary.
3. **Senior Rust approval:** Yes — no unwrap in library, iterators, proper error propagation.

### CHANGELOG: v0.20.0
### Knowledge: save-generation-trace + learn recorded
