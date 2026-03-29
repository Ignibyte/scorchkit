# Work Pipeline: GraphQL Deep Security Testing Module

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
| **Forge Ticket** | #15 |
| **Forge Ticket ID** | 019d3a83-86fa-707f-917e-7918b4a55ea1 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** GraphQL deep security testing module
- **Type:** Feature
- **Scope:** New built-in scanner module (`scanner/graphql.rs`) that tests GraphQL endpoints for security vulnerabilities beyond schema discovery (which `api_schema` already does). Tests: introspection enabled, query depth/complexity abuse (deeply nested queries), query batching abuse, field suggestion information leaks, mutation enumeration, and DoS via resource-intensive queries. Uses existing `reqwest` HTTP client — all GraphQL operations are HTTP POST with JSON bodies. No new crate dependencies needed.
- **Files Expected:** ~2 files (1 new scanner module `scanner/graphql.rs`, modification to `scanner/mod.rs`)
- **Dependencies:** Existing `ScanContext` with `http_client`, `serde_json` for GraphQL request/response bodies. No new crate deps.
- **Risks:**
  - GraphQL endpoints at varying paths (/graphql, /api/graphql, /gql) — need to probe common paths
  - Introspection may be partially disabled (types available but not queries) — need robust detection
  - Depth/complexity limits vary — module tests for their absence, not specific thresholds
  - Boundary with api_schema: api_schema = Recon (discovers schema exposure), graphql = Scanner (tests security issues). Clear separation by module category.
- **Acceptance Criteria:**
  - `GraphQLModule` in `scanner/graphql.rs` implements `ScanModule`
  - Discovers GraphQL endpoints via common path probing
  - Tests: introspection enabled, query depth abuse, batching abuse, field suggestion leaks, mutation enumeration
  - Pure functions for query generation and response analysis
  - Graceful no-op when no GraphQL endpoints found
  - Unit tests for query generation, response parsing, endpoint detection
  - `cargo test` passes with no regressions
  - `cargo clippy` clean, `cargo fmt` clean
  - Registered as 25th built-in scanner module

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 92 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap (api_schema = Recon discovery, graphql = Scanner testing — clear boundary)

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
New built-in scanner module `scanner/graphql.rs` implementing `ScanModule`. Two-phase: discover GraphQL endpoints via common path probing + introspection query, then run security tests against confirmed endpoints. All GraphQL operations are HTTP POST with JSON bodies via the existing `reqwest` client — no new dependencies.

**Discovery Phase:**
Probe common paths (`/graphql`, `/api/graphql`, `/gql`, `/query`, `/v1/graphql`, `/graphql/v1`) with a simple introspection query `{ __typename }`. If the response contains `"data"` with a valid `__typename` → confirmed GraphQL endpoint.

**Security Tests:**
| # | Test | Query/Technique | Severity | CWE |
|---|------|----------------|----------|-----|
| 1 | Introspection enabled | Full introspection query `{ __schema { types { name } } }` | Medium | 200 |
| 2 | Query depth abuse | Deeply nested query (10+ levels) — tests for depth limiting | High | 770 |
| 3 | Batch query abuse | Array of 50 identical queries in one request `[{query},{query},...]` | Medium | 770 |
| 4 | Field suggestion leak | Intentionally misspelled field, check for "Did you mean" suggestions | Low | 200 |
| 5 | Mutation enumeration | Introspection filtered to mutation type — lists all mutations | Medium | 200 |
| 6 | `__type` info leak | Query `{ __type(name: "User") { fields { name } } }` for common types | Low | 200 |

**Key Design Decisions:**

- **Separate from api_schema** — api_schema is Recon (discovers schema exposure). GraphQL module is Scanner (actively tests security). Different categories, different concerns, zero overlap.
- **No new dependencies** — All GraphQL is HTTP POST with JSON. `serde_json::json!()` macro builds query bodies. Response analysis via `serde_json::Value` parsing.
- **Depth query generation as pure function** — Builds nested `{ field { field { ... } } }` strings programmatically. Configurable depth. Testable without HTTP.
- **Batch via JSON array** — GraphQL batching sends `[{query1}, {query2}, ...]` as the POST body. If the server returns a JSON array of results, batching is supported (and potentially abusable for DoS).
- **Field suggestion detection** — Send `{ __typenme }` (misspelled). If response contains "Did you mean" → server leaks field names via suggestions (information disclosure).

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/graphql.rs` | Create | `GraphQLModule` — endpoint discovery + 6 security tests |
| 2 | `src/scanner/mod.rs` | Modify | Add `mod graphql;` and register `GraphQLModule` |

**Type and Trait Changes:**

Internal types in `graphql.rs`:
- `GqlEndpoint` — struct with `url: String`, `path: String`
- Pure functions: `generate_gql_paths()`, `build_depth_query()`, `build_batch_payload()`, `is_graphql_response()`, `has_field_suggestions()`

No trait changes. No new public types.

**Error Handling Strategy:**
- `ScorchError::Http` for request failures (existing, `?` propagation)
- Failed GraphQL requests → skip gracefully (endpoint may reject specific queries)
- JSON parse failures on responses → skip (not a valid GraphQL response)
- No new error variants

**Testing Strategy:**
- Unit tests in `scanner/graphql.rs` (`#[cfg(test)] mod tests`):
  - `build_depth_query()` produces correctly nested structure at various depths
  - `build_batch_payload()` produces valid JSON array
  - `is_graphql_response()` detects GraphQL vs non-GraphQL JSON
  - `has_field_suggestions()` detects "Did you mean" patterns
  - `generate_gql_paths()` covers all expected paths
  - Introspection response analysis
- No live integration tests

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 92+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_build_depth_query` | `src/scanner/graphql.rs` | Nested query at depth 5, 10, 1 |
| 4 | `test_build_batch_payload` | `src/scanner/graphql.rs` | Valid JSON array of N queries |
| 5 | `test_is_graphql_response` | `src/scanner/graphql.rs` | Detects GraphQL vs non-GQL JSON |
| 6 | `test_has_field_suggestions` | `src/scanner/graphql.rs` | "Did you mean" detection |
| 7 | `test_generate_gql_paths` | `src/scanner/graphql.rs` | Expected paths present |
| 8 | `test_introspection_response` | `src/scanner/graphql.rs` | Detects introspection data in response |
| 9 | `test_modules_list` | `tests/cli.rs` | graphql appears in module listing |

**Architectural Decisions:**
- **Scanner category, not Recon** — This module actively probes for vulnerabilities (depth abuse, batching DoS), not just discovers schema. Distinct from api_schema (Recon).
- **No graphql-client crate** — GraphQL queries are simple strings. Adding a typed GraphQL client would be massive overkill for sending 6 test queries. `serde_json::json!()` + string building is sufficient.

### Deferred Items
- Subscription abuse testing (requires WebSocket — could integrate with websocket module)
- Authorization bypass via nested queries (requires auth config + knowledge of schema)
- Custom scalar injection testing

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
| GraphQL security scanner | `src/scanner/graphql.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/scanner/mod.rs` | Added `mod graphql;` and registered `GraphQLModule` |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from graphql.rs
- **cargo test:** Pass — 100 passed, 0 failed (was 92, +8 new GraphQL unit tests)

### Notes
- Followed design exactly — 6 security tests, pure functions for query building and response analysis
- No new crate dependencies — all GraphQL via HTTP POST + serde_json
- 8 unit tests: depth query, batch payload, GQL response detection, field suggestions, path generation, introspection data, batch empty, depth high

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
- All checks pass: fmt, clippy (0 warnings in graphql.rs), tests (100 default), semgrep clean
- MCP: 197 passed (was 189, +8)
- Regression plan: 9/9 passing

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
- Phase 4→5 mcp 197→197, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS

### Self-Reflection
1. **Workarounds:** None.
2. **Cleanest version:** Yes — pure query builders, no new deps, clear api_schema boundary.
3. **Senior Rust approval:** Yes — no unwrap/expect, JSON pointer for nested access, map_or for defaults.

### CHANGELOG: v0.16.0
### Knowledge: save-generation-trace + learn recorded
