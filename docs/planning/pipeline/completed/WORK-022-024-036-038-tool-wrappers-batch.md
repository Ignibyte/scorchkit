# Work Pipeline: Tool Wrappers Batch (Trufflehog, Prowler, Trivy, DNSx, Gobuster, dnsrecon)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Complete |
| **Created** | 2026-03-30 |
| **Last Updated** | 2026-03-30 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #22 + #23 + #24 + #36 + #37 + #38 (merged pipeline) |
| **Forge Ticket ID** | 019d3a84-3f37-720f-bfee-8c320a0b69ad (#22), 019d3a84-4b91-723f-9c33-68ebf75ab39a (#23), 019d3a84-567c-7023-8ff9-3db648042e1a (#24), 019d3a85-5244-7397-aabb-204614b8ad09 (#36), 019d3a85-5ca1-701e-a25b-c9fbbc941558 (#37), 019d3a85-63d0-729a-bc78-58b14a33f41b (#38) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** Tool wrappers batch: Trufflehog, Prowler, Trivy, DNSx, Gobuster, dnsrecon
- **Type:** Feature
- **Scope:** Six new external tool wrappers implementing `ScanModule` trait, all following the established subprocess pattern (struct + `run_tool()` one-shot + parse output). Each wrapper lives in `src/tools/` and registers in `register_modules()`.
  1. **Trufflehog** (#22) — Secret scanning in git repos, config files, filesystem. JSON output. Scanner category.
  2. **Prowler** (#23) — AWS/cloud misconfiguration scanning. JSON output. Scanner category.
  3. **Trivy** (#24) — Container image and dependency vulnerability scanning. JSON output. Scanner category.
  4. **DNSx** (#36) — Fast DNS resolution, wildcard detection, record type queries. Plain text output. Recon category.
  5. **Gobuster** (#37) — Directory and vhost brute-forcing. Plain text output. Recon category.
  6. **dnsrecon** (#38) — DNS enumeration: zone transfers, brute-force, reverse lookups. JSON output. Recon category.
- **Files Expected:** ~7 files (6 new tool wrappers in `src/tools/` + modify `src/tools/mod.rs` for registration)
- **Dependencies:** Existing `ScanModule` trait, `subprocess::run_tool()`, `Finding` builder, `register_modules()`
- **Risks:**
  - Largest batch pipeline yet (6 wrappers) — but all follow identical pattern
  - Some tools output JSON (trufflehog, prowler, trivy, dnsrecon), others plain text (dnsx, gobuster)
  - Cloud tools (prowler) may need specific auth/config not available in standard scan context
- **Acceptance Criteria:**
  - Six new `ScanModule` implementations in `src/tools/`
  - All registered in `register_modules()` with `requires_external_tool = true`
  - Pure parse functions for each output format, testable without tools installed
  - Unit tests for output parsing + empty output handling (2+ tests each)
  - `cargo test` passes with no regressions
  - Module count increases from 56 to 62 (31 built-in + 31 wrappers)

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 139 default passed |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Clippy may catch unnecessary Result wrapping on parse functions (learned from #32-35 batch)
- Consolidated findings pattern (one finding per tool with count + samples) avoids flooding

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
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Architecture

**Approach:**
Six tool wrappers following the identical established pattern: unit struct + `ScanModule` trait impl + `subprocess::run_tool()` one-shot + pure parse function returning `Vec<Finding>`. Each wrapper in its own file in `src/tools/`, registered in `tools::register_modules()`.

**Tool Details:**

1. **Trufflehog** (`trufflehog`) — `trufflehog filesystem --json --no-update {path}`. Parses JSON lines (one result per line). Each result has `DetectorName`, `Verified`, `Raw`, `SourceMetadata`. Verified secrets = High, unverified = Medium. Scanner category. Uses target domain as scan path context.

2. **Prowler** (`prowler`) — `prowler -M csv --output-formats json-ocsf -f {region}`. Parses JSON array of findings with `StatusExtended=FAIL`. Maps Prowler severity (critical/high/medium/low/informational) to ScorchKit Severity. Scanner category.

3. **Trivy** (`trivy`) — `trivy fs --format json --quiet .`. Parses `Results[].Vulnerabilities[]` with VulnerabilityID, Severity, Title, Description, PkgName, InstalledVersion, FixedVersion. Maps CRITICAL/HIGH/MEDIUM/LOW to Severity. Scanner category.

4. **DNSx** (`dnsx`) — `dnsx -silent -resp -d {domain}`. Parses plain text lines: `domain [IP] [records]`. Consolidated finding with count + sample records. Recon category, Info severity.

5. **Gobuster** (`gobuster`) — `gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q --no-error`. Parses status lines like `/path (Status: 200) [Size: 1234]`. Groups by status code. Recon category, severity by status (200=Info, 301/302=Info, 403=Low).

6. **dnsrecon** (`dnsrecon`) — `dnsrecon -d {domain} -t std --json -`. Parses JSON array of record objects with `type`, `name`, `address`/`target`. Consolidated finding per record type. Recon category, Info severity (zone transfer = Medium).

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/tools/trufflehog.rs` | Create | Trufflehog secret scanning wrapper |
| 2 | `src/tools/prowler.rs` | Create | Prowler cloud misconfiguration wrapper |
| 3 | `src/tools/trivy.rs` | Create | Trivy container/dependency scanning wrapper |
| 4 | `src/tools/dnsx.rs` | Create | DNSx fast DNS toolkit wrapper |
| 5 | `src/tools/gobuster.rs` | Create | Gobuster directory/vhost brute-forcing wrapper |
| 6 | `src/tools/dnsrecon.rs` | Create | dnsrecon DNS enumeration wrapper |
| 7 | `src/tools/mod.rs` | Modify | Add 6 `pub mod` + 6 `Box::new()` registrations |

**Type and Trait Changes:**
- 6 new unit structs implementing `ScanModule` trait (no new types beyond that)
- All derive `Debug`

**Error Handling:**
- `run()` returns `Result<Vec<Finding>>` using existing `ScorchError` via `?`
- Parse functions return `Vec<Finding>` directly (not `Result`) — parse cannot fail, just returns empty on bad input
- Follows lesson from #32-35 batch: clippy flags unnecessary Result wrapping

**Testing Strategy:**
- 2 tests per wrapper: parse valid output + parse empty output
- Pure parse functions testable without tools installed
- JSON tools: test with realistic JSON samples
- Plain text tools: test with realistic line samples
- 12 total new tests

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` | N/A | All existing 139 default tests pass |
| 2 | `test_parse_trufflehog_output` | `src/tools/trufflehog.rs` | JSON line parsing, severity mapping |
| 3 | `test_parse_trufflehog_empty` | `src/tools/trufflehog.rs` | Empty output returns empty vec |
| 4 | `test_parse_prowler_output` | `src/tools/prowler.rs` | JSON finding parsing, severity mapping |
| 5 | `test_parse_prowler_empty` | `src/tools/prowler.rs` | Empty output returns empty vec |
| 6 | `test_parse_trivy_output` | `src/tools/trivy.rs` | Vulnerability parsing, CVSS mapping |
| 7 | `test_parse_trivy_empty` | `src/tools/trivy.rs` | Empty output returns empty vec |
| 8 | `test_parse_dnsx_output` | `src/tools/dnsx.rs` | Plain text DNS parsing |
| 9 | `test_parse_dnsx_empty` | `src/tools/dnsx.rs` | Empty output returns empty vec |
| 10 | `test_parse_gobuster_output` | `src/tools/gobuster.rs` | Status line parsing, severity mapping |
| 11 | `test_parse_gobuster_empty` | `src/tools/gobuster.rs` | Empty output returns empty vec |
| 12 | `test_parse_dnsrecon_output` | `src/tools/dnsrecon.rs` | JSON record parsing |
| 13 | `test_parse_dnsrecon_empty` | `src/tools/dnsrecon.rs` | Empty output returns empty vec |

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** tools

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Files Created
| # | File | Purpose |
|---|------|---------|
| 1 | `src/tools/trufflehog.rs` | Trufflehog secret scanning wrapper |
| 2 | `src/tools/prowler.rs` | Prowler cloud misconfiguration wrapper |
| 3 | `src/tools/trivy.rs` | Trivy container/dependency scanning wrapper |
| 4 | `src/tools/dnsx.rs` | DNSx DNS resolution wrapper |
| 5 | `src/tools/gobuster.rs` | Gobuster directory/vhost brute-forcing wrapper |
| 6 | `src/tools/dnsrecon.rs` | dnsrecon DNS enumeration wrapper |

### Files Modified
| # | File | Change |
|---|------|--------|
| 1 | `src/tools/mod.rs` | Added 6 `pub mod` + 6 `Box::new()` registrations |

### Quality Gates
| Gate | Result |
|------|--------|
| `cargo fmt --check` | 0 diffs |
| `cargo clippy --all-features` | 0 new actionable warnings (doc formatting only, pre-existing pattern) |
| `cargo test` | 151 passed, 0 failed (+12 new) |

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Entry Verification
| Check | Result |
|-------|--------|
| `cargo fmt --check` | 0 diffs |
| `cargo clippy --all-features` | 0 new actionable warnings |
| `cargo test` | 151 passed, 0 failed |
| Banned `\`\`\`ignore` | 0 files |
| Banned `#[ignore]` | 0 matches |
| Semgrep | clean |

### Code Review
- [x] All `pub` items have `///` doc comments
- [x] All modules have `//!` module docs
- [x] No `unwrap()` or `expect()` in library code
- [x] All types derive `Debug`
- [x] Pure parse functions testable without tools
- [x] No `unsafe`, no `#[allow]` without justification

### Test Results
- 151 total tests passed (+12 new: 2 per wrapper)
- All 13 regression test plan tests verified

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

- cargo test --features mcp: 251 passed, 0 failed
- Regressions: 0 (was 239, now 251 = +12 new)

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Final Pipeline Checklist
- [x] ALL phases (1-5) show Status = PASS
- [x] `cargo fmt --check` = 0 diffs
- [x] `cargo test --features mcp` = 251 passed, 0 failed
- [x] No banned patterns
- [x] `bootstrap`, `recall`, `learn`, `save-generation-trace` called
- [x] CHANGELOG.md updated (v0.23.0)

### Self-Reflection
1. No workarounds used
2. Implementation is clean — all 6 follow identical established pattern
3. Zero fix iterations (clippy suggestions only)
