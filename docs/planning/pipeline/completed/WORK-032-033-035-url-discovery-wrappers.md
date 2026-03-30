# Work Pipeline: URL Discovery Tool Wrappers (Katana, Gau, ParamSpider)

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
| **Forge Ticket** | #32 + #33 + #35 (merged pipeline) |
| **Forge Ticket ID** | 019d3a85-1f7c-73e9-a043-892f2ff36ae3 (Katana), 019d3a85-2d9e-7234-bf72-8efd57012f3d (Gau), 019d3a85-461b-71bb-be46-bd6255ca7fd1 (ParamSpider) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** URL discovery tool wrappers: Katana, Gau/Waybackurls, ParamSpider
- **Type:** Feature
- **Scope:** Three new external tool wrapper modules following the existing nmap/nuclei/feroxbuster subprocess pattern:
  1. `tools/katana.rs` — Wraps ProjectDiscovery's Katana crawler. Runs `katana -u {target} -json -silent`, parses JSON output for discovered URLs. Category: Recon. Requires `katana` binary.
  2. `tools/gau.rs` — Wraps `gau` (GetAllUrls) for passive URL discovery from Wayback Machine, Common Crawl, etc. Runs `gau {domain} --json`, parses JSON output. Category: Recon. Requires `gau` binary.
  3. `tools/paramspider.rs` — Wraps ParamSpider for URL parameter mining. Runs `paramspider -d {domain}`, parses output for parameterized URLs. Category: Recon. Requires `paramspider` binary.
- **Files Expected:** ~4 files (3 new tool wrappers in `tools/`, 1 mod.rs modification)
- **Dependencies:** Existing `subprocess::run_tool()` for process management. Existing `ScanModule` trait. No new crate deps.
- **Risks:**
  - Tools not installed — standard graceful degradation (ToolNotFound)
  - Output format varies by tool version — need robust parsing
  - All three follow the exact same pattern as existing 22 tool wrappers
- **Acceptance Criteria:**
  - Three new tool wrappers implementing `ScanModule` with `requires_external_tool() = true`
  - Each parses tool output into `Finding` objects with evidence
  - Graceful degradation when tool not installed
  - Registered in `tools/mod.rs::register_modules()`
  - Unit tests for output parsing (pure functions, no tool needed)
  - `cargo test` passes with no regressions
  - Module count: 56 (was 53, +3 tool wrappers)

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 133 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- #34 (Interactsh CLI) was already done as part of #11 — closed as duplicate

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
Three new tool wrappers following the identical pattern as `tools/nmap.rs`: struct implementing `ScanModule`, `requires_external_tool() = true`, `required_tool()` returning the binary name, `run()` calling `subprocess::run_tool()` with appropriate args, parsing output into `Finding` objects. All three are Recon category (URL/endpoint discovery, not vulnerability testing).

**Module 1: `tools/katana.rs` — Katana Web Crawler**
- Binary: `katana`
- Args: `katana -u {url} -json -silent -depth 3 -no-color`
- Output: JSON lines, each with `request.endpoint` field
- Timeout: 300s
- Finding: Info severity — "URL Discovered: {url}" for each unique endpoint

**Module 2: `tools/gau.rs` — GetAllUrls Passive Discovery**
- Binary: `gau`
- Args: `gau --subs {domain}`
- Output: Plain text, one URL per line
- Timeout: 120s
- Finding: Info severity — "Historical URL: {url}" for each discovered URL

**Module 3: `tools/paramspider.rs` — ParamSpider Parameter Mining**
- Binary: `paramspider`
- Args: `paramspider -d {domain} --quiet`
- Output: Plain text, one parameterized URL per line
- Timeout: 120s
- Finding: Info severity — "Parameterized URL: {url}" for URLs containing query parameters

**Key Design Decisions:**

- **All Recon category** — these discover endpoints/URLs, not vulnerabilities. Info-severity findings. Same as existing recon modules (headers, tech, discovery, subdomain, crawler).
- **run_tool one-shot** — unlike interactsh (long-running), these are fire-and-forget subprocess calls. Identical to nmap/nuclei pattern.
- **Output line counting** — each tool produces one URL per line. Parse and deduplicate. Create one consolidated Info finding per tool with count + sample URLs rather than one finding per URL (which could be thousands).
- **Pure parse functions** — `parse_katana_output()`, `parse_gau_output()`, `parse_paramspider_output()` — all testable without tools installed.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/tools/katana.rs` | Create | `KatanaModule` — JS-rendering web crawler wrapper |
| 2 | `src/tools/gau.rs` | Create | `GauModule` — passive URL discovery wrapper |
| 3 | `src/tools/paramspider.rs` | Create | `ParamSpiderModule` — URL parameter mining wrapper |
| 4 | `src/tools/mod.rs` | Modify | Add `pub mod katana/gau/paramspider;` and register all three |

**Type and Trait Changes:** None. Uses existing `ScanModule` trait, existing `subprocess::run_tool()`.

**Error Handling:** Existing `ScorchError::ToolNotFound`, `ScorchError::ToolFailed`, `ScorchError::Cancelled` via `run_tool()`.

**Testing Strategy:**
- Pure parse functions for each tool's output format
- JSON line parsing for Katana
- Plain text line parsing for Gau and ParamSpider
- Empty output handling
- No live tool tests (tools may not be installed)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 133+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_parse_katana_output` | `src/tools/katana.rs` | Parses Katana JSON lines |
| 4 | `test_parse_gau_output` | `src/tools/gau.rs` | Parses Gau plain text URLs |
| 5 | `test_parse_paramspider_output` | `src/tools/paramspider.rs` | Parses ParamSpider URLs with params |
| 6 | `test_parse_empty_output` | each file | Handles empty/no output gracefully |
| 7 | `test_modules_list` | `tests/cli.rs` | katana + gau + paramspider in listing |

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

## Phase 3-6: All PASS
- **Implement:** 3 files created, 1 modified. 139 default tests (+6). Clippy clean.
- **Validate:** MCP 236 (+6). Semgrep clean.
- **Verify:** 236→236, delta 0, regressions 0.
- **Complete:** CHANGELOG v0.21.0. Knowledge recorded.

### Self-Reflection
1. **Workarounds:** None. Clippy-driven improvement: changed parse functions from Result<Vec> to Vec (can't fail).
2. **Cleanest version:** Yes — identical nmap pattern, consolidated findings, pure parse functions.
3. **Senior Rust approval:** Yes.
