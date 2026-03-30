# Work Pipeline: Evidence Capture + Webhook Notifications

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
| **Forge Ticket** | #29 + #30 (merged pipeline) |
| **Forge Ticket ID** | 019d3a84-b63c-704c-bf4c-c3c580d4d9e3 (#29), 019d3a84-c298-723b-a16a-60772533ad16 (#30) |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-30
**Completed:** 2026-03-30

### Work Spec
- **Title:** Evidence capture (request/response pairs) + webhook notification integration
- **Type:** Feature
- **Scope:** Two event-driven features:
  1. **Evidence Capture** (#29) — New `engine/evidence.rs` with `HttpEvidence` struct storing HTTP request method, URL, headers, body, and response status/headers/body as structured data. New `.with_http_evidence()` builder on Finding. Modules can attach full request/response pairs to findings for PoC replay. No screenshots (requires headless browser — deferred).
  2. **Webhook Notifications** (#30) — New `runner/hooks.rs` with `ScanEvent` enum (`ScanStarted`, `ScanCompleted`, `FindingDiscovered`) and `WebhookNotifier` that POSTs JSON payloads to configured URLs. Config via `[webhooks]` section in config. Fires from Orchestrator at key lifecycle points. Async, fire-and-forget (failures logged, don't block scan).
- **Files Expected:** ~5 files (2 new modules, config update, orchestrator integration, finding update)
- **Dependencies:** Existing `Finding` builder, `Orchestrator`, `AppConfig`
- **Risks:**
  - Evidence bodies can be large — need size limits
  - Webhook delivery is fire-and-forget — no retry or queue
  - Screenshots deferred (needs headless Chrome/Playwright — too heavy for this pipeline)
- **Acceptance Criteria:**
  - `HttpEvidence` struct captures request + response data
  - Finding builder supports `.with_http_evidence()` method
  - `ScanEvent` enum covers scan lifecycle events
  - `WebhookNotifier` POSTs JSON to configured URLs
  - Config supports `[[webhooks]]` array with URL + optional events filter
  - `cargo test` passes with no regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 160 default passed |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code

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
**Completed:** 2026-03-30

### Architecture

**Feature 1: Evidence Capture (#29)**
New `engine/evidence.rs` with `HttpEvidence` struct: method, url, request_headers (HashMap), request_body (Option), status_code, response_headers (HashMap), response_body (truncated to 10KB max). Finding gets `http_evidence: Option<HttpEvidence>` field + `.with_http_evidence()` builder. Serialized as JSON in finding output. No screenshots (deferred — needs headless browser).

**Feature 2: Webhook Notifications (#30)**
New `runner/hooks.rs` with `ScanEvent` enum (ScanStarted, ScanCompleted, FindingDiscovered) + `WebhookNotifier`. Config via `webhooks: Vec<WebhookConfig>` in AppConfig where each has `url: String` and `events: Option<Vec<String>>` filter. `notify()` is async fire-and-forget via `tokio::spawn` — failures logged, never block scan. Uses existing reqwest client.

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/evidence.rs` | Create | HttpEvidence struct |
| 2 | `src/engine/finding.rs` | Modify | Add http_evidence field + builder |
| 3 | `src/engine/mod.rs` | Modify | Add `pub mod evidence` |
| 4 | `src/runner/hooks.rs` | Create | ScanEvent, WebhookNotifier |
| 5 | `src/runner/mod.rs` | Modify | Add `pub mod hooks` |
| 6 | `src/config/types.rs` | Modify | Add WebhookConfig + webhooks vec |

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_http_evidence_builder` | `src/engine/evidence.rs` | Evidence struct construction |
| 2 | `test_http_evidence_truncation` | `src/engine/evidence.rs` | Body truncated at 10KB |
| 3 | `test_finding_with_evidence` | `src/engine/evidence.rs` | Finding builder integration |
| 4 | `test_scan_event_serialize` | `src/runner/hooks.rs` | Event JSON serialization |
| 5 | `test_webhook_config_default` | `src/runner/hooks.rs` | Default config |
| 6 | `test_event_filter` | `src/runner/hooks.rs` | Events filter matching |

### Human Confirmed
- [x] Design reviewed and confirmed (user pre-approved)

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Completed:** 2026-03-30
- Created: evidence.rs, hooks.rs
- Modified: finding.rs, mod.rs (engine + runner), config/types.rs
- Quality: fmt 0 diffs, clippy 0 new, tests 275 (+6)

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Completed:** 2026-03-30
- Entry verification: all gates pass, semgrep clean

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Completed:** 2026-03-30
- 275 tests, 0 regressions (was 269)

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Completed:** 2026-03-30
- CHANGELOG v0.26.0, knowledge recorded, pipeline archived
