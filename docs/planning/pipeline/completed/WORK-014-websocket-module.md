# Work Pipeline: WebSocket Security Testing Module

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
| **Forge Ticket** | #14 |
| **Forge Ticket ID** | 019d3a83-7ad9-73af-aba1-c1361fd23de8 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Work Spec
- **Title:** WebSocket security testing module
- **Type:** Feature
- **Scope:** New built-in scanner module (`scanner/websocket.rs`) that tests WebSocket endpoint security. Probes common WS paths (`/ws`, `/socket.io`, `/cable`, `/hub`, `/graphql`), tests WS/WSS connectivity, checks origin header validation (CSWSH — Cross-Site WebSocket Hijacking), tests unauthenticated access to WS endpoints, and analyzes upgrade response headers. Requires adding `tokio-tungstenite` crate for async WebSocket client support. Does NOT include message fuzzing or protocol-specific payload injection in this initial scope — focuses on connection-level security checks.
- **Files Expected:** ~3 files (1 new scanner module `scanner/websocket.rs`, modification to `scanner/mod.rs`, `Cargo.toml` for `tokio-tungstenite` dependency)
- **Dependencies:** New crate: `tokio-tungstenite` (async WebSocket client, well-maintained, ~4M downloads). Existing: `ScanModule` trait, `ScanContext`, `url` crate for URL scheme conversion (http→ws, https→wss)
- **Risks:**
  - New crate dependency (`tokio-tungstenite`) — first entirely new crate since `croner` for scheduling
  - WS endpoints often require specific subprotocols or auth tokens — module must handle connection failures gracefully
  - `cargo deny` must accept the new dependency's license
  - WebSocket connections may hang if server doesn't respond — needs connect timeout
- **Acceptance Criteria:**
  - `WebSocketModule` in `scanner/websocket.rs` implements `ScanModule`
  - Probes common WS endpoint paths for connectivity
  - Tests origin header validation (CSWSH) by connecting with spoofed origin
  - Tests unauthenticated WS access (connects without auth credentials)
  - Analyzes upgrade response headers for security issues
  - Graceful handling of connection failures and timeouts
  - Unit tests for URL conversion, path generation, and response analysis
  - `cargo test` passes with no regressions
  - `cargo clippy` clean, `cargo fmt` clean
  - Registered as 23rd built-in scanner module

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0 |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test | OK — 86 default passed |
| Active pipelines | None |

### Human Confirmed
- [x] Spec reviewed and confirmed (user pre-approved)

### Known Pitfalls (from RLM)
- After ANY context continuation, re-read all active pipeline documents before resuming work
- MANDATORY: Call bootstrap -> ticket-next -> recall BEFORE writing any code
- Check existing modules for overlap (lesson from auth/misconfig boundary)
- Adding new crate: verify cargo deny accepts the license

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
New built-in scanner module `scanner/websocket.rs` implementing `ScanModule`. Three-phase approach:

1. **Discovery** — Probe common WebSocket paths (`/ws`, `/wss`, `/socket.io`, `/cable`, `/hub`, `/graphql`, `/realtime`, `/events`, `/stream`, `/chat`) by attempting HTTP Upgrade requests. A successful upgrade (101 status) confirms a WS endpoint exists. Uses `reqwest` for the initial HTTP probe (Upgrade header check) — no `tokio-tungstenite` needed for discovery.

2. **CSWSH Test** — For each discovered endpoint, attempt a WebSocket connection with a spoofed `Origin: https://evil-attacker.com` header. If the connection succeeds, the server doesn't validate origins → Cross-Site WebSocket Hijacking vulnerability.

3. **Upgrade Response Analysis** — Inspect the HTTP upgrade response headers for security issues: missing `Strict-Transport-Security` on WSS, WS (unencrypted) when HTTPS is available, information disclosure in server headers.

**Key Design Decisions:**

- **`tokio-tungstenite` for WS connections** — Required for actual WebSocket handshake and CSWSH testing. `reqwest` can send Upgrade requests but can't complete the WS handshake. `tokio-tungstenite` is MIT/Apache-2.0 (both in deny.toml allow list), async-native, well-maintained (4M+ downloads).
- **`tokio-tungstenite` with `connect_async_with_config` + `rustls` connector** — Uses the `rustls-tls-native-roots` feature to match ScorchKit's existing TLS stack (reqwest also uses rustls). Avoids linking native OpenSSL.
- **Connect timeout** — All WS connections wrapped in `tokio::time::timeout(Duration::from_secs(5))`. Prevents hanging on non-responsive endpoints.
- **HTTP probe before WS connect** — Check for 101 Upgrade response via reqwest first. Only attempt full WS handshake (with tokio-tungstenite) on confirmed endpoints. This avoids slow timeout loops on non-WS paths.
- **URL conversion** — Pure function `http_to_ws_url()` converts `http://→ws://`, `https://→wss://`. Used to construct WS URLs from the target's HTTP base URL.
- **No message fuzzing** — Initial scope is connection-level security. Message injection/fuzzing requires protocol understanding (Socket.IO, STOMP, etc.) and is deferred.

**WebSocket Security Tests:**
| # | Test | What it checks | Severity | CWE |
|---|------|---------------|----------|-----|
| 1 | WS endpoint discovery | Which paths accept WebSocket upgrades | Info | — |
| 2 | CSWSH (origin bypass) | Server accepts connections from evil origin | High | 346 |
| 3 | Unencrypted WS | WebSocket over `ws://` when HTTPS available | Medium | 319 |
| 4 | Unauthenticated access | WS connection succeeds without auth credentials | Medium | 306 |

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/scanner/websocket.rs` | Create | `WebSocketModule` — WS endpoint discovery, CSWSH, upgrade analysis |
| 2 | `src/scanner/mod.rs` | Modify | Add `mod websocket;` and register `WebSocketModule` |
| 3 | `Cargo.toml` | Modify | Add `tokio-tungstenite` with `rustls-tls-native-roots` feature |

**Type and Trait Changes:**

Internal types in `websocket.rs`:
- `WsEndpoint` — struct with `url: String`, `path: String` for discovered endpoints
- Pure functions: `http_to_ws_url()`, `generate_ws_paths()`, `is_upgrade_response()`

No trait changes. No modifications to `ScanModule`, `ScanContext`, or public types.

**Error Handling Strategy:**
- `ScorchError::Http` for HTTP probe failures (existing variant)
- WS connection failures → gracefully skip (endpoint doesn't accept WS)
- Connection timeouts → skip endpoint (5s timeout)
- No new error variants needed

**Testing Strategy:**
- Unit tests in `scanner/websocket.rs` (`#[cfg(test)] mod tests`):
  - `http_to_ws_url()` conversion for http/https/custom-port/with-path
  - `generate_ws_paths()` produces expected endpoint paths
  - `is_upgrade_response()` header analysis
  - WS endpoint struct construction
- No live WS integration tests (would require a WebSocket server)
- Existing `tests/cli.rs::test_modules_list` auto-verifies websocket module appears

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cargo test` (default) | N/A | All existing 86+ tests pass |
| 2 | `cargo clippy --all-features` | N/A | No new warnings |
| 3 | `test_http_to_ws_url` | `src/scanner/websocket.rs` | http→ws, https→wss, port/path preserved |
| 4 | `test_http_to_ws_url_edge_cases` | `src/scanner/websocket.rs` | Already-ws URLs, custom ports |
| 5 | `test_generate_ws_paths` | `src/scanner/websocket.rs` | All expected paths generated |
| 6 | `test_is_upgrade_response` | `src/scanner/websocket.rs` | Detects 101 + upgrade/websocket headers |
| 7 | `test_modules_list` | `tests/cli.rs` | websocket appears in module listing |

**Architectural Decisions:**
- **New crate: `tokio-tungstenite`** — MIT/Apache-2.0, both in deny.toml allow list. The only mature async WS client in the Rust ecosystem. `rustls-tls-native-roots` feature to match ScorchKit's TLS stack.
- **HTTP probe first** — Avoids slow WS handshake timeouts on every path. Reqwest can quickly determine if a path returns 101 Upgrade before committing to a full WS connection.
- **No overlap with existing modules** — SSL module tests TLS config, this tests WS protocol security. No boundary issue.

### Deferred Items
- Message injection/fuzzing (protocol-specific: Socket.IO, STOMP, GraphQL subscriptions)
- WS subprotocol detection and testing
- Authenticated WS connections using AuthConfig tokens

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
| WebSocket security scanner | `src/scanner/websocket.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/scanner/mod.rs` | Added `mod websocket;` and registered `WebSocketModule` |
| `Cargo.toml` | Added `tokio-tungstenite` with `rustls-tls-native-roots` feature |

### Quality Gates
- **cargo fmt --check:** Pass — zero diffs
- **cargo clippy --all-features:** Pass — zero warnings from websocket.rs
- **cargo test:** Pass — 92 passed, 0 failed (was 86, +6 new WS unit tests)

### Notes
- Followed design exactly — HTTP probe first, then WS handshake for confirmed endpoints
- Used `strip_prefix` + `map`/`or_else` chain for URL conversion (clippy-approved)
- `if let Ok(Ok(...))` pattern for WS connection result matching
- 6 unit tests: URL conversion (standard + edge cases + query), path generation, upgrade detection, endpoint construction

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Entry Verification
- All checks pass: fmt, clippy, tests (92 default), semgrep clean, no banned patterns, no unjustified #[allow]

### Test Results
- **Default:** 92 passed (was 86, +6)
- **MCP:** 189 passed (was 183, +6)
- **Regression plan:** 7/7 passing

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Regression: Phase 4→5 mcp 189→189, delta 0, regressions 0

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-03-29
**Completed:** 2026-03-29

### Self-Reflection
1. **Workarounds:** None.
2. **Cleanest version:** Yes — two-stage discovery, idiomatic `if let` for WS results, clippy-approved URL conversion chain.
3. **Senior Rust approval:** Yes — no unwrap/expect, proper timeout handling, new crate license verified.

### CHANGELOG: v0.15.0
### Knowledge: save-generation-trace + learn recorded
