# Work Pipeline: Event Bus v2 — In-Process Pub/Sub for Scan Lifecycle

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Phase 2: Design |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /design |
| **Next Step** | Run `/implement` for Phase 3 |
| **Blocked** | No |
| **Forge Ticket** | #97 |
| **Forge Ticket ID** | 019d8ce5-6683-72dd-8c90-d4c507dbf7d5 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec

- **Title:** Event bus v2: in-process pub/sub for scan lifecycle events
- **Type:** Infrastructure
- **Scope:** Add an in-process async event bus for scan lifecycle events. Publishers (Orchestrator, CodeOrchestrator) emit typed events at key lifecycle points. Subscribers (`EventHandler` trait) receive and react to events. The existing `HookRunner` becomes one implementation of `EventHandler` — it subscribes to events and executes scripts. Both systems coexist; the event bus is the primary extensibility mechanism, hooks remain for backward compatibility and script authors who prefer JSON stdin/stdout.
- **Files Expected:** ~5–7 (new `src/engine/events.rs`, modifications to `src/runner/orchestrator.rs` + `code_orchestrator.rs`, `src/engine/hook_runner.rs` becomes a handler, module registration)
- **Dependencies:** tokio (already present), existing `ScanContext`/`CodeContext` types, `Finding` type
- **Risks:**
  - Lifetime complexity — events carrying references (e.g., `&Finding`) would force `'static` bounds on handlers. **Mitigation:** clone into owned event variants (`Finding` is cheap to clone).
  - Backpressure — a slow subscriber shouldn't block the scan. **Mitigation:** `tokio::broadcast` with bounded capacity + lagged receiver handling (log and drop).
  - Existing hooks regression — the refactor must not break current behavior. **Mitigation:** `HookRunner` wraps itself as an `EventHandler` internally; external API unchanged.
- **Acceptance Criteria:**
  - `src/engine/events.rs` defines `ScanEvent` enum with 7+ lifecycle variants
  - `EventBus` struct wraps `tokio::sync::broadcast::Sender<ScanEvent>`
  - `EventHandler` trait (async, `Send + Sync`) for subscribers
  - `Orchestrator::run()` and `CodeOrchestrator::run()` emit events at: scan start, module start, module completed, finding produced, module skipped, module error, scan completed
  - Multiple subscribers supported (broadcast semantics)
  - `HookRunner` refactored to subscribe to events and run existing scripts
  - Graceful failure — subscriber errors/panics don't abort the scan
  - Tests: event emission, multi-subscriber fanout, subscriber error isolation, hook handler adapter
  - `cargo test`, `cargo clippy`, `cargo fmt --check` clean

### Preflight Results

| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK (cargo 1.94.0, rustc 1.94.0) |
| Security tools | OK |
| Hooks wired | OK (8/8) |
| cargo check | OK |
| cargo test | OK (463 passed, 0 failed) |

### Known Pitfalls (from RLM)

- **Re-read pipeline docs after context continuation** — DL-004-P1. This pipeline spans a context clear; the next session must re-read this doc before resuming.
- **Multiple active pipeline docs confuse enforce-agent-scope.sh.** Only this pipeline should be in `active/` while implementing.
- **MCP server pattern (rmcp)** — if event bus exposes tools, `#[tool_router]` macro private methods can't be tested directly. Extract logic to `do_*()` pub methods. Not applicable here unless we add MCP events later.

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — project context
2. **Recall** — `recall(agent, phase, component_types)`
3. **Learn** — record lessons
4. **Search** — architecture docs before coding

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Approach

Build an in-process event bus using `tokio::sync::broadcast`, which provides multi-producer/multi-consumer with lagged receiver handling — the natural fit for a scan lifecycle where many observers want to know when events fire but must not block the scan.

**Three layers:**

1. **`ScanEvent` enum** — typed lifecycle events. Cloneable so `broadcast` can fan out. Carries owned data (no lifetimes).
2. **`EventBus` struct** — wraps `broadcast::Sender`. Offers `.publish(event)` for emitters and `.subscribe()` for handlers. Stored in `ScanContext.events` / `CodeContext.events`.
3. **`EventHandler` trait** — async trait for consumers. Orchestrator spawns one task per registered handler that drives its receive loop.

**Publishing** is synchronous from the caller's perspective: `bus.publish(event)` returns immediately (broadcast send is non-blocking). If the channel is lagging, old events are dropped for slow subscribers — we log it but don't abort. This is the right choice for observability-style events (vs. critical-path).

**The existing `HookRunner`** wraps itself in a `HookEventHandler` struct that implements `EventHandler`. It subscribes to `PreScan` / `PostModule` / `PostScan`-equivalent events and executes configured scripts. External API (`HookConfig` in `scorchkit.toml`) unchanged. Internal: the orchestrator no longer calls `hook_runner.execute()` directly — it publishes events and the handler picks them up.

### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/events.rs` | Create | `ScanEvent` enum, `EventBus` struct, `EventHandler` trait, `subscribe_handler` helper to spawn receive loops |
| 2 | `src/engine/mod.rs` | Modify | Add `pub mod events;` |
| 3 | `src/engine/scan_context.rs` | Modify | Add `events: EventBus` field. Update `new()` to accept/create a bus. |
| 4 | `src/engine/code_context.rs` | Modify | Same — add `events: EventBus` field |
| 5 | `src/runner/orchestrator.rs` | Modify | Emit events at lifecycle points in `run()` and `run_with_checkpoint()` |
| 6 | `src/runner/code_orchestrator.rs` | Modify | Emit events at lifecycle points in `run()` |
| 7 | `src/engine/hook_runner.rs` | Modify | Add `HookEventHandler` struct that impls `EventHandler` and adapts to the existing script runner. Keep `HookRunner` internals. |
| 8 | `src/prelude.rs` | Modify | Re-export `ScanEvent`, `EventBus`, `EventHandler` |

### Type and Trait Changes

```rust
// src/engine/events.rs

/// Scan lifecycle events emitted by orchestrators.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    ScanStarted { scan_id: String, target: String },
    ModuleStarted { scan_id: String, module_id: String, module_name: String },
    ModuleCompleted { scan_id: String, module_id: String, findings_count: usize, duration_ms: u64 },
    ModuleSkipped { scan_id: String, module_id: String, reason: String },
    ModuleError { scan_id: String, module_id: String, error: String },
    FindingProduced { scan_id: String, module_id: String, finding: Finding },
    ScanCompleted { scan_id: String, total_findings: usize, duration_ms: u64 },
}

/// Broadcast channel for scan events.
#[derive(Clone)]
pub struct EventBus {
    sender: tokio::sync::broadcast::Sender<ScanEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self;
    pub fn publish(&self, event: ScanEvent);  // Fire-and-forget
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ScanEvent>;
}

impl Default for EventBus { /* capacity 256 */ }

/// Async trait for event subscribers.
#[async_trait::async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle a scan event. Return value is advisory — errors are logged, not propagated.
    async fn handle(&self, event: ScanEvent) -> Result<(), String>;
}

/// Spawn a receive loop that drives the handler for all events.
/// Returns a JoinHandle so the caller can await completion (typically not needed).
pub fn subscribe_handler(bus: &EventBus, handler: Arc<dyn EventHandler>) -> tokio::task::JoinHandle<()>;
```

### Error Handling Strategy

- **Publish is infallible from the publisher's view.** `broadcast::Sender::send` returns an error only when there are zero receivers, which is fine (log at debug, continue).
- **Handler failures are logged, not propagated.** The `EventHandler::handle` method returns `Result<(), String>` for diagnostic purposes only. Errors are logged at `warn`; the scan proceeds. This matches the hook system's existing fail-open semantics.
- **Lagged receivers drop old events.** `broadcast::Receiver` returns `RecvError::Lagged(n)` when a slow consumer has missed N events. Log and continue the receive loop.
- **No new `ScorchError` variants.** Event bus uses `Result<(), String>` for handler errors to keep the trait lightweight. Orchestrator errors remain `ScorchError` as today.

### Architectural Decisions

1. **`tokio::broadcast` over `mpsc` or custom channel.** Broadcast supports multi-subscriber natively with bounded buffering and lagged-handling semantics built in. `mpsc` is single-consumer only. A custom channel would reinvent the wheel.
2. **Owned events, no lifetimes.** `ScanEvent` variants carry `String` and owned `Finding` clones. This keeps the trait simple (`handle(&self, event: ScanEvent)` — no lifetime params). `Finding` is small and clone-cheap.
3. **Fire-and-forget publish.** Publishers don't await or check handler completion. This keeps the scan path non-blocking and resilient to slow/broken handlers.
4. **`HookRunner` adapter, not deprecation.** The existing hook system stays. `HookEventHandler` translates events into the same JSON stdin/stdout protocol hooks use today. This preserves user configuration and adds native handlers alongside.
5. **Bus lives in ScanContext/CodeContext.** Modules already have access to the context; if a module wants to emit custom events (e.g., a progress event from a long-running scanner), it can use `ctx.events.publish()`. This is a future capability; initial v2 events come only from the orchestrator.
6. **Broadcast capacity 256.** Large enough that normal scans won't lag any reasonable subscriber. Small enough to bound memory. Configurable via `EventBus::new(capacity)` if needed.
7. **No persistence.** Events are in-process only. Users who want audit logs subscribe with a handler that writes to a file/DB. The bus itself is ephemeral.
8. **Two phases of integration.** v2a: event emission from orchestrators + `HookRunner` as a subscriber. v2b (future): custom module-level events, MCP event stream tool, event filtering. Keep v2a scoped.

### Testing Strategy

- **`src/engine/events.rs` inline tests:** event publish/subscribe round-trip, multi-subscriber fanout, lagged receiver handling, `EventBus::default()` behavior.
- **Orchestrator integration tests:** scan end-to-end with an `EventHandler` collecting events, assert correct sequence of `ScanStarted` → `ModuleStarted` → (`FindingProduced*` | `ModuleSkipped` | `ModuleError`) → `ModuleCompleted` → `ScanCompleted`.
- **Hook handler regression:** existing `tests/hooks.rs` (if present) continues to pass unchanged. Hook scripts still fire at pre-scan / post-module / post-scan equivalent events.
- **Subscriber error isolation:** a panicking handler doesn't crash the scan; errors are logged.

### Regression Test Plan

| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_event_bus_publish_subscribe` | `src/engine/events.rs` | Single subscriber receives a published event |
| 2 | `test_event_bus_multiple_subscribers` | `src/engine/events.rs` | Fanout to 2+ subscribers — all receive the same event |
| 3 | `test_event_bus_no_subscribers` | `src/engine/events.rs` | Publishing with 0 subscribers is a no-op (no error propagated) |
| 4 | `test_event_bus_default_capacity` | `src/engine/events.rs` | `EventBus::default()` works and accepts publish |
| 5 | `test_subscribe_handler_receives_all` | `src/engine/events.rs` | `subscribe_handler` helper delivers events to the handler trait |
| 6 | `test_orchestrator_emits_scan_events` | `tests/` (integration) | Running a mock scan produces expected event sequence |
| 7 | `test_hook_handler_still_fires_scripts` | `src/engine/hook_runner.rs` | `HookEventHandler` subscribes to events and triggers script execution at correct points |
| 8 | `test_handler_error_does_not_abort_scan` | `src/engine/events.rs` | A handler returning `Err` doesn't affect other handlers or the publisher |

### Deferred Items

- **MCP event stream tool** — exposing the event bus over MCP as a subscribable stream. Requires rmcp subscription/notification support; too much scope for v2a. Deferred to v2b.
- **Event filtering / selective subscription** — subscribers always receive all events in v2a. Future: bitmask or enum discriminant filter on `subscribe(filter)`. Not needed yet.
- **Event persistence (audit log)** — no built-in persistence; users write their own handler. If a built-in audit handler becomes common, add it later.
- **Module-emitted custom events** — modules can use `ctx.events.publish()` but the variant set is fixed in v2a. Adding `ScanEvent::Custom { kind: String, data: serde_json::Value }` is a trivial follow-up if demand appears.

### Issues Found

- None during design.

### Knowledge Recorded

- **Lessons:** 1 (design captured below)
- **Failures:** 0
- **Component Types:** engine, events, runner, hooks

### Human Confirmed

- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started
**Started:**
**Completed:**

### Files Created
| File | Path |
|------|------|

### Files Modified
| File | Change |
|------|--------|

### Quality Gates
- **cargo fmt --check:**
- **cargo clippy:**
- **cargo test:**

### Notes

### Knowledge Recorded
- **Lessons:**
- **Failures:**
- **Component Types:**

---

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started
**Started:**
**Completed:**

### Entry Verification (independently run)
- **cargo fmt --check:**
- **cargo clippy:**
- **cargo test:**
- **```ignore check:**
- **#[ignore] check:**
- **#[allow] workaround check:**

### Code Review
- **Standards Compliance:**
- **Workaround Detection:**
- **Security Review (semgrep):**

### Test Results
- **Cargo Test Count:**
- **Doctest Count:**
- **Coverage:**

### Regression Test Plan Compliance

### Knowledge Recorded
- **Lessons:**
- **Failures:**
- **Component Types:**

---

## Phase 5: Verify
**Command:** /verify
**Status:** Not Started

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started

---

## Context for Next Session (after /clear)

### Where we are
Pipeline through Phase 2 Design is COMPLETE. Ready for Phase 3 Implement.

### Key files to re-read first
1. `docs/planning/pipeline/active/WORK-097-event-bus-v2.md` (this document) — source of truth
2. `src/engine/hook_runner.rs` — existing hook system to refactor
3. `src/runner/orchestrator.rs` — publisher integration points (`run()`, `run_with_checkpoint()`)
4. `src/runner/code_orchestrator.rs` — publisher integration points (`run()`)
5. `src/engine/scan_context.rs` + `src/engine/code_context.rs` — fields to add `events: EventBus`
6. `CONSTITUTION.md` — phase rules + code quality standards

### Start implementation with

```bash
cargo test 2>&1 | strings | grep "^test result:" | head -3
# expected: 463 passed
```

Then advance the pipeline status from "Phase 2: Design" → "Phase 3: Implement" in the header.

Implementation order (safe incremental):
1. Create `src/engine/events.rs` (standalone, testable)
2. Add `pub mod events;` to `src/engine/mod.rs`
3. Add `events: EventBus` to `ScanContext` (non-breaking default)
4. Add `events: EventBus` to `CodeContext` (non-breaking default)
5. Emit events in `Orchestrator::run()` — start, completed
6. Add remaining event emission points (module start/complete/skipped/error, findings)
7. Replicate in `code_orchestrator.rs`
8. Refactor `HookRunner` into `HookEventHandler`
9. Re-exports in `src/prelude.rs`
10. Tests throughout

Each step should leave the tree in a compiling, green-test state.
