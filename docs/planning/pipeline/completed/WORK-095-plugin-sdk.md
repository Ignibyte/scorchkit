# Work Pipeline: Plugin SDK — Rust Plugin Author Guide + Examples

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Quality gates |
| **Blocked** | No |
| **Forge Ticket** | #95 |
| **Forge Ticket ID** | 019d8ca8-bacc-70b2-862d-ba1f7ea5fb80 |

---

## Phase 1: Plan — PASS
## Phase 2: Design — PASS

### Approach
Plugin SDK foundation for v1.3. Uses the existing `scorchkit` crate and prelude — no workspace restructure. Adds working examples + documentation so third-party Rust developers can write native `ScanModule` and `CodeModule` implementations.

### File Manifest
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | examples/custom_scanner/Cargo.toml | Create | Example third-party DAST scan module crate |
| 2 | examples/custom_scanner/src/lib.rs | Create | Complete ScanModule impl with tests |
| 3 | examples/custom_code_scanner/Cargo.toml | Create | Example third-party SAST code module crate |
| 4 | examples/custom_code_scanner/src/lib.rs | Create | Complete CodeModule impl with tests |
| 5 | docs/plugin-sdk.md | Create | Plugin author guide |

### Regression Test Plan
| # | Test | Verifies |
|---|------|----------|
| 1 | compile-check: custom_scanner builds against scorchkit | `cargo check --manifest-path examples/custom_scanner/Cargo.toml` |
| 2 | compile-check: custom_code_scanner builds | `cargo check --manifest-path examples/custom_code_scanner/Cargo.toml` |

### Architectural Decisions
1. **No workspace restructure.** The existing `scorchkit` crate + `prelude` already exposes every type a plugin author needs. A separate `scorchkit-sdk` crate would require splitting `engine/` types across crates with complex dependency boundaries. Examples + docs are lower risk, immediately usable.
2. **Examples as path dependencies.** `examples/custom_scanner/Cargo.toml` uses `path = "../.."` to depend on the main scorchkit crate. This keeps examples in sync with the current API during development.
3. **No new cargo features.** Examples depend on the default scorchkit build — no storage/mcp features needed for plugin authors.
4. **Documentation focus: contract + pattern, not API reference.** `cargo doc` already generates API docs. The plugin-sdk.md doc focuses on the conceptual pattern: how to structure a module, where findings fit, testing strategy.
