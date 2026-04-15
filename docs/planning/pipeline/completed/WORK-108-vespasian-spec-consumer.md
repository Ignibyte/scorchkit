# Work Pipeline: Vespasian spec consumer (architectural primitive)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Status** | Complete (archived) |
| **Forge Ticket** | #108 |
| **Forge Ticket ID** | 019d8e0e-6726-735a-ad38-25f3a8de7292 |

## Phase 1-2 — PASS

### Scope: smaller than originally ticketed

Original ticket proposed wiring 6 scanners to consume Vespasian's spec. That's too big for one pipeline. Reshaping this ticket as the **architectural primitive** + **one demo consumer**, and creating WORK-108b for the remaining 5 scanner wirings as a follow-up.

### Files
- NEW `src/engine/api_spec.rs` — `ApiSpec`, `ApiEndpoint`, `SHARED_KEY_API_SPEC`, `publish_api_spec`, `read_api_spec` (mirrors `service_fingerprint.rs` pattern)
- MOD `src/engine/mod.rs` — `pub mod api_spec;`
- MOD `src/tools/vespasian.rs` — call `publish_api_spec(&ctx.shared_data, &spec)` after parse
- MOD `src/scanner/injection.rs` — consume `read_api_spec` and probe each discovered endpoint's parameters
- MOD `src/prelude.rs` — re-export `ApiSpec`, `ApiEndpoint`
- NEW `docs/architecture/api-spec-shared-data.md` — operator + contributor reference

### Pattern for follow-up (WORK-108b)
The four remaining consumer modules (csrf, idor, graphql, auth, ratelimit) follow the same shape: `read_api_spec` → iterate endpoints → run module-specific tests against each endpoint's URL + method + params.

## Phase 3-6 — PASS (2026-04-15)

### Files created
- `src/engine/api_spec.rs` — primitive (3 unit tests)
- `docs/architecture/api-spec-shared-data.md`

### Files modified
- `src/engine/mod.rs` — `pub mod api_spec;`
- `src/tools/vespasian.rs` — `build_api_spec` + `publish_api_spec` call after parse
- `src/scanner/injection.rs` — `read_api_spec` consumer + `build_probe_url` helper + 3 unit tests
- `src/prelude.rs` — re-export `ApiSpec`, `ApiEndpoint`
- `CHANGELOG.md` — WORK-108 bullet

### Quality gates
- `cargo fmt` ✓
- `cargo clippy -- -D warnings` ✓ (5 fixes during iteration: doc_markdown backticks, useless_format / format-iter rewrite to manual push_str)
- `cargo test` ✓ — **605 passed** (+6 vs WORK-107 baseline of 599)

### Follow-up
- WORK-108b created for the remaining 5 scanners (csrf, idor, graphql, auth, ratelimit) — same pattern, mechanical to apply