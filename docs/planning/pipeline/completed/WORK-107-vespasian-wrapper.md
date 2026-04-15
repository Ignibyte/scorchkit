# Work Pipeline: Vespasian wrapper (API endpoint discovery)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Status** | Complete (archived) |
| **Forge Ticket** | #107 |
| **Forge Ticket ID** | 019d8e0e-360f-71b1-8cd0-9468b6220323 |

## Phase 1-2 — PASS

New `src/tools/vespasian.rs` follows the canonical `ScanModule` wrapper pattern. Invokes `vespasian scan <url> -o <yaml-tempfile>`, parses the resulting OpenAPI 3.0 spec, and surfaces one Info `Finding` per discovered endpoint plus a summary finding listing endpoint count + classification (REST/GraphQL/SOAP/WebSocket).

Files:
- `src/tools/vespasian.rs` — wrapper
- `src/tools/mod.rs` — declare + register
- `src/cli/doctor.rs` — `ToolSpec` entry
- `docs/tools/vespasian.md` — operator reference

## Phase 3-6 — PASS (2026-04-15)

- 1 wrapper + 5 tests; lib clippy clean; default tests 599 (+5).
- `tempfile` reused (already a runtime dep from WORK-111); no new deps.
- Doc at `docs/tools/vespasian.md`.