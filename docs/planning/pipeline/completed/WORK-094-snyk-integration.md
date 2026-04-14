# Work Pipeline: Snyk CLI Integration — Dependency + Code Scanning

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /implement |
| **Next Step** | Quality gates |
| **Blocked** | No |
| **Forge Ticket** | #94 |
| **Forge Ticket ID** | 019d8c66-05f0-7078-b110-14dac2238787 |

---

## Phase 1: Plan — PASS
## Phase 2: Design — PASS

### File Manifest
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | src/sast_tools/snyk_test.rs | Create | Snyk dependency SCA wrapper (snyk test --json), CodeCategory::Sca |
| 2 | src/sast_tools/snyk_code.rs | Create | Snyk code SAST wrapper (snyk code test --json), CodeCategory::Sast |
| 3 | src/sast_tools/mod.rs | Modify | Add pub mod + register both |
| 4 | src/mcp/prompts.rs | Modify | Add "snyk-test" and "snyk-code" to is_sast_module() |

### Regression Test Plan
| # | Test | Verifies |
|---|------|----------|
| 1 | test_parse_snyk_test_output | Parses snyk test JSON |
| 2 | test_parse_snyk_test_empty | Empty/invalid graceful |
| 3 | test_parse_snyk_code_output | Parses snyk code test JSON |
| 4 | test_parse_snyk_code_empty | Empty/invalid graceful |
