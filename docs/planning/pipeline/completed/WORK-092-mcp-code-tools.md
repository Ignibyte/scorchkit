# Work Pipeline: MCP Code Scanning Tools — scan-code + list-code-modules

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
| **Forge Ticket** | #92 |
| **Forge Ticket ID** | 019d8c4a-719b-7123-848c-0c7a82e2d094 |

---

## Phase 1: Plan — PASS
## Phase 2: Design — PASS

### File Manifest
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | src/mcp/types.rs | Modify | Add CodeScanParams, ListCodeModulesParams |
| 2 | src/mcp/tools.rs | Modify | Add do_scan_code(), do_list_code_modules(), fix update_finding_status bug, add #[tool] wrappers |

### Regression Test Plan
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | test_do_list_code_modules | src/mcp/tools.rs | Returns JSON with all SAST modules |
| 2 | test_do_scan_code_empty | src/mcp/tools.rs | Empty dir produces empty findings |

---

## Phase 3-6: (in progress)
