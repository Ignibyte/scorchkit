# Work Pipeline: Prowler Deep Integration + Cloud Tool Wrappers (cnspec, pacu, cloudsplaining)

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 3: Implement |
| **Created** | 2026-04-15 |
| **Last Updated** | 2026-04-15 |
| **Last Command** | /implement |
| **Next Step** | Quality gates then commit |
| **Blocked** | No |
| **Forge Ticket** | #129, #130 |
| **Forge Ticket ID** | 019d8ef5-a54b-70eb-b277-533ddbbe28af, 019d8ef5-b7c4-712e-997d-4a8057eb4be6 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Work Spec
- **Title:** Prowler Deep Integration + Cloud Tool Wrappers (cnspec, pacu, cloudsplaining)
- **Type:** Feature
- **Scope:** Two deliverables: (A) Enhance the existing `prowler-cloud` OCSF parser to extract per-control compliance IDs (CIS, PCI-DSS, NIST) from Prowler's OCSF `compliance` field and populate `Finding.compliance` with them. (B) Add 3 new `CloudModule` tool wrappers: `cnspec` (Mondoo cloud security), `pacu` (AWS exploitation framework for offensive validation), `cloudsplaining` (IAM least-privilege auditor).
- **Files Expected:** ~5-6 (1 modified prowler.rs, 3 new tool wrapper files, cloud/mod.rs update)
- **Dependencies:** `CloudModule` trait (WORK-150), `CloudEvidence` + `enrich_cloud_finding` (WORK-154), `subprocess::run_tool_lenient` pattern
- **Risks:**
  - Prowler OCSF compliance field structure may vary between Prowler versions
  - cnspec/pacu/cloudsplaining may not be installed on the operator's system (graceful skip via `requires_external_tool`)
  - pacu is an offensive tool — findings should clearly indicate this is for authorized testing
- **Acceptance Criteria:**
  - Prowler parser extracts CIS/PCI-DSS/NIST control IDs from OCSF compliance field
  - Finding.compliance populated with per-check control references (not just blanket A05)
  - 3 new cloud module tool wrappers registered
  - All wrappers follow standard subprocess pattern with `run_tool_lenient`
  - All findings use `CloudEvidence` + `enrich_cloud_finding`
  - Zero test regressions

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK |
| Security tools | OK |
| Hooks wired | OK — 8/8 |
| cargo check | OK |
| cargo test (cloud) | OK — 714 passed |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- WORK-151: run_tool_lenient over strict run_tool (Prowler exits 3 on FAIL findings)
- WORK-154: CloudEvidence builder + enrich_cloud_finding for all cloud findings

---

## Forge Briefing

Every phase command MUST call bootstrap, recall, learn, search-architecture-docs.

---

## Phase 2: Design
**Command:** /design
**Status:** Not Started

---

## Phase 3: Implement
**Command:** /implement
**Status:** Not Started

---

## Phase 4: Validate
**Command:** /validate
**Status:** Not Started

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** Not Started

---

## Phase 6: Complete
**Command:** /complete
**Status:** Not Started
