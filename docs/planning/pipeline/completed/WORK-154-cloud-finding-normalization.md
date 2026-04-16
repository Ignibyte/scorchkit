# Work Pipeline: Cloud Finding Normalization — Common Evidence Builder + Compliance Extraction

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Feature |
| **Status** | Phase 6: Complete |
| **Created** | 2026-04-15 |
| **Last Updated** | 2026-04-15 |
| **Last Command** | /complete |
| **Next Step** | Run `/commit` to ship |
| **Blocked** | No |
| **Forge Ticket** | #154 |
| **Forge Ticket ID** | 019d93ca-6074-7247-b0a5-db05a3863581 |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Work Spec
- **Title:** Cloud Finding Normalization — Common Evidence Builder + Compliance Extraction
- **Type:** Feature
- **Scope:** Replace freeform pipe-delimited evidence strings in all 3 cloud modules with a structured `CloudEvidence` builder type (Part A), and replace hardcoded OWASP A05:2021 / CWE 1188 with per-check compliance mapping using the existing `compliance.rs` functions (Part B).
- **Files Expected:** ~8-12 files (1 new type file in engine/, 3 cloud module modifications, compliance.rs enhancement, cloud_module.rs or finding.rs additions, tests)
- **Dependencies:** Existing `Finding` builder (engine/finding.rs), `compliance_for_owasp` / `compliance_for_cwe` (engine/compliance.rs), all 3 cloud modules (cloud/prowler.rs, cloud/scoutsuite.rs, cloud/kubescape.rs)
- **Risks:**
  - Changing evidence format is a breaking change for any downstream consumers parsing the pipe-delimited strings
  - Per-check CWE/OWASP mapping requires understanding each tool's check taxonomy (Prowler OCSF categories, Scout rule IDs, Kubescape control IDs)
  - Compliance mapping coverage may be incomplete for cloud-specific checks (CWE 1188 "Insecure Default Initialization" is generic)
- **Acceptance Criteria:**
  - A structured `CloudEvidence` type exists with builder methods, replacing raw string evidence in cloud findings
  - All 3 cloud modules (Prowler, ScoutSuite, Kubescape) use the new structured evidence builder
  - Per-check OWASP/CWE mapping replaces the blanket A05:2021/CWE-1188 on all findings
  - The `.with_compliance()` field is populated using existing compliance.rs lookup functions
  - All existing cloud module tests pass with no regressions
  - New unit tests cover the evidence builder and compliance extraction logic

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94.0, rustc 1.94.0, fmt 1.8.0, clippy 0.1.94 |
| Security tools | OK — semgrep 1.156.0, cargo-audit 0.22.1, cargo-deny 0.19.0, cargo-tarpaulin 0.35.2 |
| Hooks wired | OK — 2 PreToolUse + 6 Stop = 8 total |
| Config files | OK — .semgrep.yml, deny.toml, rustfmt.toml all present |
| gh CLI | OK — 2.87.3 |
| cargo check | OK — clean compilation |
| cargo test | OK — 654 passed (641 lib + 13 integration), 0 failed, 2 ignored |

### Human Confirmed
- [ ] Spec reviewed and confirmed

### Known Pitfalls (from RLM)
- DL-004: After any context continuation, re-read pipeline documents — pipeline doc is source of truth
- DL-016: MUST call bootstrap -> recall before writing code
- DL-002: Phase gates are strict — no skipping ahead

---

## Forge Briefing

Every phase command MUST call these Forge MCP tools:

1. **Bootstrap** — `bootstrap` for project context, architecture decisions, active patterns
2. **Recall** — `recall(agent="{role}", phase={N}, component_types=[...])` for targeted failures and lessons
3. **Learn** — `learn(summary, topic, component_types)` to record what was discovered
4. **Search** — `search-architecture-docs` before writing code

These are enforced by `enforce-completion.sh`. Skipping them blocks the conversation from ending.

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Architecture

**Approach:**
Two components — both in a single new file `src/engine/cloud_evidence.rs`:

1. **`CloudEvidence` struct** — Typed evidence builder for cloud modules. Fields: `provider` (`CloudProvider`), `service` (`String`), `check_id` (`Option<String>`), `resource` (`Option<String>`), `detail` (`HashMap<String, String>`). Implements `Display` to produce the existing pipe-delimited format (`"provider:aws | service:s3 | check_id:... | ..."`), so it feeds directly into `Finding::with_evidence(evidence.to_string())` with zero downstream breakage.

2. **`enrich_cloud_finding()` function** — Takes a `Finding` + service name, applies per-service OWASP/CWE mapping instead of blanket A05/CWE-1188, then auto-populates `Finding.compliance` via existing `compliance_for_owasp()` / `compliance_for_cwe()`. Service-to-OWASP/CWE mapping:
   - `iam` / `identitymanagement` → A01 (Broken Access Control) / CWE-287 (Improper Authentication)
   - `s3` / `storage` / `gcs` → A01 (Broken Access Control) / CWE-200 (Exposure of Sensitive Information)
   - `ec2` / `compute` / `vm` → A05 (Security Misconfiguration) / CWE-16 (Configuration)
   - `vpc` / `network` / `firewall` → A05 (Security Misconfiguration) / CWE-284 (Improper Access Control)
   - `cloudtrail` / `logging` / `monitoring` → A09 (Security Logging and Monitoring Failures) / CWE-778 (Insufficient Logging)
   - `kms` / `encryption` / `crypto` → A02 (Cryptographic Failures) / CWE-311 (Missing Encryption)
   - `rds` / `database` / `sql` → A05 (Security Misconfiguration) / CWE-16 (Configuration)
   - Kubernetes controls (by control ID prefix) → A05 / CWE-16 with RBAC controls mapping to A01/CWE-287
   - Default fallback → A05 (Security Misconfiguration) / CWE-1188 (preserves existing behavior)

**File Manifest:**
| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/cloud_evidence.rs` | Create | `CloudEvidence` struct + builder + `Display` impl + `enrich_cloud_finding()` + `cloud_service_owasp_cwe()` mapping |
| 2 | `src/engine/mod.rs` | Modify | Add `pub mod cloud_evidence` under `#[cfg(feature = "cloud")]` gate |
| 3 | `src/cloud/prowler.rs` | Modify | Use `CloudEvidence::new()` + `enrich_cloud_finding()` in `finding_from_ocsf_value()` |
| 4 | `src/cloud/scoutsuite.rs` | Modify | Use `CloudEvidence::new()` + `enrich_cloud_finding()` in `parse_scoutsuite_json()` |
| 5 | `src/cloud/kubescape.rs` | Modify | Use `CloudEvidence::new()` + `enrich_cloud_finding()` in `parse_kubescape_json()` |
| 6 | `src/engine/compliance.rs` | Modify | Add CWE mappings for cloud-specific IDs (16, 200, 284, 778) |

**Testing Strategy:**
- Unit tests for `CloudEvidence` builder: all fields, optional fields, `Display` output format
- Unit tests for `cloud_service_owasp_cwe()`: all known service mappings + unknown fallback
- Unit tests for `enrich_cloud_finding()`: verify OWASP/CWE set, compliance populated, round-trip
- Update existing cloud module parser tests to verify new evidence format + compliance population
- Verify existing tests pass unchanged (backward-compatible `Display` output)

**Regression Test Plan:**
| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `test_cloud_evidence_builder_all_fields` | `src/engine/cloud_evidence.rs` | All fields set correctly via builder |
| 2 | `test_cloud_evidence_display_format` | `src/engine/cloud_evidence.rs` | Display output matches pipe-delimited format |
| 3 | `test_cloud_evidence_optional_fields_omitted` | `src/engine/cloud_evidence.rs` | Optional fields not in Display when None |
| 4 | `test_cloud_service_owasp_cwe_known_services` | `src/engine/cloud_evidence.rs` | All mapped services return correct OWASP/CWE |
| 5 | `test_cloud_service_owasp_cwe_unknown_fallback` | `src/engine/cloud_evidence.rs` | Unknown service falls back to A05/CWE-1188 |
| 6 | `test_enrich_cloud_finding_sets_compliance` | `src/engine/cloud_evidence.rs` | Compliance field populated from OWASP/CWE lookups |
| 7 | `test_enrich_cloud_finding_iam_service` | `src/engine/cloud_evidence.rs` | IAM service → A01/CWE-287 + compliance controls |
| 8 | `test_prowler_findings_have_per_service_compliance` | `src/cloud/prowler.rs` | Prowler parser now produces per-service OWASP/CWE |
| 9 | `test_scoutsuite_findings_have_per_service_compliance` | `src/cloud/scoutsuite.rs` | Scout parser produces per-service OWASP/CWE |
| 10 | `test_kubescape_findings_have_compliance` | `src/cloud/kubescape.rs` | Kubescape parser produces compliance field |
| 11 | `test_compliance_cwe_cloud_ids` | `src/engine/compliance.rs` | New cloud CWE IDs (16, 200, 284, 778) have mappings |

**Architectural Decisions:**
- `CloudEvidence` is a builder that produces a `String` via `Display`, NOT a new field on `Finding`. This avoids breaking the 77+ module ecosystem that uses `Finding.evidence: Option<String>`. Cloud modules get type safety; the rest of the system is untouched.
- Service-to-OWASP/CWE mapping is a simple match statement, not a config file or database. The mapping is small (~15 entries), rarely changes, and benefits from compile-time exhaustiveness checking.
- `enrich_cloud_finding()` consumes and returns `Finding` (builder pattern) rather than taking `&mut Finding`, matching the existing builder chain style.

### Deferred Items
- None

### Issues Found
- None

### Knowledge Recorded
- **Lessons:** 1 (architecture decision recorded)
- **Failures:** 0
- **Component Types:** engine, cloud, finding, compliance

### Human Confirmed
- [ ] Design reviewed and confirmed

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Files Created
| File | Path |
|------|------|
| Cloud evidence builder + enrichment | `src/engine/cloud_evidence.rs` |

### Files Modified
| File | Change |
|------|--------|
| `src/engine/mod.rs` | Added `pub mod cloud_evidence` under `#[cfg(feature = "cloud")]` |
| `src/engine/compliance.rs` | Added CWE 16, 284, 778 mappings + 1 new test |
| `src/cloud/prowler.rs` | Use `CloudEvidence` + `enrich_cloud_finding()`, updated test assertions |
| `src/cloud/scoutsuite.rs` | Use `CloudEvidence` + `enrich_cloud_finding()`, removed dead `evidence_tag`, updated test assertions |
| `src/cloud/kubescape.rs` | Use `CloudEvidence` + `enrich_cloud_finding()`, updated test assertions |

### Quality Gates
- **cargo fmt --check:** Pass
- **cargo clippy:** Pass — 0 warnings
- **cargo test (cloud):** Pass — 714 passed, 0 failed, 2 ignored
- **cargo test (default):** Pass — 642 passed, 0 failed, 2 ignored

### Notes
- Followed design exactly
- Merged match arms per clippy `match_same_arms` lint (K8s RBAC into IAM arm, K8s network into VPC arm, K8s workload/DB into compute arm)
- Removed dead `ScoutProvider::evidence_tag()` since `CloudEvidence` now carries the provider
- CWE-200 already existed in compliance.rs — no duplicate needed
- 1 fix iteration: clippy caught duplicate CWE-200 arm, dead code, needless borrows

### Knowledge Recorded
- **Lessons:** 1
- **Failures:** 0
- **Component Types:** engine, cloud, finding, compliance

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

### Entry Verification (independently run)
- **cargo fmt --check:** Pass
- **cargo clippy:** Pass — 0 warnings
- **cargo test (cloud):** Pass — 714 passed, 0 failed, 2 ignored
- **```ignore check:** Pass — 0 found
- **#[ignore] check:** Pass — 0 in changed files
- **#[allow] workaround check:** Pass — 0 in changed files

### Code Review
- **Standards Compliance:** Pass — all public items documented, `#[must_use]` on builders, `BTreeMap` for deterministic output
- **Workaround Detection:** Pass — no workarounds found
- **Security Review (semgrep):** Pass — 0 findings across 5 changed files

### Test Results
- **Cargo Test Count (cloud):** 714 passed, 0 failed
- **Cargo Test Count (default):** 642 passed, 0 failed
- **Doctest Count:** 2 passed (cloud_evidence module example)
- **Coverage:** Not measured (no change in coverage infra)

### Regression Test Plan Compliance
1. `test_cloud_evidence_builder_all_fields` — implemented, passing
2. `test_cloud_evidence_display_format` — implemented, passing
3. `test_cloud_evidence_optional_fields_omitted` — implemented, passing
4. `test_cloud_service_owasp_cwe_known_services` — implemented, passing
5. `test_cloud_service_owasp_cwe_unknown_fallback` — implemented, passing
6. `test_enrich_cloud_finding_sets_compliance` — implemented, passing
7. `test_enrich_cloud_finding_iam_service` — implemented, passing
8. `test_parse_prowler_ocsf_array` (updated assertions) — passing
9. `test_parse_scoutsuite_json_extracts_findings` (updated assertions) — passing
10. `test_parse_kubescape_json_extracts_failed_controls` (updated assertions) — passing
11. `test_compliance_cwe_cloud_ids` — implemented, passing
- **Bonus tests:** `test_cloud_evidence_detail_sorted`, `test_cloud_service_owasp_cwe_case_insensitive`, `test_enrich_cloud_finding_logging_service`, `test_enrich_cloud_finding_unknown_service_gets_fallback_compliance`

### Knowledge Recorded
- **Lessons:** 0 (no new lessons from validation)
- **Failures:** 0
- **Component Types:** engine, cloud, finding, compliance

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

- **Cargo Test Full Suite (cloud):** Pass
- **Cargo Test Count (cloud):** 714 passed, 0 failed (identical to Phase 3 and Phase 4)
- **Cargo Test Regressions:** None — 714 cloud, 642 default, identical across all phases
- **Integration Tests:** Pass — 13 passed
- **Doctests:** Pass — 2 passed (cloud), 13 passed (default)

### Knowledge Recorded
- **Lessons:** 0
- **Failures:** 0
- **Component Types:** engine, cloud, finding, compliance

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-15
**Completed:** 2026-04-15

- **Documentation Updated:** CHANGELOG.md (WORK-154 entry), docs/architecture/cloud.md (Finding normalization section)
- **Changelog Updated:** Yes
- **Pipeline Doc Archived:** Yes — moved to `completed/`

### Self-Reflection
1. Did any phase use workarounds? No — all implementations are idiomatic Rust with proper types.
2. Was the implementation the cleanest version? Yes — `CloudEvidence` as a builder-to-string avoids breaking changes, `BTreeMap` ensures deterministic output, merged match arms per clippy.
3. Would a senior developer approve? Yes — clean separation of concerns, backward-compatible design, comprehensive test coverage.

### After-Action Review (MANDATORY)
- **Generation Trace Saved:** Yes
- **Lessons Recorded:** 2 (design + implementation)
- **Failures Recorded:** 0
- **Component Types Tagged:** engine, cloud, finding, compliance
