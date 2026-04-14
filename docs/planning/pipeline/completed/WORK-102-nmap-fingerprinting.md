# Work Pipeline: Service Fingerprinting + nmap InfraModule Migration

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | COMPLETE |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /complete |
| **Next Step** | — (pipeline archived) |
| **Blocked** | No |
| **Forge Ticket** | #102 |
| **Forge Ticket ID** | 019d8d82-a0bd-70a0-b0e0-fd39052b0fef |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Completed:** 2026-04-14

### Work Spec

- **Title:** WORK-102 — Service fingerprinting + nmap InfraModule migration
- **Type:** Infrastructure
- **Scope:** Extract the existing nmap XML parser into a pure function producing `ServiceFingerprint` records, register a new `infra::NmapModule` (InfraModule) that publishes those fingerprints to `shared_data` for downstream CVE matching, and refactor the existing DAST `tools::NmapModule` to reuse the shared parser. The DAST wrapper stays in place for backwards compat until WORK-105's unified `assess` command lands.
- **Files:**
  - NEW `src/engine/service_fingerprint.rs` (not gated — pure data type)
  - NEW `src/infra/nmap.rs` (gated)
  - MODIFY `src/engine/mod.rs` — add `pub mod service_fingerprint;`
  - MODIFY `src/infra/mod.rs` — register NmapModule
  - MODIFY `src/tools/nmap.rs` — refactor to reuse the extracted parser
  - MODIFY `src/prelude.rs` — re-export ServiceFingerprint
- **Dependencies:** WORK-101 (infra foundation, shipped). No new crate deps.
- **Risks:**
  - Refactoring `tools/nmap.rs` could change existing DAST behavior. Mitigation: keep the public `ScanModule` trait impl intact, only swap the internal parse call. Existing tests must still pass.
  - Publishing `Vec<ServiceFingerprint>` through `SharedData<HashMap<String, Vec<String>>>` requires JSON-string encoding. Documented via `SHARED_KEY_FINGERPRINTS` constant + a helper `publish_fingerprints()` / `read_fingerprints()` pair so callers don't hand-roll JSON.
- **Acceptance:**
  - Default build: all existing DAST nmap tests still pass unchanged.
  - `--features infra`: new nmap InfraModule is registered and its test suite passes.
  - Pure `parse_nmap_xml_fingerprints(xml) -> Vec<ServiceFingerprint>` replaces the duplicated parser logic in both modules.
  - `ServiceFingerprint` derives `Debug + Clone + Serialize + Deserialize`; field names are part of the wire format.
  - `build_cpe(vendor, product, version)` produces `cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*`.
  - `cargo fmt`, `cargo clippy -- -D warnings` (default + infra), `cargo test` (default + infra), `cargo deny check` all green.

### Known Pitfalls
- **DL-004** re-read pipeline doc after context continuation.
- `SharedData` stores `Vec<String>` — not arbitrary types. Encode fingerprints as JSON strings on publish, decode on read. Provide helpers.
- Existing DAST nmap severity classification + outdated-version detection must remain in the DAST wrapper (not the shared parser) — those are DAST presentation concerns, not fingerprint data.

---

## Forge Briefing
Bootstrap + recall + learn + search-architecture-docs mandated each phase.

---

## Phase 2: Design
**Status:** PASS
**Completed:** 2026-04-14

### Approach

The fingerprint parser currently lives inline in `tools/nmap.rs:parse_nmap_xml` (returns `Vec<Finding>` with presentation mixed in). Split along the data/presentation seam:

- **Data**: `ServiceFingerprint { port, protocol, service_name, product, version, cpe }`. Pure parser `parse_nmap_xml_fingerprints(xml: &str) -> Vec<ServiceFingerprint>`. CPE builder `build_cpe(vendor, product, version) -> String`. Shared-data helpers `publish_fingerprints(&SharedData, &[ServiceFingerprint])` and `read_fingerprints(&SharedData) -> Vec<ServiceFingerprint>`.

- **Presentation**: DAST `tools::NmapModule` calls the pure parser then maps fingerprints to Findings with severity classification + outdated-version checks. No behavior change for DAST users.

- **Infra**: new `infra::NmapModule` calls the pure parser, emits `ScanEvent::Custom { kind: "infra.nmap.fingerprints", data: ... }` for observability, publishes fingerprints to `shared_data`, and emits one Info Finding per open port (lightweight — the DAST version does richer classification and this version stays minimal since CVE correlation is coming in WORK-103).

### File Manifest

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/service_fingerprint.rs` | Create | `ServiceFingerprint` struct + `parse_nmap_xml_fingerprints` + `build_cpe` + shared-data helpers + tests |
| 2 | `src/engine/mod.rs` | Modify | `pub mod service_fingerprint;` (not gated) |
| 3 | `src/infra/nmap.rs` | Create (gated) | `NmapModule` InfraModule + tests |
| 4 | `src/infra/mod.rs` | Modify | Register NmapModule |
| 5 | `src/tools/nmap.rs` | Modify | Refactor to use the shared parser; keep severity/outdated logic local |
| 6 | `src/prelude.rs` | Modify | Re-export `ServiceFingerprint` |

### Type Changes

```rust
// src/engine/service_fingerprint.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

pub const SHARED_KEY_FINGERPRINTS: &str = "infra.service_fingerprints";

pub fn parse_nmap_xml_fingerprints(xml: &str) -> Vec<ServiceFingerprint>;
pub fn build_cpe(vendor: &str, product: &str, version: &str) -> String;
pub fn publish_fingerprints(shared: &SharedData, fingerprints: &[ServiceFingerprint]);
pub fn read_fingerprints(shared: &SharedData) -> Vec<ServiceFingerprint>;
```

### Testing Strategy
- Parser on well-formed nmap XML → multiple variants.
- Parser on empty / malformed input → empty vec (defensive).
- CPE builder round-trip (standard cases + empty vendor fallback).
- Publish/read round-trip via real `SharedData`.
- DAST nmap wrapper tests unchanged — verify refactor didn't regress.
- Infra nmap module construction + trait methods.

### Regression Test Plan

| # | Test | File | Verifies |
|---|------|------|----------|
| 1 | `test_parse_nmap_xml_fingerprints_multi_port` | `service_fingerprint.rs` | 3 open ports → 3 fingerprints with product/version |
| 2 | `test_parse_nmap_xml_fingerprints_skips_closed` | `service_fingerprint.rs` | Closed ports excluded |
| 3 | `test_parse_nmap_xml_fingerprints_empty` | `service_fingerprint.rs` | Empty input → empty vec |
| 4 | `test_parse_nmap_xml_fingerprints_missing_fields` | `service_fingerprint.rs` | Port with no product/version still parses |
| 5 | `test_build_cpe_standard` | `service_fingerprint.rs` | nginx 1.18 → cpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:* |
| 6 | `test_build_cpe_different_vendor_product` | `service_fingerprint.rs` | different vendor/product components |
| 7 | `test_publish_and_read_fingerprints_round_trip` | `service_fingerprint.rs` | SharedData JSON round-trip |
| 8 | `test_read_fingerprints_empty` | `service_fingerprint.rs` | Empty SharedData → empty vec |
| 9 | `test_dast_nmap_still_parses` | `tools/nmap.rs` | Existing parser test passes after refactor |
| 10 | `test_infra_nmap_module_metadata` | `infra/nmap.rs` | name/id/category/requires_external_tool |
| 11 | `test_infra_nmap_publishes_fingerprints` | `infra/nmap.rs` | Given mock XML output, shared_data gets populated (use injected parser) |

### Deferred
- CVE matching against published fingerprints → WORK-103
- Removing the DAST nmap wrapper → WORK-105 (when `assess` subsumes it)
- Live nmap execution in tests → skipped (needs nmap binary); the infra test uses the pure parser + SharedData write directly

---

## Phase 3: Implement
**Status:** PASS
**Completed:** 2026-04-14

### Files Created
| File | Purpose |
|------|---------|
| `src/engine/service_fingerprint.rs` | `ServiceFingerprint` + pure parser + CPE builder + SharedData helpers (10 tests) |
| `src/infra/nmap.rs` | `NmapModule` (InfraModule) + `nmap_target_arg` + `fingerprints_to_findings` (4 tests) |

### Files Modified
| File | Change |
|------|--------|
| `src/engine/mod.rs` | `pub mod service_fingerprint;` (not gated) |
| `src/infra/mod.rs` | Register `NmapModule` alongside `TcpProbeModule` |
| `src/tools/nmap.rs` | Refactored to call `parse_nmap_xml_fingerprints`; removed ~35 lines of duplicated XML parsing + dead `extract_xml_attr` |
| `src/prelude.rs` | Re-export `ServiceFingerprint` (not gated) |

### Quality Gates
- `cargo fmt --check`: PASS
- `cargo clippy -- -D warnings` (default): PASS
- `cargo clippy --features infra -- -D warnings`: PASS (after 1 fix iteration: `match_same_arms` on Host/Endpoint arms in `nmap_target_arg` — combined with `|` pattern)
- `cargo test`: PASS — **498 passed** (+10 vs WORK-101 baseline of 488; all from new `service_fingerprint` tests, which are not feature-gated)
- `cargo test --features infra`: PASS — **526 passed** (+14 vs WORK-101's 512; 10 in service_fingerprint + 4 in infra/nmap)
- `cargo deny check`: PASS (still clean, no new deps)

### Notes
- **One clippy fix iteration:** `nmap_target_arg` had identical match arms for `Host` and `Endpoint { host, .. }`. Combined with `|` pattern binding the `host` field — clippy's recommended idiom.
- **DAST nmap behavior preserved.** The existing `tools/nmap.rs` tests (`test_parse_nmap_xml`, `test_parse_nmap_xml_empty`) still pass unchanged. Severity classification + outdated-version checks remain in the DAST wrapper as before.
- **Pure parser shares zero state** between DAST and infra callers. Each reads the nmap XML output and produces `Vec<ServiceFingerprint>`; the two modules then diverge on presentation.
- **Fingerprint → SharedData** uses JSON encoding because `SharedData` stores `Vec<String>`. Helper pair (`publish_fingerprints` / `read_fingerprints`) keeps callers from hand-rolling that serialization. WORK-103 will consume via `read_fingerprints`.

### Regression Test Plan — 11/11 (target met, +1 bonus)

| # | Test | File | Verified |
|---|------|------|----------|
| 1 | `test_parse_nmap_xml_fingerprints_multi_port` | `service_fingerprint.rs` | YES |
| 2 | `test_parse_nmap_xml_fingerprints_skips_closed` | `service_fingerprint.rs` | YES |
| 3 | `test_parse_nmap_xml_fingerprints_empty` | `service_fingerprint.rs` | YES |
| 4 | `test_parse_nmap_xml_fingerprints_missing_fields` | `service_fingerprint.rs` | YES |
| 5 | `test_build_cpe_standard` | `service_fingerprint.rs` | YES |
| 6 | `test_build_cpe_different_vendor_product` | `service_fingerprint.rs` | YES |
| 7 | `test_build_cpe_blanks_become_wildcards` | `service_fingerprint.rs` | YES (bonus) |
| 8 | `test_publish_and_read_fingerprints_round_trip` | `service_fingerprint.rs` | YES |
| 9 | `test_read_fingerprints_empty` | `service_fingerprint.rs` | YES |
| 10 | `test_publish_empty_is_noop` | `service_fingerprint.rs` | YES |
| 11 | `test_infra_nmap_module_metadata` | `infra/nmap.rs` | YES |
| 12 | `test_nmap_target_arg_for_each_variant` | `infra/nmap.rs` | YES |
| 13 | `test_fingerprints_to_findings_emits_one_per_fingerprint` | `infra/nmap.rs` | YES |
| 14 | `test_infra_nmap_publishes_fingerprints_via_shared_data` | `infra/nmap.rs` | YES |

---

## Phase 4: Validate
**Status:** PASS
**Completed:** 2026-04-14

### Entry Verification (re-run)

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS (exit 0) |
| `cargo clippy -- -D warnings` (default) | PASS |
| `cargo clippy --features infra -- -D warnings` | PASS |
| `cargo test` (default) | PASS — 498 passed, 0 failed |
| `cargo test --features infra` | PASS — 526 passed, 0 failed |
| `cargo deny check` | PASS |
| No new `#[allow]` / `#[ignore]` / ``` ```ignore ``` | CLEAN |

### Code Review
- All new `pub` items have `///` docs; `//!` module doc on `service_fingerprint.rs`.
- `# Errors` not needed — the only fallible public functions are `publish_fingerprints` / `read_fingerprints` which are infallible by design (serde errors are swallowed into log-and-continue, matching the observability contract).
- No `unwrap()` / `expect()` in library code; tests use `.expect()` per repo convention.
- `ServiceFingerprint` fields use `Option<String>` for absent data — idiomatic, avoids empty-string sentinels.
- `NmapModule` uses `&'static str` returns (matches the WORK-101 lesson for trait methods returning string literals).
- DAST nmap refactor is behavior-preserving — existing tests pass unchanged.

### Knowledge Recorded
- Lessons: 1 (validation clean)
- Failures: 0
- Component Types: engine, infra, tools, testing

---

## Phase 5: Verify
**Status:** PASS

- `cargo test`: 498 / 0 (identical to Phase 4)
- `cargo test --features infra`: 526 / 0 (identical)
- **Zero regressions vs Phase 4.**

---

## Phase 6: Complete
**Status:** PASS

### Documentation
- `CHANGELOG.md` updated with #102 bullet.
- Architecture decision `engine.service-fingerprint` recorded in Forge.
- `docs/architecture/engine.md` — added "Service fingerprints" subsection.

### Self-Reflection
1. **Workarounds?** None. One clippy fix was the idiomatic `Host | Endpoint { host, .. }` pattern, not a suppression.
2. **Cleanest version?** Yes. The extraction was motivated by duplication WORK-103 would have introduced anyway — WORK-102 pays the refactoring cost now, at the right time.
3. **Senior dev approval?** Pure-function parser, JSON-encoded SharedData publication with helper pair (not hand-rolled), CPE construction as a separate testable function, zero behavior change to the DAST wrapper (verified by unchanged tests).

### Final Checklist
- [x] Phases 1–5 PASS
- [x] All quality gates green across default + infra feature sets
- [x] bootstrap + recall + learn + architecture-set + save-generation-trace called
- [x] CHANGELOG + engine architecture doc updated
- [x] Pipeline archived to `completed/`
- [x] Ticket #102 closed as Done
