# Work Pipeline: OSV sibling backend (`OsvCveLookup`) for `CveLookup` trait

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Complete (archived) |
| **Created** | 2026-04-14 |
| **Last Updated** | 2026-04-14 |
| **Last Command** | /design |
| **Next Step** | Run `/implement` for Phase 3 (after design completes) |
| **Blocked** | No |
| **Forge Ticket** | #106 |
| **Forge Ticket ID** | 019d8de7-fc2b-71b4-b8a1-bf6daa856b5a |

---

## Phase 1: Plan
**Command:** /work
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Work Spec
- **Title:** OSV sibling backend (`OsvCveLookup`) for `CveLookup` trait — WORK-103c
- **Type:** Infrastructure
- **Scope:** Add a second production `CveLookup` impl that talks to the [OSV.dev](https://osv.dev) v1 query API. OSV uses package coordinates (ecosystem + name + version) rather than CPE, so the lookup carries an internal CPE → (ecosystem, package, version) translator covering high-value language-ecosystem CPEs (npm, PyPI, Maven, RubyGems, NuGet, Go modules, crates.io, Packagist). Unknown CPEs return empty (cached negatively). New `CveBackendKind::Osv` variant; OSV uses no API key but is rate-limited to ~25 QPS by OSV's fair-use policy. Reuses `FsCache`, the `governor` rate limiter, and the `build_cve_lookup` factory pattern from WORK-103b.
- **Files Expected:** ~5 new + 4 modified (see Phase 2 manifest)
- **Dependencies:** WORK-103b (merged) — supplies `FsCache`, `governor` setup, `httpmock` dev-dep, factory pattern. No new crate deps.
- **Risks:**
  - Lossy CPE → ecosystem translation; mitigated by `warn!` log on unmapped CPEs
  - OSV "fair use" rate limit (~25 QPS) is undocumented as hard cap; conservative limiter at 10 RPS
  - OSV severity field can be empty or `CVSS_V3` only; map missing → `Severity::Info`
  - No live network in CI — fully covered by httpmock fixtures
- **Acceptance Criteria:** see ticket #106 description.

### Preflight Results
| Check | Status |
|-------|--------|
| Forge MCP | OK |
| Toolchain | OK — cargo 1.94, rustc 1.94, clippy 0.1.94, fmt 1.8.0 |
| Security tools | OK — semgrep 1.156, cargo-audit 0.22.1, cargo-deny 0.19.0, cargo-tarpaulin 0.35.2 |
| Hooks wired | OK — 8/8 |
| `cargo check --features infra` | OK |
| `cargo test --features infra` | OK — 619 passing |

### Known Pitfalls (from RLM)
- DL-016-P1 / DL-004-P1 — bootstrap → recall → ticket before code; re-read pipeline doc on context continuation. Already handled by this command flow.
- WORK-103b learnings (just recorded): separate reqwest client per backend, `base_url` config field is the test injection seam, negative caching is load-bearing, env-var precedence over config for keys (N/A for OSV — keyless).

---

## Phase 2: Design
**Command:** /design
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Architecture

**Approach:** Mirror the WORK-103b shape — `OsvCveLookup` owns its own `reqwest::Client`, a `governor::RateLimiter` (conservative 10 RPS, well under OSV's documented ~25 QPS fair-use cap), and an `FsCache` rooted at a separate per-backend directory (`scorchkit/cve-osv/` vs WORK-103b's `cve/`). The trait shape is unchanged — `query(cpe: &str)` — so the orchestrator and `CveMatchModule` plug in without modification.

The hard problem unique to OSV is that its API takes package coordinates (`{"package": {"name", "ecosystem"}, "version"}`), not CPE. A pure `infra::cpe_purl::cpe_to_package(&str) -> Option<PackageCoord>` translator carries an embedded static mapping table for ≥30 high-value language-ecosystem CPEs (npm, PyPI, Maven, Go, crates.io, RubyGems, NuGet, Packagist). Unmapped CPEs (system software like `nginx`, `openssh`, `openssl`) return `None`; the lookup returns `Ok(empty)` and emits one `warn!` so operators can see what they're missing.

OSV severity comes back as a CVSS v3.x **vector string** (`CVSS:3.1/AV:N/AC:L/...`), not a numeric base score. To produce a `Severity` variant we need to compute the base score from the vector. New `engine::cve::cvss_v3_base_score(vector: &str) -> Option<f64>` lives alongside the existing `severity_from_cvss(score)` mapper — placed in `engine::cve` (not `infra::cve_osv`) because it's data-shape logic that any future backend could reuse and because `engine::cve` is the canonical home for CVE data semantics.

The factory dispatch in `infra::cve_lookup::build_cve_lookup` extends to a fourth arm (`CveBackendKind::Osv`). No changes ripple beyond that — `Engine::infra_scan` already consults the factory and appends `CveMatchModule` automatically when a backend is configured.

**File Manifest:**

| # | File | Action | Purpose |
|---|------|--------|---------|
| 1 | `src/engine/cve.rs` | Modify | Add `cvss_v3_base_score(vector: &str) -> Option<f64>` pure function with full v3.x base-score formula |
| 2 | `src/infra/cpe_purl.rs` | Create | Pure `cpe_to_package(cpe: &str) -> Option<PackageCoord>`; embedded static `(vendor, product) → (ecosystem, package_name)` table covering ≥30 CPEs across 8 ecosystems |
| 3 | `src/infra/cve_osv.rs` | Create | `OsvCveLookup` impl of `CveLookup` — POST to `/v1/query`, OSV response parser, embedded reqwest::Client + governor limiter + FsCache |
| 4 | `src/config/cve.rs` | Modify | Add `Osv` variant to `CveBackendKind`; new `pub osv: OsvConfig` field on `CveConfig`; new `OsvConfig { base_url, cache_dir, cache_ttl_secs, max_rps }` |
| 5 | `src/infra/cve_lookup.rs` | Modify | Extend `match` to dispatch `Osv → OsvCveLookup::from_config(&cfg.cve.osv)` |
| 6 | `src/infra/mod.rs` | Modify | `pub mod cve_osv; pub mod cpe_purl;` |
| 7 | `src/prelude.rs` | Modify | Re-export `OsvCveLookup`, `OsvConfig`, `cpe_to_package` |
| 8 | `tests/cve_osv.rs` | Create | httpmock integration tests + `#[ignore]`-gated live smoke against api.osv.dev |
| 9 | `tests/fixtures/osv/express_query_response.json` | Create | Recorded OSV v1 response for npm:express with a real CVE |
| 10 | `tests/fixtures/osv/empty_response.json` | Create | Empty `{"vulns": []}` response for negative-cache test |
| 11 | `docs/modules/cve-osv.md` | Create | Operator-facing backend reference: config block, ecosystem coverage table, troubleshooting, comparison vs NVD |
| 12 | `docs/architecture/engine.md` | Modify | Update CVE correlation section to mention OSV as a sibling backend behind the same trait |
| 13 | `CHANGELOG.md` | Modify | Add WORK-103c bullet under `[Unreleased] / Added` |

**Type and Trait Changes:**

- New types:
  - `engine::cve::cvss_v3_base_score(vector: &str) -> Option<f64>` — pure function
  - `infra::cpe_purl::PackageCoord { ecosystem: &'static str, name: String, version: String }` — `Debug`, `Clone`, `PartialEq`
  - `infra::cpe_purl::cpe_to_package(cpe: &str) -> Option<PackageCoord>` — pure
  - `infra::cve_osv::OsvCveLookup` — pub struct
  - `config::cve::OsvConfig { base_url: Option<String>, cache_dir: Option<PathBuf>, cache_ttl_secs: u64, max_rps: u32 }` — `Debug`, `Clone`, `Default`, `Serialize`, `Deserialize`
  - `config::cve::CveBackendKind::Osv` — new variant
- No changes to `CveLookup` trait, `CveRecord`, `CveMatchModule`, `MockCveLookup`, `NvdCveLookup`, or `FsCache`. The trait shape is right and stable across both production backends.
- No new `ScorchError` variants. `ScorchError::Http`, `ScorchError::Json`, and `ScorchError::Config` cover every failure mode; OSV unmappable CPE is *not* an error (returns `Ok(empty)`).

**Error Handling Strategy:**

| Failure | Outcome |
|---------|---------|
| `cpe_to_package` returns `None` (unmapped CPE) | `warn!("osv: no package mapping for {cpe}; skipping")`; cache `Ok(empty)`; return `Ok(empty)` — *not* an error |
| OSV HTTP timeout / 5xx | `ScorchError::Http`; per-fingerprint failure logged by `CveMatchModule` and skipped; scan continues |
| OSV 429 (rate-limited) | `ScorchError::Config`; the conservative 10 RPS limiter should prevent this in practice |
| Response missing `vulns` | Treated as `{"vulns": []}` (serde `default`) |
| Response field shape mismatch | `ScorchError::Json` |
| CVSS vector unparseable | `cvss_v3_base_score` returns `None`; severity → `Severity::Info`; record still emitted with the OSV summary |
| FsCache failures | Identical to WORK-103b — best-effort, log-and-continue, never abort |

**Architectural Decisions:**

1. **Embedded static mapping table for CPE → ecosystem.** ~30-50 entries, version-stable, deterministic. External file would add load logic + error handling for one-time data and create a runtime-config concern that doesn't need to exist. Operators who need broader coverage send a PR adding entries — a clear contribution path beats a fragile config file.
2. **`cvss_v3_base_score` in `engine::cve`, not `infra::cve_osv`.** It's data-shape logic; any future backend that produces vectors instead of scores (CSAF, GitHub Advisory Database when consumed directly, MITRE CVE list) can reuse it. `engine::cve` is the canonical home for CVE data semantics; `severity_from_cvss(score)` is already there.
3. **Conservative 10 RPS limiter (vs OSV's documented ~25 QPS).** Leaves headroom for OSV's hidden adaptive throttling and avoids tripping soft bans. Configurable via `OsvConfig.max_rps` for operators with shared-cache deployments who can negotiate higher limits with OSV directly.
4. **Per-backend cache directory** — default `<cache_root>/scorchkit/cve-osv/`. Separate from NVD's `<cache_root>/scorchkit/cve/`. Rationale: a wholesale cache flush of one backend should not affect the other; the two backends return DIFFERENT data for the same CPE (NVD knows about nginx, OSV doesn't), so co-mingling cache files would risk cross-contamination if the cache key were ever loosened.
5. **`PackageCoord.ecosystem` is `&'static str`.** The table lives in the binary; ecosystem names are a finite, stable set per OSV spec ([`OSV ecosystems`](https://ossf.github.io/osv-schema/#defined-ecosystems)). `&'static` makes invalid-state-by-construction impossible.
6. **No client-side version-range matching.** OSV's `affected` array carries version-range constraints (`semver`, `ecosystem-specific`); we pass the exact version in the query and trust OSV's server-side filtering. If OSV returns a vuln, it applies to our version. Reimplementing version-range arithmetic per ecosystem is a separate, large pipeline and would duplicate logic that already lives in OSV.
7. **Multi-backend aggregation is out of scope.** `CveBackendKind` selects ONE backend at a time. Operators who want both NVD and OSV today must construct two `CveMatchModule`s manually. A future `CveBackendKind::Composite` (or `MultiCveLookup` aggregator) would handle dedup-by-CVE-ID across backends — explicitly deferred. Documented in `docs/modules/cve-osv.md`.
8. **No API key support.** OSV is keyless and intentionally so (per their FAQ). No `api_key` field on `OsvConfig`. If OSV ever adds API keys, that's a separate config addition.

**Testing Strategy:**

- **Unit tests** in `src/engine/cve.rs`:
  - `cvss_v3_base_score` for known vectors: critical (Log4Shell-style 9.8/10), high, medium, low, scope-changed, missing metric → `None`, malformed prefix → `None`
- **Unit tests** in `src/infra/cpe_purl.rs`:
  - Maps known CPEs (express → npm:express, log4j → Maven:org.apache.logging.log4j:log4j-core, django → PyPI:django, rails → RubyGems:rails)
  - Returns `None` for system-software CPEs (nginx, openssh)
  - Returns `None` for malformed CPE strings
  - Version field is preserved from CPE field 6
  - Table size invariant: ≥30 entries
- **Unit tests** in `src/infra/cve_osv.rs`:
  - Parse a recorded OSV response into `Vec<CveRecord>` — covers id, summary, severity vector, references
  - Empty response → empty Vec, no error
  - Missing severity → `Severity::Info`, `cvss_score = None`
  - Quota construction with default `max_rps = 10`
- **Unit tests** in `src/config/cve.rs`:
  - `OsvConfig::default()` — `cache_ttl_secs = 86400`, `max_rps = 10`, no `base_url`/`cache_dir`
  - `[cve.osv]` TOML round-trip
  - `CveBackendKind::Osv` serialises as `"osv"`
- **Unit tests** in `src/infra/cve_lookup.rs`:
  - `build_cve_lookup_osv_returns_osv` — backend = "osv" yields `Some(OsvCveLookup)`
- **Integration test** `tests/cve_osv.rs`:
  - httpmock returns `express_query_response.json` for a POST to `/v1/query`; assert findings count + IDs
  - Cache hit on second query (httpmock served exactly 1 request)
  - Empty-response variant (negative cache); second call serves zero requests
  - Unmapped CPE (e.g. nginx CPE) → no httpmock request issued, `Ok(empty)` returned
- **Live smoke** (`#[ignore]`-gated):
  - Hit real api.osv.dev with `npm:express:4.17.0` (a known-vulnerable version), assert ≥1 vuln returned

**Regression Test Plan:**

| # | Test Name | File | Verifies |
|---|-----------|------|----------|
| 1 | `cvss_v3_base_score_critical` | `src/engine/cve.rs` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8 |
| 2 | `cvss_v3_base_score_high_scope_changed` | `src/engine/cve.rs` | Scope-changed formula path produces correct score |
| 3 | `cvss_v3_base_score_medium` | `src/engine/cve.rs` | A medium-severity vector parses correctly |
| 4 | `cvss_v3_base_score_low` | `src/engine/cve.rs` | A low-severity vector parses correctly |
| 5 | `cvss_v3_base_score_missing_metric_returns_none` | `src/engine/cve.rs` | Vector missing `A:` returns `None` |
| 6 | `cvss_v3_base_score_malformed_returns_none` | `src/engine/cve.rs` | Garbage input returns `None` |
| 7 | `cpe_to_package_npm_express` | `src/infra/cpe_purl.rs` | nginx-style CPE for express → npm:express with version |
| 8 | `cpe_to_package_maven_log4j` | `src/infra/cpe_purl.rs` | apache:log4j → Maven:org.apache.logging.log4j:log4j-core |
| 9 | `cpe_to_package_pypi_django` | `src/infra/cpe_purl.rs` | djangoproject:django → PyPI:django |
| 10 | `cpe_to_package_rubygems_rails` | `src/infra/cpe_purl.rs` | rails:rails → RubyGems:rails |
| 11 | `cpe_to_package_unmapped_returns_none` | `src/infra/cpe_purl.rs` | nginx CPE returns `None` |
| 12 | `cpe_to_package_malformed_returns_none` | `src/infra/cpe_purl.rs` | Garbage CPE returns `None` |
| 13 | `cpe_to_package_table_has_at_least_30_entries` | `src/infra/cpe_purl.rs` | Mapping table size invariant |
| 14 | `parse_osv_response_extracts_records` | `src/infra/cve_osv.rs` | Real OSV JSON → `Vec<CveRecord>` field mapping |
| 15 | `parse_osv_response_handles_missing_severity` | `src/infra/cve_osv.rs` | No `severity` array → `Severity::Info` |
| 16 | `parse_osv_response_handles_empty_vulns` | `src/infra/cve_osv.rs` | `{"vulns": []}` → empty Vec |
| 17 | `osv_quota_default_is_10_rps` | `src/infra/cve_osv.rs` | `max_rps = 10` matches default |
| 18 | `osv_config_default` | `src/config/cve.rs` | TTL 86400, max_rps 10, no base_url/cache_dir/api_key |
| 19 | `osv_config_toml_round_trip` | `src/config/cve.rs` | `[cve.osv]` TOML deserializes |
| 20 | `cve_backend_kind_osv_serde_lowercase` | `src/config/cve.rs` | `Osv` ↔ `"osv"` |
| 21 | `build_cve_lookup_osv_returns_osv` | `src/infra/cve_lookup.rs` | Factory dispatch |
| 22 | `osv_lookup_against_mock_server_emits_findings` | `tests/cve_osv.rs` | End-to-end mock server → findings |
| 23 | `osv_lookup_caches_after_first_query` | `tests/cve_osv.rs` | Second call served from cache |
| 24 | `osv_lookup_empty_response_is_negative_cached` | `tests/cve_osv.rs` | Negative cache works |
| 25 | `osv_lookup_unmapped_cpe_returns_empty_no_request` | `tests/cve_osv.rs` | Unmapped CPE → no HTTP call, `Ok(empty)` |
| 26 | `osv_lookup_live_smoke` (`#[ignore]`) | `tests/cve_osv.rs` | Real api.osv.dev returns ≥1 vuln for express:4.17.0 |

### Deferred Items
*None.* All scope items have a concrete plan. Live-network test included but `#[ignore]`-gated.

### Issues Found
- The mapping table will need maintenance as ecosystems evolve. Documented as a contribution-friendly seam (PRs welcome to add entries).
- OSV's GHSA-formatted IDs differ from NVD's CVE- IDs. Same vulnerability often has both. Cross-backend dedup is explicitly out of scope (see Architectural Decision #7). Documented in `docs/modules/cve-osv.md`.

### Knowledge Recorded
- **Lessons:** to record on Phase 4 — "OSV needs CPE→PURL translation; CVSS v3 base score computer is reusable across backends; per-backend cache dirs prevent cross-contamination"
- **Failures:** none
- **Component Types:** `infra`, `cve`, `network`, `cache`, `config`

### Human Confirmed
- [x] Design reviewed (user delegated autonomous run through `/commit`)

---

## Phase 3: Implement
**Command:** /implement
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Files Created
- `src/infra/cpe_purl.rs` — `PackageCoord` + `cpe_to_package` translator + 39-entry MAPPING table
- `src/infra/cve_osv.rs` — `OsvCveLookup` + OSV response parser + governor limiter + FsCache reuse
- `tests/cve_osv.rs` — 4 httpmock integration tests + `#[ignore]` live smoke
- `tests/fixtures/osv/express_query_response.json` — recorded GHSA-rv95-896h-c2vc shape
- `tests/fixtures/osv/empty_response.json`
- `docs/modules/cve-osv.md` — operator reference

### Files Modified
- `src/engine/cve.rs` — new `cvss_v3_base_score(vector)` (with `apply_metric` helper to keep the function under 100 lines)
- `src/config/cve.rs` — `Osv` variant on `CveBackendKind`; new `OsvConfig`; new test for backend kind serialisation + OSV config defaults + TOML round-trip
- `src/infra/cve_lookup.rs` — factory dispatch arm for `Osv` + test
- `src/infra/mod.rs` — `pub mod cpe_purl; pub mod cve_osv;`
- `src/prelude.rs` — re-export `OsvCveLookup`, `OsvConfig`, `cpe_to_package`, `PackageCoord`
- `CHANGELOG.md` — WORK-103c bullet under `[Unreleased] / Added`
- `docs/architecture/engine.md` — CVE correlation section now describes both production backends

### Quality Gates
- **cargo fmt:** Pass (auto-applied)
- **cargo clippy --features infra (lib, -D warnings):** Pass — 0 warnings
- **cargo build --features infra:** Pass
- **cargo test --features infra:** **651 passing** (was 619 — net +32 lib tests + 4 integration cve_osv + 1 ignored live)
- **semgrep on new files (cve_osv, cpe_purl, cve, cve config):** 0 findings
- **cargo deny check advisories:** Pass
- **cargo audit:** No new advisories (RUSTSEC-2026-0097 in rand still pre-existing, already in deny.toml ignore list)

### Notes
- One refactor needed during clippy pass: `cvss_v3_base_score` originally exceeded the 100-line cap; extracted `apply_metric(&mut CvssMetrics, key, val) -> core::result::Result<(), ()>` helper. The fully-qualified `core::result::Result` is required because the module's `Result` alias is fixed to `ScorchError` — documented inline.
- Used `f64::mul_add` for the spec's recommended fused-multiply-add in the impact formula (matches FIRST's reference impls and satisfies clippy `suboptimal_flops`).
- `quota_for_rps` made `const fn` per clippy `missing_const_for_fn`.
- Doc-comment backticks added around `OSV.dev`, `npm`, `PyPI`, `Maven` etc. per `doc_markdown`.

### Knowledge Recorded
- **Lessons:** to record in Phase 4
- **Failures:** none
- **Component Types:** `infra`, `cve`, `network`, `cache`, `config`

---

## Phase 4: Validate
**Command:** /validate
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

### Entry Verification (independently re-run)
- `cargo fmt --check` — Pass
- `cargo clippy --features infra -- -D warnings` (lib) — Pass
- `cargo test --features infra` — Pass, 651 lib + integration tests, 0 failures
- ` ```ignore ` doctest check — none introduced
- `#[ignore]` check — only `tests/cve_osv.rs::osv_lookup_live_smoke`, with explicit `reason = "live network — hits api.osv.dev"`
- `#[allow]` check — zero new `#[allow(...)]` introduced

### Code Review
- **Standards Compliance:** Pass — trait-driven backend selection, separate HTTP client, idiomatic naming, `pub(crate)` where appropriate (`MAPPING`, `apply_metric`, `pick_best_severity`)
- **Workaround Detection:** Pass — no `// HACK`, `// TODO`, `// FIXME`, `--no-verify`, or feature-gate hacks
- **Production unwrap/expect:** Pass — zero `unwrap()`/`expect()` in production paths. `NonZeroU32::new(cfg.max_rps).ok_or_else(|| ...)?` propagates instead of panicking.
- **Security Review (semgrep):** Pass — 0 findings on new files
- **Cargo Audit:** Pass at hook bar (no CVSS 9-10 advisories)
- **Cargo Deny:** Pass

### Test Results
- **Cargo Test (default):** 559 passed, 0 failed
- **Cargo Test (mcp):** 701 passed, 0 failed
- **Cargo Test (infra):** 651 passed, 0 failed (+32 vs WORK-103b baseline)
- **Doctests:** 10 passed

### Regression Test Plan Compliance
All 26 planned tests implemented (with naming kept exactly to the Phase 2 plan). Every one passing.

### Knowledge Recorded
- **Lessons:** 1 (`infra/osv-backend-design`) + design-time `cve.backend.osv` architecture decision; implementation lesson to record below.
- **Failures:** 0
- **Component Types:** `infra`, `cve`, `network`, `cache`, `config`

---

## Phase 5: Verify (Full Suite)
**Command:** /verify
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

| Build | Tests Passed | Notes |
|-------|-------------:|-------|
| `cargo test` (default) | **559** | unchanged from WORK-103b — infra is gated |
| `cargo test --features mcp` | **701** | unchanged from WORK-103b |
| `cargo test --features infra` | **651** | **+32 vs WORK-103b**; zero failures |

No regressions across any feature build. Doctest count (10) unchanged. The single `#[ignore]`-gated live test does not run in CI.

---

## Phase 6: Complete
**Command:** /complete
**Status:** PASS
**Started:** 2026-04-14
**Completed:** 2026-04-14

- **Documentation Updated:** `docs/modules/cve-osv.md` (new), `docs/architecture/engine.md` (CVE section now describes both production backends).
- **Changelog Updated:** Yes (`## [Unreleased]` → first bullet under "Added", labelled WORK-103c).
- **Generation Trace Saved:** Yes.
- **Architecture Decision Recorded:** `cve.backend.osv`.
- **Lessons Recorded:** 1 design lesson + 1 implementation lesson.
- **Pipeline Doc Archived:** Yes — moved to `completed/`.

### Self-Reflection
1. **Workarounds?** None. Two refactors driven by clippy (`apply_metric` helper to fit the 100-line cap; `core::result::Result` to disambiguate from the module-level alias) — both improvements, not workarounds.
2. **Cleanest version?** Yes for v1. CPE→PURL translator is intentionally narrow (≥30 high-value mappings; PR-friendly seam for additions). No client-side version-range matching (trust OSV's server-side filter). No multi-backend aggregation (one backend per discriminant; `Composite` deferred to a future pipeline if demand emerges).
3. **Senior dev approval?** Yes. Trait-driven backend selection (zero plumbing changes for the new backend), separate HTTP client (audit-resistant), per-backend cache dirs (no cross-contamination), pure functions for the CVSS computer + CPE translator (testable without live targets), conservative rate limit (10 RPS vs ~25 QPS fair-use), unmapped-CPE short-circuit (don't burn budget on queries we know will return nothing).

### Final Checklist
- [x] All quality gates green (default / mcp / infra)
- [x] Lib clippy zero warnings
- [x] semgrep clean on new files
- [x] cargo audit / deny — no new advisories
- [x] No new `#[allow]`
- [x] All public items documented; `# Errors` on `Result`-returning APIs
- [x] Architecture decision recorded
- [x] Lessons recorded (design + implementation)
- [x] Generation trace saved
- [x] Changelog updated
- [x] Pipeline doc archived
- [ ] PR created — `/commit`
