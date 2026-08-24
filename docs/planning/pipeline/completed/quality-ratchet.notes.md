---
title: Complete scheduled mutation inventory and quality ratchet — notes
pipeline_id: 1508637c-d626-43cd-ab4a-3d27ef8b5bba
---

# Complete scheduled mutation inventory and quality ratchet — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `AAR-001-rustal-quality-workflow`: one completed broad inventory is sufficient to form a repair
    queue; incomplete outcomes are never green; mutation-blind files need an explicit ledger; exact
    focused evidence must bind raw outcomes and mutation inputs.
  - `PR-scorchkit-gate-prerequisites-001`: do not spend mutation time after a failed prerequisite.
  - `BF-scorchkit-mutation-rescan-cost-001` and `PR-scorchkit-focused-mutation-repair-001`: never
    repeat the broad inventory after it has named the survivor scope.
  - `AAR-007-workspace-crate-extraction` and `PR-scorchkit-workspace-gate-scope-001`: the campaign
    must cover all workspace packages rather than only the root facade.
  - `AAR-023-windows-process-owner` and `PR-scorchkit-target-inactive-mutation-files-001`: retain
    only the exact reviewed target-inactive exclusions; no new exclusion is authorized.
  - `PR-scorchkit-validation-evidence-before-receipt-001`: finish evidence narratives before the
    receipt-producing run so documentation does not invalidate the exact-tree receipt.
- Recon evidence:
  - `bash bin/mutants.sh --inspect` passed and reported 9,772 configured mutations across 298
    workspace source files; source-root, composition-binary, and policy-kernel assertions passed.
  - The host reports 24 logical CPUs and 827 GiB free on `/mnt/buildtmp`; bounded cargo-mutants
    workers can use local NVMe scratch without concurrent Cargo invocations.
  - TICKET-024's final DIFF measured 84.59% line coverage and caught 7/7 viable mutations. TICKET-025
    must independently reproduce current-tree coverage before setting an 80% floor.
- Operator confirmation: the repository owner directed completion of the next five ordered tickets
  on 2026-08-22. That includes SK-047's roadmap-defined one-time FULL inventory and conditional
  survivor repair. The completed baseline will be copied into sealed evidence and its exact missed
  names will be recorded here and in the ticket/spec before repair begins.

## Phase 2 — Design

- Architecture: one resumable FULL campaign owns immutable per-shard raw outcomes and a fail-closed
  merged result under `.git`. Shards run sequentially through the canonical mutation wrapper while
  cargo-mutants uses bounded internal workers on NVMe scratch. Merge proves identical inputs,
  versions, denominators, exact inventory partition, successful baselines, and reconstructed counts.
  A completed red FULL becomes the sole broad baseline; exact missed names define the approved
  focused scope and generic section-19 evidence binds transition snapshots plus the survivor-only
  recheck. No product runtime or remote effect changes.
- File manifest: add `bin/full-mutation-campaign.sh`; extend `bin/mutants.sh`, `bin/gate.sh`, and
  `tests/quality_gate_contract.rs`; update CI only if its canonical helper contract requires it;
  update development/Constitution/roadmap/changelog and planning knowledge. Append exact repair
  source/test files only after the FULL result names them.
- Regression test plan: campaign positive and adversarial merge/resume self-tests; mutation wrapper
  exact-name selection tests; unchanged exact exclusion assertions; inventory inspection; fast gate;
  one database-backed FULL campaign; exact survivor-only recheck; generic focused verifier;
  pre-completion and post-archive focused-repair gates with 80% coverage and at least 95% viable MSI.
- Operator confirmation: the owner-directed SK-047 outcome fixes the campaign shape. No additional
  product choice is needed; the exact repair ledger remains mechanically deferred until the FULL
  baseline reports its survivor identities.

## Phase 3 — Implement

- Owner scope correction (2026-08-23): after shard `0/4` completed with one survivor, shard `1/4`
  completed with six, and shard `2/4` stopped after 138 outcomes with six more, the owner directed
  ScorchKit to stop the remaining broad work, squash the exact observed survivors only, and move to
  SK-048. Shard `3/4` never started. The two completed shards and partial third shard remain
  incomplete discovery evidence and are not a FULL result or delivery proof.
- Exact owner-approved repair scope (13 unique names, four files):
  - `src/engine/tls_probe.rs:565:38: replace < with <= in check_expiration`
  - `src/recon/cloud.rs:35:9: replace <impl ScanModule for CloudReconModule>::description -> &'static str with ""`
  - `src/scanner/ratelimit.rs:68:25: replace || with && in <impl ScanModule for RateLimitModule>::run`
  - `src/scanner/ratelimit.rs:69:25: replace || with && in <impl ScanModule for RateLimitModule>::run`
  - `src/scanner/ratelimit.rs:82:16: delete ! in <impl ScanModule for RateLimitModule>::run`
  - `src/scanner/ratelimit.rs:82:25: replace && with || in <impl ScanModule for RateLimitModule>::run`
  - `src/scanner/ratelimit.rs:82:42: replace >= with < in <impl ScanModule for RateLimitModule>::run`
  - `src/scanner/ssrf.rs:174:5: replace test_own_params -> Result<()> with Ok(())`
  - `src/scanner/ssrf.rs:18:9: replace <impl ScanModule for SsrfModule>::name -> &'static str with "xyzzy"`
  - `src/scanner/ssrf.rs:262:13: replace || with && in contains_ssrf_indicator`
  - `src/scanner/ssrf.rs:44:17: replace || with && in <impl ScanModule for SsrfModule>::run`
  - `src/scanner/ssrf.rs:45:17: replace || with && in <impl ScanModule for SsrfModule>::run`
  - `src/scanner/ssrf.rs:99:22: replace == with != in test_ssrf_param`
- Exact pre-repair result: the completed 13-name run caught the cloud-description candidate and
  reproduced the other 12 as misses. The authoritative repair/recheck scope is therefore those 12
  misses across `tls_probe.rs`, `ratelimit.rs`, and `ssrf.rs`; evidence still accounts for all 13.
- Files and behavior changed:
  - Removed the unfinished FULL campaign integration while retaining an exact-name recheck mode in
    `bin/mutants.sh`; the runner inventories requested names before execution, validates safe source
    paths, writes to a caller-selected Git evidence directory, and self-tests empty/blank/duplicate
    name rejection.
  - Added a direct 30-day TLS warning-boundary regression in `tls_probe.rs`.
  - Added bounded loopback rate-limit fixtures proving ten unblocked attempts and protection first
    observed on the tenth attempt remain distinguishable.
  - Added SSRF regressions for exact module metadata, each scenario-compatibility dimension, exact
    query-parameter mutation, own-parameter delegation, and every independent metadata marker.
  - The cloud-description candidate needed no new test or source change because the completed exact
    baseline caught it on the unchanged tree.
- Design deviations: the owner-directed stop replaces the confirmed FULL merge and 80% coverage
  ratchet with an exact focused repair at the unchanged floors. `CONSTITUTION.md` records this
  explicit exception; incomplete broad output remains non-passing.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | Partial shard labels called 13 candidates survivors, but the completed exact-name baseline caught the cloud-description candidate and reproduced only 12 misses. | Medium | Corrected the ticket, spec, Constitution amendment, and evidence arithmetic to a 13-candidate initial scope and exact 12-miss repair scope. |
| 2 | Data integrity | The first exact-name validator used an early `awk exit 1` whose `END` block could overwrite the failure for a blank line. | High | Replaced it with accumulated invalid state and added executable valid, blank, duplicate, and empty-list self-tests. |
| 3 | Correctness | The rate-limit fixture server awaited eleven requests without a bound, so a future early-return regression could hang the test instead of failing promptly. | Medium | Wrapped fixture completion in a two-second Tokio timeout while retaining exact request-count assertions. |
| 4 | Security | The repair adds only test-local loopback I/O and local developer mutation tooling; no scanner effect, grant, target, credential, redirect, TLS, redaction, timeout, or output boundary changes. | None | Accepted; focused tests use `127.0.0.1` or in-process `httpmock`, and the fast gate's security/static lanes are green. |
| 5 | Simplification | Keeping the unfinished campaign helper would add merge and resume machinery after the owner canceled the remaining shards. | Medium | Deleted that untracked helper and restored ordinary FULL gate wiring; retained only the smaller exact-name capability needed for this and later approved repairs. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Focused regressions passed: the exclusive 30-day TLS boundary; all five rate-limit module
    tests; all twelve SSRF module tests; and all four quality-gate contract tests.
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all`,
    `shellcheck -x bin/mutants.sh`, and `bash bin/mutants.sh --selftest` passed.
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --fast` passed all
    14 applicable lanes with zero failures and eight intentional delivery-only skips; the
    all-feature library suite reported 1,346 passed and four reasoned ignored tests.
  - The completed exact 13-name pre-repair run selected every requested candidate, caught one, and
    reproduced 12 misses. The one exact current-tree 12-name recheck caught all 12 with zero
    missed, timeout, or unviable outcomes.
  - `bash bin/focused-mutation-evidence.sh --verify
    .git/scorchkit-mutants-focused-ticket-025` verifies 13/13 viable caught at 100% focused MSI,
    the three-file input transition, current mutation-input digest
    `edbf7f3a5faa4d8cc66b7528d813954db8a5bf48b146c65492877994064ec05f`, and evidence digest
    `129a7116ebcb56350863486836fdae48340c5247e81a7c99c0602031e85fdf5a`.
- Gate run and receipt:
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh
    --focused-repair` passed 19 applicable lanes with zero failures and three named web-only skips;
    it verified sealed evidence without launching cargo-mutants and wrote an exact-worktree
    focused-repair receipt.
  - Coverage was 84.71%, above the unchanged 62% floor. Strict Nextest passed 1,945 cases with ten
    repository-declared skips. PostgreSQL integration and CLI/MCP contract lanes passed.
- Documented skips with reasons:
  - Gates 17–19 remain the named not-applicable browser/rendering/asset skips because ScorchKit has
    no web UI. No test, advisory, coverage, mutation, feature, retry, or suppression skip was added.

## Phase 5 — Complete

- Docs updated: the changelog, development guide, Constitution, roadmap, intake, ticket, spec,
  notes, and knowledge register distinguish stopped discovery evidence from a completed result,
  document exact-name operation, retain the existing floors, and name SK-048 next.
- AAR submitted: `AAR-025-quality-ratchet` on 2026-08-23 with effectiveness 4/5; two reusable
  prevention rules and two failure patterns are registered in the knowledge index.
- Archive: pending the repository-owned completion transition and required post-archive
  focused-repair delivery receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The stopped shard output described all 13 observed names as survivors, but a complete exact baseline caught one. | Partial campaign outcomes were treated as authoritative before one bounded candidate reproduction completed. | Reclassified all 13 as candidates and used the completed exact run's 12 misses as the repair/recheck set. | Treat names from incomplete mutation work as candidates; one exact completed pre-repair run defines the repair scope. |
| 2 | A blank line passed the first exact-name shell validator. | An early `awk exit 1` was overwritten by the script's unconditional `END` exit status. | Accumulated invalid state and emitted the final exit only from `END`; added blank, empty, duplicate, and valid self-tests. | Stateful stream validators must preserve earlier failures through their finalization block. |
| 3 | The first rate-limit loopback fixture could hang if a regression returned before all expected requests. | The server task had an exact count but no completion deadline. | Wrapped the join in a two-second Tokio timeout. | Bound both client work and fixture completion when testing request-count behavior. |
| 4 | The first focused summary used a mutation-input hash taken before the exact-run test contract was finalized. | Evidence metadata captured the historical hash too early, although all changed repair files had valid snapshots. | Reconstructed the historical input from the three sealed snapshots and recorded that verifier-derived digest. | Seal transition metadata only after the exact baseline and pre-repair snapshots are both fixed. |
