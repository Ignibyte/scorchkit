---
title: Shared bounded job executor — notes
pipeline_id: 166cba1b-513e-488f-b6f2-9fcc43ef4796
---

# Shared bounded job executor — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `CONSTITUTION.md`, `SECURITY.md`, `AGENTS.md`, the SK-028 through SK-042
  roadmap, the engine/runner/module/SAST/infra/cloud architecture set, the completed WORK-104
  pipeline, and the active prevention rules in `docs/planning/knowledge/INDEX.md`.
- Recalled rules that changed the plan: `PR-scorchkit-policy-before-effects-001` keeps all effects
  behind contexts; `PR-scorchkit-executor-contract-001` requires tests through the injectable
  boundary; `PR-scorchkit-observable-seams-001` requires observable cancellation and budget seams;
  `PR-scorchkit-derived-network-policy-001` prevents an executor-owned raw network client; and
  `PR-scorchkit-bounded-process-exit-race-001` requires bounded process cleanup evidence.
- Recon evidence: all four standard family loops await each module while holding their only
  semaphore permit, so they are serial. DAST and infra also have shared-data dependencies that
  require explicit producer phases before true concurrency is safe.
- Operator confirmation: on 2026-08-16 the operator said to continue and finish SK-028. The prior
  instruction to avoid repeated full mutation scans remains in force.

## Phase 2 — Design

- Architecture: add a vendor-neutral `runner::job_executor` that accepts borrowed work items and a
  closure. It polls at most `max_concurrency` futures at once, races the batch against a cloneable
  cancellation token and one wall-clock deadline, measures each job, and sorts completed outcomes
  by an internal submission ordinal. It has no knowledge of targets, policy, findings, events,
  storage, or agent providers. Each family adapter remains responsible for tool availability,
  lifecycle events, hooks, finding assembly, and policy-sealed context calls.
- Dependency design: DAST runs recon and scanner batches in that order. Infrastructure runs all
  non-`CveMatch` modules before `CveMatch` modules. SAST and cloud currently have no registered
  producer/consumer contract, so each uses one batch. Checkpoint mode stays serial because SK-028
  cannot preserve per-module durable checkpoints if a concurrent batch returns only at its end.
- Cancellation design: existing run methods create a fresh token and delegate to public
  cancellation-aware methods. Cancelling drops the bounded stream, which drops pending reqwest
  futures and `SystemToolExecutor` futures. The existing HTTP client and Unix process-group guards
  own effect cleanup. Cancellation does not synthesize a module failure or partial `ScanResult`.
- Budget design: construct an executor budget from `ScanConfig`. Reject zero concurrency or a zero
  timeout as a configuration error. Treat the configured timeout as the whole-batch wall-time
  budget in addition to the existing per-request timeout. Preserve module-specific process
  timeouts and per-stream output limits.
- Determinism design: the executor returns submission-ordered outcomes even when completion order
  differs. Family adapters apply post-module hooks and emit finding/completion/error events while
  consuming that stable list. Stable severity sorting retains submission order for equal-severity
  findings.
- File manifest: add direct `futures-util` and `tokio-util` dependencies in `Cargo.toml` and
  `Cargo.lock`; add `src/runner/job_executor.rs`; export it from `src/runner/mod.rs`; replace the
  standard scheduling loops in `src/runner/orchestrator.rs`, `code_orchestrator.rs`,
  `infra_orchestrator.rs`, and `cloud_orchestrator.rs`; document the seam in a new
  `docs/architecture/executor.md` and update runner, engine, SAST, infra, cloud, guide, and roadmap
  references as needed. Ticket/spec/notes/AAR and knowledge index changes remain pipeline-owned.
- Regression test plan: executor unit tests cover zero budgets, true bounded overlap, stable order,
  pre-cancellation, in-flight cancellation, deadline cancellation, pending loopback HTTP EOF, and
  Unix child/descendant exit. One cross-family internal suite runs two deliberately out-of-order
  modules through DAST, SAST, infra, and cloud and asserts stable results and overlap. DAST and infra
  tests assert producer data is visible to consumers. Existing hook, skip, error, empty-registry,
  event, checkpoint, policy, output-limit, and process-tree tests must remain green.
- Validation plan: run the named executor and orchestrator tests first, then `bash bin/gate.sh
  --fast`. Phase 4 runs one database-backed `bash bin/gate.sh --focused-repair` to verify the sealed
  five-file evidence and create the required receipt without executing mutants. No broad mutation
  campaign will run. Completion changes the worktree, so the same focused gate runs once more for
  delivery.

## Phase 3 — Implement

- Files and behavior changed: added direct `futures-util` and `tokio-util` dependencies; added the
  vendor-neutral `runner::job_executor` budget, executor, cancellation token, and ordered outcome
  contract; routed standard DAST, SAST, infrastructure, and cloud module work through that executor;
  added explicit DAST recon/scanner and infrastructure producer/CVE phases; kept checkpoint mode
  serial; and documented the boundary in `docs/architecture/executor.md` and the affected family
  architecture guides.
- Cancellation coverage: caller cancellation drops queued and active module futures, pending
  loopback HTTP work, owned Unix process trees, and DAST/SAST lifecycle-hook futures. Every
  cancellation-aware family checks the token before publishing `ScanCompleted`.
- Contract evidence: the all-feature executor suite passed 14 tests covering bounded overlap,
  stable ordering, zero budgets, pre- and in-flight cancellation, deadline cancellation,
  adjacent-effect drop, loopback HTTP release, Unix descendant cleanup, and the same contract
  through all four families. DAST and infrastructure dependency regression tests passed.
- Broad development evidence: the repaired-tree `bash bin/gate.sh --fast` passed all 14 active
  checks, including the complete library run (1,221 passed, 4 intentionally ignored), all
  integration/doc tests, the feature-state lint
  matrix, rustdoc, dependency/security checks, secret scanning, and static analysis. Fast mode
  correctly skipped coverage, mutation, database, and broad CLI/MCP contract gates.
- Design deviations: borrowed family futures are erased to `BoxFuture` before crossing the shared
  executor boundary because the all-feature MCP macro build exposed higher-ranked lifetime/`Send`
  inference failures with a generic closure API. This is an implementation-level type erasure only;
  jobs and contexts remain borrowed, and no behavior or ownership boundary changed.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | Cancellation initially raced module batches only, so a DAST/SAST hook could outlive caller cancellation and the family could publish successful completion after cancellation. | High | Fixed with the shared `cancel_on_token` adjacent-effect race, final cancellation checks in all families, and a future-drop test. The 13-test all-feature executor suite and strict all-feature Clippy pass. |
| 2 | Security | The executor must not become a bypass around scope, HTTP, cloud credential, filesystem, or subprocess controls. | None | Verified: production executor code constructs no target, client, credential, command, socket, or provider request. It polls only family-built futures over policy-sealed contexts. Raw HTTP and spawned tasks occur only in loopback/process cancellation tests. |
| 3 | Integrity | Infrastructure and cloud paths published `ScanCompleted` before their final fallible target conversion, allowing a success event to precede an error return. | Medium | Fixed by completing target conversion and summary assembly before the cancellation linearization point and success event. Family tests and strict all-feature Clippy pass. |
| 4 | Integrity | A fail-closed post-module hook cannot prevent already-running siblings in the same concurrent phase from completing. | Low | Accepted and documented. Every sibling effect is independently policy-authorized; the hook still aborts result assembly, and preserving a serial hook barrier would defeat the explicitly required overlap. |
| 5 | Simplification | Phased DAST retained a `&Box<dyn ScanModule>` helper boundary and suppression, while the cloud adapter comment still described the pre-shared-executor architecture. | Low | Fixed by passing `&dyn ScanModule`, removing the borrowed-box suppression, and replacing the stale comment with the current family-adapter boundary. |

## Phase 4 — Validate

- Focused mutation: inventory first proved that canonical `--diff` would select 1,038 mutants in
  135 accumulated changed files. To honor the operator's no-broad-rescan direction, the executed
  run was limited to the five SK-028 executor/orchestrator files and selected 68 variants. The
  initial result was 31 assertion-caught, 2 timeout-caught, 2 missed, and 33 unviable. The survivors
  identified missing direct proof for the final cancellation check and the explicit phased DAST
  partition. Added both regressions, then an exact two-item recheck caught both. Final focused
  result: 35/35 viable caught, 0 missed, 33 unviable, 100% MSI. Compact raw evidence is sealed under
  `.git/scorchkit-mutants-focused-ticket-002`. The TICKET-002 verifier independently reconstructs
  every count and survivor identity, compares the current 68-item production inventory with the
  initial inventory without compiling mutants, binds the pre-recheck two-file snapshots to base
  input `452389de87b3f05602305a53af387b1806faf93f06de5bf3231dee0ef762293e`, and binds current
  mutation input `097016dbdded38f39272366f0153166c2ebcdaf6113960c52708f1ee30e793ba`.
- Tests run: the 14-test all-feature executor contract suite; DAST, SAST, infrastructure, and cloud
  orchestrator suites; hook tests; strict all-feature Clippy; and `git diff --check` all passed.
  `bash bin/gate.sh --fast` passed 14/14 active lanes on the repaired tree. Database-backed
  `cargo llvm-cov` passed at 79.26% lines against the unchanged 62% floor. Nextest listed 19
  non-empty suites and passed 1,406/1,406 executed tests. The named PostgreSQL lane passed 76 tests,
  and the CLI/MCP contract lane passed 91 tests.
- Gate run and receipt: the owner-approved TICKET-002 amendment in `CONSTITUTION.md` §19 now permits
  the focused-repair receipt for this exact SK-028 scope. Its verifier passes at 35/35 viable caught
  and seals evidence digest `572e96256cbb8298dd97f0d46bf9b74a3ee14c3b90afae5ca28358cbef4dfbbb`.
  The database-backed pre-completion gate passed 19 applicable lanes with 0 failures and 3 named
  web-only skips, measured 79.26% line coverage, passed 1,406/1,406 Nextest cases, passed the 76-test
  PostgreSQL lane and 91-test CLI/MCP lane, and wrote the exact-tree focused-repair receipt. The
  pipeline consumed that receipt and passed Validate. No DIFF/FULL mutation run was launched.
- Documented skips: four library and two integration live-network smokes remain ignored by design:
  DNSSEC/AXFR require `SCORCHKIT_DNS_TEST_ZONE`, TLS version/cipher enumeration requires
  `SCORCHKIT_TLS_ENUM_HOST`, NVD requires `SCORCHKIT_NVD_API_KEY`, and OSV contacts public
  `api.osv.dev`. Authorized loopback coverage exercises the corresponding automated paths.

## Phase 5 — Complete

- Docs updated: executor and family architecture guides, module guide, Constitution §19, roadmap,
  ticket/spec/notes, gate receipt contract, TICKET-002 focused verifier, knowledge register, and
  this AAR.
- AAR submitted: `AAR-002-shared-job-executor`, 2026-08-16, effectiveness 5.
- Archive: `bash bin/pipeline.sh pass complete` closed TICKET-002 on 2026-08-16, removed it from the
  open queue, and moved the spec/notes pair to `docs/planning/pipeline/completed` with rewritten
  closed/completed cross-links.
- Post-archive proof: the final database-backed `bash bin/gate.sh --focused-repair` reruns every
  non-mutation delivery lane and binds the archived worktree to the sealed TICKET-002 evidence
  digest. Its exact-tree receipt is the authoritative delivery result.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The workspace mount could not host Cargo build artifacts reliably. | The mounted filesystem cannot execute every generated helper in place. | Reused `/private/tmp/scorchkit-target-501` through `CARGO_TARGET_DIR`. | Continue using the gate-selected or explicit local build directory documented in `AGENTS.md`. |
| 2 | The first all-feature build rejected the generic borrowed-job closure at MCP-generated call sites. | The closure produced futures whose inferred lifetime and `Send` bounds were not general enough across macro-expanded async code. | Build explicit `Vec<BoxFuture<'_, T>>` batches in ordinary loops before calling the executor. | Capture as an AAR prevention rule after inspection confirms the boundary. |
| 3 | Initial fast-gate passes found narrow lint and TOML-ordering defects. | New tests used conversions/patterns that violated the repository lint profile, and the dependency insertion was not in canonical order. | Rewrote the test patterns, added only adjacent justified function-size suppressions, and formatted `Cargo.toml`. | Treat the fast gate as the implementation feedback loop; do not weaken lints. |
| 4 | Review found cancellation did not cover DAST/SAST hooks or the final success edge. | The token initially raced only executor batches; lifecycle hook futures remained outside that boundary. | Added a shared cancellation race for adjacent fallible effects and final token checks in all four families, with a future-drop regression test. | Capture a rule that cancellation-aware lifecycles must cover adjacent effects and successful completion, not only the central work loop. |
| 5 | Focused mutation left the final cancellation check and explicit phased DAST partition alive. | Family pre-cancellation tests exercised the executor before reaching the final check, and only the standard DAST entry point asserted the dependency barrier. | Added a direct final-check negative and the same producer/consumer assertion through `run_phased`; an exact two-item recheck caught both. | `PR-scorchkit-public-mode-dependency-contract-001`. |
| 6 | Canonical DIFF would select 1,038 mutants instead of the 68 SK-028 variants. | TICKET-002 began on top of an uncommitted TICKET-001 worktree, so Git has no ticket boundary for diff targeting. | Did not launch the broad run. Recorded the owner's exact scope in `CONSTITUTION.md` §19 and added a fail-closed TICKET-002 verifier that binds raw outcomes, inventory equivalence, source transitions, input hashes, and the receipt digest. | `PR-scorchkit-ticket-diff-baseline-001`. |
