---
title: Durable scan job lifecycle and storage abstraction — notes
pipeline_id: 14c13839-5292-4c3a-a832-639b87143ce5
---

# Durable scan job lifecycle and storage abstraction — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` keeps resume authorization in the
  current `Engine`; `PR-scorchkit-cancellation-whole-lifecycle-001` requires the job token to cover
  setup and terminal publication; `PR-scorchkit-observable-seams-001` rejects a behavior-free job
  wrapper; `PR-scorchkit-ticket-diff-baseline-001` required the clean `d65a67a` boundary; and
  `PR-scorchkit-global-set-lock-001` makes concurrent recovery/CAS behavior part of the store proof.
- Recon changed the approach: `EventBus` explicitly permits dropped events for slow subscribers, so
  it remains telemetry rather than durable progress. Completed-module findings need one reliable,
  atomic progress seam owned by the DAST job adapter. The mandatory MCP `PgPool` is a construction
  concern, not an inherent dependency of stateless tools.
- Operator confirmation: the owner directed SK-029 through SK-033 back to back and on 2026-08-16
  explicitly approved the baseline and per-ticket local commits. This confirms the plan; no push,
  PR, remote target, or broad mutation run is authorized.

## Phase 2 — Design

- Architecture: add provider-neutral job models, transitions, the `JobStore` trait, and
  `InMemoryJobStore` under `runner::job`; add `ScanJobService` as the DAST adapter that owns active
  cancellation tokens and drives `Orchestrator`. `Orchestrator` accepts an optional reliable
  `ModuleProgressSink`; module futures send owned start/finish updates through an unbounded channel,
  and the service drains that channel into optimistic store updates before it can publish a terminal
  job state. `JobExecutor` remains unchanged and persistence-free. PostgreSQL implements the same
  trait in `storage::jobs` using a JSONB job document plus indexed lifecycle columns and a revision
  predicate. MCP owns an `Arc<ScanJobService>` and an optional pool. CLI constructs the PostgreSQL
  service for cross-process job commands.
- State design: queued may become running or cancelled; running may become cancelling, succeeded,
  failed, or interrupted; cancelling may become cancelled, failed, or interrupted. Terminal and
  interrupted records are immutable. Recovery claims each abandoned nonterminal record with CAS,
  clears active modules, and marks it interrupted. Resume creates a linked successor with attempt
  incremented, completed modules and their findings copied, and all other module state cleared.
- Cancellation design: insert the active token before the queued-to-running CAS, remove it only
  after progress is drained and terminal state is committed, and make cancel mutate the stored state
  before signaling the token. A stale success CAS therefore cannot overwrite cancelling/cancelled.
- Authorization design: submission constructs a policy-sealed context before persistence but does
  not poll it. Every run and resume reconstructs that context from the current config. Resume also
  requires the current engagement ID and serialized snapshot to match the immutable request; a
  disabled, expired, narrowed, or replaced engagement is denied before scanner effects.
- Recovery design: findings are staged by module and committed with `ModuleCompleted`. A successor
  excludes only completed modules; skipped and failed modules are eligible to run again. On success,
  prior completed findings/modules merge ahead of new submission-ordered results and the summary is
  recomputed.
- Compatibility design: keep existing synchronous `do_scan` and legacy CLI `--resume` checkpoint.
  Add explicit job start/status/cancel/resume MCP tools. Stdio startup uses in-memory jobs when no
  database URL exists; configured-but-unreachable PostgreSQL remains a startup error. Database-only
  methods call one `require_pool` helper. Add storage-feature CLI `job run/status/cancel/recover/resume`
  commands; `run` and `resume` execute in the foreground so process lifetime never abandons an
  unowned background task.
- File manifest: add `src/runner/job.rs`, `src/storage/jobs.rs`,
  `migrations/006_scan_jobs.sql`, `src/cli/job.rs`, `tests/job_lifecycle.rs`, and
  `docs/architecture/jobs.md`; update `src/runner/mod.rs`, `src/runner/orchestrator.rs`,
  `src/storage/mod.rs`, `src/mcp/server.rs`, `src/mcp/tools.rs`, `src/mcp/types.rs`,
  `src/mcp/instructions.rs`, `src/cli/mod.rs`, `src/cli/args.rs`, `src/cli/runner.rs`,
  `tests/mcp_tools.rs`, CLI contract tests, storage integration tests, roadmap, changelog, and linked
  pipeline artifacts.
- Regression test plan: pure state transition table; shared memory/PostgreSQL store conformance and
  stale-revision races; queued and running cancellation; completed-module atomic progress;
  interrupted recovery; resume skip/merge and changed-engagement denial; authorized loopback MCP
  start/poll/cancel/resume without a pool; database-tool unavailable errors; stdio startup without
  `DATABASE_URL`; storage-feature CLI parse/process contracts; legacy synchronous scan and checkpoint
  suites; existing SK-028 executor/cancellation/order tests; fast gate during development and one
  normal diff gate for validation plus the required post-archive diff delivery gate.
- Operator confirmation: the owner's instruction to work SK-029 through SK-033 back to back and the
  explicit “approved and commit” response confirm this design and its local delivery boundaries.

## Phase 3 — Implement

- Files and behavior changed: added `runner::job` domain types, legal transitions, ownership leases,
  bounded module progress, cancellation, recovery, resume, in-memory storage, optimistic revisions,
  and compact revision audit events. DAST orchestration now accepts an optional reliable
  module-boundary sink while `JobExecutor` remains persistence-free. Added PostgreSQL job and audit
  migrations plus a transactional store adapter. Added foreground CLI job commands and asynchronous
  MCP job operations. MCP now uses process-local jobs without a database and guards every
  database-only path explicitly. Added repeated expired-lease recovery, architecture/operator
  documentation, and loopback, storage, process, and duplex-transport contracts.
- Design deviations: replaced the planned unbounded progress channel with a 512-update bounded
  channel that fails closed on saturation; capped public job lists and recoverable batches at 1,000;
  added a separate append-only audit migration so every accepted revision has an atomic compact
  event without copying finding evidence; and added periodic MCP recovery because a one-time startup
  pass could observe a dead owner's lease before it expired. These changes tighten resource,
  recovery, and audit invariants without changing the requested host surface.
- Development evidence: strict all-target/all-feature Clippy passed; job lifecycle 3/3, MCP 60/60,
  CLI 21/21, and storage integration 8/8 passed against authorized loopback fixtures and the local
  validation database. The final fast gate passed all 14 applicable non-mutation lanes. Its first
  run exposed only a mechanically unformatted `Cargo.toml`; `taplo fmt` corrected it before the
  green rerun.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Lifecycle/concurrency | Dropping the `run` future could leave its spawned heartbeat and active-token ownership alive. | High | Fixed with an RAII run guard that cancels the scanner and heartbeat and removes active ownership; added a future-abort regression test. |
| 2 | Lifecycle/concurrency | Concurrent cancellation could make the losing controller retry a same-state transition and return an error. | High | Added a dedicated idempotent CAS cancellation loop; the cross-service test now requires both concurrent controllers to succeed. |
| 3 | Data integrity | Concurrent resume could fork multiple successors. | High | Added per-parent and per-root/attempt uniqueness in memory and migration 008, plus concurrent resume and provider tests. |
| 4 | Security/privacy | A target URL with embedded credentials could be persisted and returned through job APIs. | High | Reject embedded URL credentials during authorization before persistence; added a no-record regression test. |
| 5 | Failure containment | Progress or heartbeat persistence failure did not promptly stop scanner effects. | High | Both control tasks now cancel the shared scanner token when durable control fails. |
| 6 | Data integrity | Public store callers could change immutable request/identity fields or bypass legal transitions. | High | Both stores validate queued creation and every replacement; PostgreSQL locks and validates the current document before update. |
| 7 | Data integrity | Duplicate prevention alone did not stop a direct store caller from forging successor lineage or recovered progress. | High | Both stores now load and validate the interrupted parent, exact request, root, attempt, and retained progress before inserting a successor. |
| 8 | Resource/recovery | Progress buffering, public lists, and recovery batches were initially unbounded; one startup-only recovery pass could miss a live lease that later expired. | Medium | Bounded progress at 512, lists/batches at 1,000, queried only recoverable rows, and added a five-second MCP recovery pass. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused job-domain unit tests passed 13/13; MCP wrapper unit
  tests passed 2/2; the CLI comma-list regression passed; and the all-feature MCP integration suite
  passed 62/62 against loopback targets and the local PostgreSQL validation database. Strict
  all-target/all-feature Clippy and the 14 applicable fast-gate lanes were already green before
  mutation repair. ShellCheck, focused-evidence self-test, inventory equality, and transition-hash
  reconstruction are green after the verifier generalization.
- Mutation evidence: the completed normal DIFF baseline selected 279 mutants across eight files:
  150 caught, 22 timed out/caught, 61 missed, and 46 unviable (73.81% MSI before repair). The owner
  had already stopped repeat mutation scans and required reruns only for fixed code. The exact
  current-tree recheck selected the identical 61 survivors across 23 functions/four files and
  caught all 61 in 14 minutes with zero misses, timeouts, or unviable cases. Sealed evidence
  reconstructs 233/233 viable outcomes (100% MSI) and proves only four snapshotted mutation inputs
  changed after the broad baseline. The first validation-gate attempt then found two redundant
  clones in validator tests. After the mechanical Clippy repair, a separately sealed final-tree
  follow-up ran all 41 mutants in exactly `ScanJob::validate_successor` and
  `ScanJob::validate_replacement`; all 41 were caught in eight minutes. The main broad-baseline
  score remains 233/233 rather than double-counting those follow-up mutants.
- Gate run and receipt: the first `bash bin/gate.sh --focused-repair` attempt was stopped after gate
  2 found the two strict-Clippy test issues; the already-started all-feature test lane passed 1,241
  library tests and all integration suites. The receipt-producing rerun passed all 19 applicable
  lanes with zero failures and three named web-only skips. It measured 79.55% line coverage, passed
  1,433/1,433 Nextest cases, PostgreSQL integration, and CLI/MCP process contracts. Gate 16 verified
  the sealed 233/233 evidence and did not run cargo-mutants. `bash bin/pipeline.sh pass validate`
  accepted that receipt and advanced the spec to Phase 5. The status edit invalidated the receipt as
  designed, so completion requires the same receipt-producing mode after archive.
- Documented skips with reasons: gates 17–19 are named web-only skips by repository policy. No test
  skip is used as mutation evidence; the 46 compiler-rejected mutants remain labeled unviable and
  the baseline's 22 cargo-mutants timeouts remain labeled and counted as caught by the verifier.

## Phase 5 — Complete

- Docs updated: job, executor, storage, MCP, and CLI architecture guides; roadmap and changelog;
  Constitution §19; focused mutation evidence, gate, and pipeline contracts; ticket/spec/notes;
  knowledge register; and this AAR.
- AAR submitted: `AAR-003-scan-job-lifecycle`, 2026-08-16, effectiveness 5.
- Archive: `bash bin/pipeline.sh pass complete` closes TICKET-003 on 2026-08-16, removes it from the
  open queue, moves the spec/notes pair to `docs/planning/pipeline/completed`, and rewrites the
  ticket/spec links to their closed and completed destinations.
- Post-archive proof: rerun `bash bin/gate.sh --focused-repair` against the local validation database.
  It must pass every non-mutation delivery lane, verify the sealed TICKET-003 evidence without
  starting cargo-mutants, and bind the archived worktree and evidence digest to the final receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | First fast gate failed TOML formatting. | Adding the MCP client test feature left the inline dependency table in a shape rejected by Taplo. | Ran the repository formatter and reran the same gate green. | Run Taplo on dependency feature edits before the first gate. |
| 2 | The completed 279-mutant DIFF baseline scored 73.81% and would take roughly 85 minutes to repeat. | New lifecycle invariants and thin adapter outputs had functional tests but insufficient falsification assertions. | Added exact invariant/output regressions and reran only the 61-survivor set under the owner's approved focused scope; all 61 were caught. | Treat store invariants, thin wrapper payloads, and every boolean branch as explicit mutation-test seams before the ticket gate. |
| 3 | The first startup-branch repair still let the OR-to-AND mutant survive. | Both the configured database path and closed stateless stdio produced nonzero process exits, so an exit-only assertion was ambiguous. | Required the exact database connection error and preflighted that one mutant before the definitive focused pass. | Tests for fail-closed selection branches must assert the selected failure source, not only failure status. |
| 4 | The generic focused verifier could not verify timeout-bearing baselines or multiple changed input snapshots and the gate remained hard-coded to TICKET-002. | The first genericization retained assumptions from a one-ticket follow-up case. | Generalized ticket/evidence discovery, approval checks, timeout accounting, exact repair-scope comparison, dynamic transition snapshots, evidence digests, and self-tests. | Focused repair is a repository contract keyed by active ticket metadata, never by a hard-coded ticket number. |
| 5 | The first focused validation gate failed strict Clippy on two redundant clones in new validator tests. | Mutation-oriented table construction cloned the last consumed values even though ownership could move. | Preserved the exact pre-fix mutation-input snapshot, moved the final values, reran strict Clippy and the two tests, then caught all 41 mutants generated by only those two validators. | Run strict all-target Clippy after mutation-test additions and before sealing the first focused current-tree hash. |
