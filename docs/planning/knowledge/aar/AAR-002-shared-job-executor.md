---
aar: AAR-002-shared-job-executor
ticket: TICKET-002
pipeline: shared-job-executor
status: submitted
opened: 2026-08-16
submitted: 2026-08-16
effectiveness: 5 - delivered the shared executor and closed its lifecycle and proof gaps
---

# AAR-002 — Shared bounded job executor

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | The executor will control work that can perform network, filesystem, cloud, and subprocess effects. | Yes. It kept authorization, clients, credentials, and process construction in the existing contexts. |
| `PR-scorchkit-executor-contract-001` | Four orchestrators need to converge on one execution seam. | Yes. The plan requires one cross-family contract suite and direct boundary tests. |
| `PR-scorchkit-observable-seams-001` | Cancellation and concurrency need tests without timing-only inference. | Yes. The design uses an explicit token, ordered outcomes, and active-job high-water counters. |
| `PR-scorchkit-derived-network-policy-001` | HTTP cancellation testing could tempt a raw production client in the executor. | Yes. HTTP remains module/context work; only a loopback fixture uses a dedicated test client. |
| `PR-scorchkit-bounded-process-exit-race-001` | Cancellation must prove process-tree cleanup. | Yes. The acceptance test has a two-second bound and reuses owned process groups. |
| `docs/planning/ROADMAP.md` SK-028/SK-029/SK-033 | Scope could drift into persisted jobs or crate extraction. | Yes. Those changes are explicitly deferred. |

## What happened

- Planning found that the four documented concurrent loops are actually serial and that DAST and
  infrastructure scans have producer/consumer dependencies hidden by the serial behavior.
- One vendor-neutral executor now supplies bounded overlap, a batch deadline, caller cancellation,
  duration/ordinal outcomes, and stable result order to DAST, SAST, infrastructure, and cloud.
  Family adapters retain policy-sealed contexts, events, hooks, findings, and target conversion.
- Inspection closed cancellation gaps around DAST/SAST hooks and final success publication, and
  moved fallible infrastructure/cloud target conversion ahead of `ScanCompleted`.
- Focused SK-028 mutation initially exposed two test gaps. Direct final-cancellation and explicit
  phased-dependency regressions raised the five-file result to 35/35 viable caught at 100% MSI.
- Every non-mutation delivery lane is green, including 79.26% line coverage, 1,406 passing Nextest
  cases, PostgreSQL integration, and CLI/MCP contracts. The owner-approved TICKET-002 amendment now
  represents the SK-028 boundary honestly: its verifier seals 68 initial outcomes, the exact
  two-survivor recheck, current inventory equivalence, and the two-file test transition without
  launching the 1,038-mutant accumulated Git diff.
- The pre-completion focused-repair gate passed all 19 applicable lanes with zero failures and three
  explicit web-only skips. The pipeline consumed its exact-tree receipt before completion edits made
  that receipt stale for the required post-archive delivery rerun.

## Novel findings

- A semaphore does not create concurrency when its permit is acquired and released inside a serial
  await loop; overlap needs one scheduler that polls several futures at once.
- Enabling real overlap makes hidden producer/consumer dependencies observable. DAST recon and
  infrastructure fingerprinting therefore need explicit barriers.
- Caller cancellation is a whole-lifecycle contract. It must drop adjacent hook effects and be
  checked at the success linearization point, not only inside the central executor.
- Public execution modes need their own dependency contract even when they share lower-level batch
  helpers; mutation reversed only `run_phased_with_cancellation` and survived the standard-path test.
- A content receipt without a committed ticket boundary cannot reconstruct an incremental mutation
  diff. Beginning the next ticket on an accumulated worktree expands canonical diff scope.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-borrowed-future-inference-001` | A generic borrowed closure was not sufficiently general/`Send` through MCP macro-expanded async call sites. | First all-feature build. |
| `BF-scorchkit-cancellation-lifecycle-gap-001` | Hook futures and the final success edge initially sat outside caller cancellation. | Correctness inspection. |
| `BF-scorchkit-success-before-final-conversion-001` | Infrastructure/cloud emitted `ScanCompleted` before final fallible target conversion. | Integrity inspection. |
| `BF-scorchkit-public-mode-proof-gap-001` | Final cancellation and explicit phased partition mutations survived despite adjacent family tests. | Focused SK-028 mutation. |
| `BF-scorchkit-accumulated-diff-mutation-scope-001` | Canonical DIFF selected 1,038 accumulated mutants for a 68-variant ticket scope. | Validation scope inventory. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Race cancellation across central work and adjacent async effects, then check it before publishing success. | Hook work could outlive cancellation and return a successful scan. |
| `PR-scorchkit-public-mode-dependency-contract-001` | Assert producer/consumer ordering through every public execution mode that owns a phase partition. | Reversing the explicit phased partition survived the standard-mode regression. |
| `PR-scorchkit-ticket-diff-baseline-001` | Establish a canonical Git/receipt boundary before starting the next ticket that relies on diff mutation. | Without a boundary, the next ticket's DIFF gate reselects accumulated prior work. |
| `AD-scorchkit-boxed-borrowed-jobs-001` | Erase borrowed concurrent module futures to `BoxFuture` before the executor boundary. | It preserves borrowed ownership while satisfying async macro `Send`/lifetime constraints. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5 - The work replaced four false-concurrent loops with one policy-neutral execution contract while
preserving every effect boundary and deterministic result contract. Inspection closed a real
cancellation lifecycle gap and a success-event integrity defect. Focused mutation found two public
mode proof gaps, both were repaired, and the sealed verifier reports 35/35 viable caught. The
accumulated-worktree problem became an explicit, fail-closed receipt rule rather than a false DIFF
claim or another broad rescan. SK-029 can now add durable job state on a tested cancellation and
resource-budget seam.
