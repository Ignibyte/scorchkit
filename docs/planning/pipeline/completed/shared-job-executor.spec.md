---
title: Shared bounded job executor
pipeline_id: 166cba1b-513e-488f-b6f2-9fcc43ef4796
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-002
ticket_doc: docs/planning/tickets/closed/TICKET-002-shared-job-executor.md
aar: docs/planning/knowledge/aar/AAR-002-shared-job-executor.md
created: 2026-08-16
---

# Shared bounded job executor — spec

## Intent

Ship the SK-028 execution contract that SK-029 can build on: one generic bounded executor used by
the four scanner families, with cloneable cancellation, an enforced whole-batch deadline, stable
outcome ordering, and explicit dependency phases. The refactor corrects the current false
concurrency without moving policy ownership or persistence into the runner.

## Scope

- In: `runner::job_executor`; DAST/SAST/infra/cloud standard run paths; DAST recon and infra
  fingerprint dependency phases; explicit cancellation-aware orchestrator methods; contract,
  cancellation, resource-budget, and regression tests; executor architecture documentation.
- Out: checkpoint concurrency or partial checkpoint recovery; stored jobs; MCP job control;
  scanner/plugin redesign; provider-specific transports; crate extraction; Windows execution; full
  mutation testing.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When any standard DAST, SAST, infrastructure, or cloud scan runs runnable modules, ScorchKit shall schedule those modules through the same job executor. | `runner::job_executor` cross-family contract suite and architecture inspection. |
| REQ-002 | When runnable jobs exceed the concurrency budget, ScorchKit shall cap active jobs at the budget and shall reject a zero budget. | Unit tests for active-count high-water mark and invalid configuration. |
| REQ-003 | When completion order differs from submission order, ScorchKit shall return job outcomes, module IDs, and equal-severity findings in submission order. | Delayed-job executor test and family contract result assertions. |
| REQ-004 | When a cancellation token is cancelled before or during execution, ScorchKit shall drop queued and active jobs and return `ScorchError::Cancelled`. | Pre-cancel, in-flight cancel, and four-family cancellation tests. |
| REQ-005 | When cancellation interrupts pending authorized loopback HTTP or owned subprocess work, ScorchKit shall stop that work within two seconds. | Loopback socket EOF test and Unix process-tree exit test. |
| REQ-006 | When a module batch consumes its wall-time budget, ScorchKit shall stop the batch with a typed cancellation error without weakening per-effect controls. | Batch deadline test plus context and process executor inspection. |
| REQ-007 | When modules consume shared discovery or fingerprint data, ScorchKit shall schedule the producer phase before the consumer phase. | DAST recon/scanner and infra fingerprint/CVE regression tests. |
| REQ-008 | When a module skips, fails, succeeds, produces findings, or passes through configured hooks, ScorchKit shall preserve existing structured results and lifecycle events. | Existing family tests, added contract tests, and `bash bin/gate.sh --diff`. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Add the executor as `src/runner/job_executor.rs`, not a new crate. | SK-033 owns crate extraction after execution and job contracts stabilize. |
| 2 | Model the budget as nonzero maximum concurrency plus nonzero whole-batch wall time. | These map to existing scan configuration, fix the zero-permit deadlock, and make both resources observable. |
| 3 | Use borrowed futures with bounded unordered polling and sort completed outcomes by submission ordinal. | Modules and contexts stay borrowed; no detached tasks or `'static` conversion is required; execution is concurrent while result assembly is stable. |
| 4 | Expose a cloneable cancellation token through cancellation-aware family methods; existing methods create a token and delegate. | Existing callers remain source-compatible and SK-029 receives a direct control seam. |
| 5 | Keep module errors inside job outcomes; propagate cancellation and deadline errors from the executor. | Existing scans continue after a module failure, while operator cancellation remains unambiguous. |
| 6 | Run DAST and infra producer/consumer phases explicitly. | True concurrency must not race consumers against shared-data producers. |
| 7 | Process post-module hooks and publish findings/completion events in executor outcome order. | Hook and result mutation remains sequential and deterministic even though module work overlaps. |
| 8 | Keep checkpoint execution serial in SK-028. | Returning only after a concurrent batch would regress per-module checkpoint durability; SK-029 owns durable partial recovery. |
| 9 | Verify mutation behavior only in the five changed executor/orchestrator files and seal it through the TICKET-002 focused-repair receipt. | The owner prohibited broad mutation reruns, and the accumulated Git diff selects 1,038 unrelated mutants; `CONSTITUTION.md` §19 records the exact exception and keeps the broad run scheduled. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-002-shared-job-executor.md`
- AAR: `docs/planning/knowledge/aar/AAR-002-shared-job-executor.md`
- Architecture: `docs/architecture/executor.md`, `docs/architecture/runner.md`,
  `docs/architecture/engine.md`, `docs/architecture/sast.md`, `docs/architecture/infra.md`, and
  `docs/architecture/cloud.md`

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
