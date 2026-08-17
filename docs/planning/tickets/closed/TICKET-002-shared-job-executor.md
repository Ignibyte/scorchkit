---
title: TICKET-002-shared-job-executor
status: done
ticket_number: 002
type: refactor
created: 2026-08-16
closed: 2026-08-16
intake:
pipeline_spec: docs/planning/pipeline/completed/shared-job-executor.spec.md
---

# Shared bounded job executor

## Summary

Replace the four standard family-specific module scheduling loops with one bounded async job
executor. The executor supplies cooperative cancellation, a whole-batch deadline, a hard
concurrency limit, and submission-ordered outcomes. DAST, SAST, infrastructure, and cloud
orchestrators keep their policy-sealed contexts, module traits, findings, hooks, and event
contracts.

## Why

The current loops create a semaphore permit and then await each module before advancing to the
next. They are therefore serial even though their API documentation says they are concurrent.
They also expose no shared cancellation handle, and `scan.timeout_seconds` limits HTTP requests
rather than the module batch. SK-029 needs a tested execution seam before it can add persisted job
lifecycle and recovery.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When any standard DAST, SAST, infrastructure, or cloud scan runs runnable modules, ScorchKit shall schedule those modules through the same job executor. | One cross-family executor contract suite plus source inspection. |
| REQ-002 | When more runnable jobs exist than the configured concurrency budget, ScorchKit shall run no more than that budget at once and shall reject zero concurrency instead of waiting forever. | Executor concurrency and invalid-budget tests. |
| REQ-003 | When jobs finish in a different order from submission, ScorchKit shall return outcomes, module IDs, and equal-severity findings in deterministic submission order. | Executor ordering test and cross-family result assertions. |
| REQ-004 | When a caller cancels a running family scan, ScorchKit shall stop polling queued and active jobs and return `ScorchError::Cancelled`. | Executor and four-family cancellation contract tests. |
| REQ-005 | When cancellation interrupts pending local HTTP or external-process work, ScorchKit shall release the HTTP connection and terminate the owned process tree within two seconds. | Loopback HTTP and Unix process-tree cancellation tests. |
| REQ-006 | When a module batch exceeds `scan.timeout_seconds`, ScorchKit shall cancel the batch with a typed error while retaining each module's existing request, subprocess, and output limits. | Wall-time budget test and context-boundary inspection. |
| REQ-007 | When DAST recon data or infrastructure fingerprints feed downstream modules, ScorchKit shall finish the producer phase before scheduling its consumers. | DAST phase and infrastructure CVE dependency tests. |
| REQ-008 | When modules are skipped, fail, produce findings, or pass through hooks, ScorchKit shall preserve the existing structured result and lifecycle-event behavior. | Existing orchestrator suites, new contract suite, and diff gate. |

## Scope

- In: a shared executor module; cancellation and budget contracts; standard family integration;
  deterministic result assembly; producer/consumer phases; focused architecture and operator
  documentation; bounded loopback and local-process tests.
- Out: persisted `ScanJob` state, partial recovery, storage, remote cancellation transport, agent
  provider behavior, Windows support, scanner adapter consolidation, and a repository-wide mutation
  campaign.

## Locked decisions

- Keep the executor in the existing crate until SK-033 fixes crate boundaries.
- Keep authorization and effects in the four policy-sealed contexts. The executor only schedules
  futures and never constructs HTTP clients, commands, targets, or credentials.
- Treat cancellation and the batch deadline as fatal orchestration errors. Keep individual module
  errors as deterministic per-module outcomes so sibling jobs may complete.
- Preserve the existing public run methods as wrappers that create a fresh token. Add explicit
  cancellation-aware entry points for SK-029 and other callers.
- Run DAST recon before scanner modules and infrastructure fingerprint producers before
  `CveMatch` consumers. Jobs within a phase may run concurrently.
- Leave checkpoint persistence behavior serial and intact in this ticket. SK-029 owns partial
  recovery and durable job lifecycle.
- Run the approved focused-repair validation for this ticket. Do not start a broad mutation
  campaign.
- Owner approval: mutation validation is limited to the five changed executor/orchestrator files;
  do not run the 1,038-mutant accumulated Git diff. Seal the 68-item focused inventory and exact
  two-survivor recheck under the TICKET-002 amendment in `CONSTITUTION.md` §19. The next broad
  mutation run remains scheduled work.

## Recon

- `Orchestrator`, `CodeOrchestrator`, `InfraOrchestrator`, and `CloudOrchestrator` all acquire a
  semaphore permit and then immediately await `module.run`, so the permit never overlaps another
  module.
- `ScanConfig` already carries `max_concurrent_modules` and `timeout_seconds`. The former can be
  zero and deadlock the current semaphore path. The latter currently configures the shared DAST
  HTTP client but does not bound a full module batch.
- DAST recon modules publish URLs, parameters, technologies, and API specifications consumed by
  scanner modules. Infrastructure `nmap` publishes fingerprints consumed by `CveMatchModule`.
- `SystemToolExecutor` already owns Unix process groups and kills them on future drop. The shared
  executor must preserve that cancellation-safe boundary rather than adding subprocess logic.
- Cloud modules deliberately have no arbitrary HTTP client. Provider transport work remains
  quarantined and outside SK-028.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/shared-job-executor.spec.md`

## Log

- 2026-08-16: opened.
- 2026-08-16: operator authorized resuming and finishing SK-028; full mutation reruns remain out of
  scope.
- 2026-08-16: completed and archived through the repository pipeline; post-archive focused-repair
  receipt is the delivery proof.
