---
title: TICKET-003-scan-job-lifecycle
status: done
ticket_number: 003
type: feature
created: 2026-08-16
closed: 2026-08-16
intake:
pipeline_spec: docs/planning/pipeline/completed/scan-job-lifecycle.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-003
---

# Durable scan job lifecycle and storage abstraction

## Summary

Add a provider-neutral `ScanJob` control plane around DAST execution. A job is authorized before it
is accepted, persists its request and monotonic lifecycle, reports module-level progress, owns the
SK-028 cancellation token, retains completed-module findings after interruption, and can resume the
remaining work under the same engagement. The control plane uses one storage trait with in-memory
and PostgreSQL implementations. MCP can start without PostgreSQL for stateless jobs; database tools
remain explicit and fail closed when no pool is attached.

## Why

MCP currently blocks on a complete scan and refuses to start without a database, while its
`scan_progress` tool only reports the most recently completed project record. The old CLI checkpoint
is DAST-only, file-coupled, serial, and has no shared cancellation owner. SK-028 supplied bounded
concurrent execution and safe cancellation; SK-029 must turn those mechanics into an observable,
recoverable lifecycle before agent workflows and typed MCP contracts are added.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authorized DAST job is submitted, ScorchKit shall persist a unique queued job and its immutable request before any scanner module is polled. | Job-service ordering test with a probe runner and store readback. |
| REQ-002 | When a job advances, ScorchKit shall allow only the documented monotonic state transitions and shall persist revision, attempt, and lifecycle timestamps with compare-and-swap protection. | State-machine table tests plus concurrent in-memory and PostgreSQL compare-and-swap tests. |
| REQ-003 | While modules execute, ScorchKit shall persist total, active, completed, skipped, and failed module progress plus findings from completed modules without changing deterministic final result order. | Loopback job progress test, partial snapshot assertions, and existing orchestrator ordering suite. |
| REQ-004 | When a queued or running job is cancelled, ScorchKit shall make cancellation idempotent, signal the SK-028 token, stop publishing success, and preserve completed-module evidence. | Pre-start and in-flight cancellation tests including loopback cleanup and partial-state readback. |
| REQ-005 | When startup recovery finds a nonterminal stored job, ScorchKit shall mark it interrupted without discarding progress; when an operator resumes it under the unchanged engagement, ScorchKit shall create the next attempt and skip already completed modules. | In-memory and PostgreSQL recovery/resume tests plus an authorization-change negative test. |
| REQ-006 | When the same job contract is used with the in-memory or PostgreSQL store, ScorchKit shall return equivalent records and reject stale writers. | Shared store conformance suite against both implementations. |
| REQ-007 | When MCP starts without database configuration, ScorchKit shall serve stateless job tools using the in-memory store, while project, schedule, finding, and migration tools return a typed database-unavailable error. | Transport-level stateless MCP integration and storage-tool negative tests. |
| REQ-008 | When CLI and MCP clients operate a job, ScorchKit shall expose submit/run, status, cancellation, interruption recovery, and resume behavior without requiring shell-generated scanner instructions. | CLI command contract tests and MCP lifecycle integration tests against authorized loopback targets. |

## Scope

- In: DAST `ScanJob` types and state machine; job service; module progress capture; in-memory and
  PostgreSQL stores; migration; recovery and resume; CLI job commands; asynchronous MCP job tools;
  optional MCP database attachment; compatibility wrappers; architecture and operator docs.
- Out: SAST/infra/cloud job adapters; remote MCP transport; remote principals; provider reasoning;
  typed MCP content/annotations (SK-032); crate extraction (SK-033); scheduled scans; full mutation
  inventory; any non-loopback scan.

## Locked decisions

- Keep authorization in `Engine` and the family context. A stored request or prior approval never
  authorizes a resume.
- Keep `JobExecutor` free of persistence. A DAST job adapter observes orchestrator lifecycle and
  writes job snapshots through the storage trait.
- Treat queued/running/cancelling jobs left by a dead process as interrupted, not failed or
  successful. Resume creates a new attempt linked to the prior job.
- Retain the synchronous `scan` MCP behavior for compatibility while adding asynchronous job tools.
- MCP stdio starts stateless by default. Database-backed tools are available only when a pool is
  explicitly attached.
- Preserve the completed 279-mutant diff baseline and repair its exact 61-survivor set. Do not
  repeat that diff sweep or run the full mutation inventory; the next broad run remains scheduled.

## Recon

- Baseline commit `d65a67a` establishes the clean SK-028 boundary required by
  `PR-scorchkit-ticket-diff-baseline-001`.
- `JobExecutor` already owns bounded concurrency, whole-batch deadlines, deterministic outcomes,
  and a cloneable cancellation token but deliberately has no persistence.
- `ScanEvent` exposes the needed module lifecycle and findings, but its broadcast channel is
  best-effort and may lag; durable progress therefore cannot claim that channel alone as its commit
  boundary.
- The existing file checkpoint runs DAST serially and deletes itself on success. It is retained as
  a compatibility path until the job adapter proves concurrent partial recovery.
- `ScorchKitServer` currently stores a mandatory `PgPool`, and `serve` connects before starting,
  even for `scan`, `list_modules`, and other stateless tools.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/scan-job-lifecycle.spec.md`

## Log

- 2026-08-16: opened.
- 2026-08-16: operator approved local baseline and per-ticket commits and directed SK-029 through
  SK-033 to run back to back; remote delivery remains unauthorized.
- 2026-08-16: the completed DIFF run selected 279 mutants and exposed 61 survivors. The owner had
  explicitly stopped repeat mutation scans and limited reruns to fixed code, then said “approved
  and commit.” The exact approved repair scope is the 61 survivors in 23 functions/four files listed
  in the linked spec; the focused recheck caught all 61 and reconstructs 233/233 viable outcomes.
- 2026-08-16: the receipt-producing focused-repair gate passed all 19 applicable lanes with zero
  failures and three named web-only skips. It measured 79.55% line coverage, passed 1,433/1,433
  Nextest cases, verified PostgreSQL and CLI/MCP contracts, and validated the sealed mutation
  evidence without starting cargo-mutants.
