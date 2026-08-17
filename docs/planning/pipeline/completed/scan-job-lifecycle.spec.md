---
title: Durable scan job lifecycle and storage abstraction
pipeline_id: 14c13839-5292-4c3a-a832-639b87143ce5
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-003
ticket_doc: docs/planning/tickets/closed/TICKET-003-scan-job-lifecycle.md
aar: docs/planning/knowledge/aar/AAR-003-scan-job-lifecycle.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-003
created: 2026-08-16
---

# Durable scan job lifecycle and storage abstraction — spec

## Intent

Ship the SK-029 job contract that later Codex and MCP work can depend on: an authorized DAST request
becomes a stored, cancellable, observable job; partial completed-module evidence survives an
interruption; resume reauthorizes and runs only remaining modules; and the same contract works in
memory or PostgreSQL. Local MCP must no longer require a database merely to start or run a stateless
scan.

## Scope

- In: job domain types and legal transitions; store trait and two implementations; PostgreSQL
  migration; DAST job adapter and progress sink; recovery/resume; CLI job operations; MCP job tools;
  optional database attachment; compatibility tests and docs.
- Out: non-DAST family adapters; remote transport/authentication; SK-030 provider changes; SK-032
  MCP structured-content and annotation redesign; SK-033 crate moves; full mutation inventory.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authorized DAST job is submitted, ScorchKit shall store the queued job and immutable request before execution begins. | Probe-runner ordering and store-readback tests. |
| REQ-002 | When lifecycle state changes, ScorchKit shall enforce the legal transition table with optimistic revision checks and complete timestamps. | Pure transition tests and shared store CAS tests. |
| REQ-003 | While a job runs, ScorchKit shall durably expose module totals and active/completed/skipped/failed sets and retain findings only after their producing module completes. | Authorized loopback progress/partial-evidence tests. |
| REQ-004 | When cancellation is requested before or during execution, ScorchKit shall return an idempotent cancelling/cancelled state, signal the shared cancellation token, and never publish a successful job. | Queued and in-flight cancellation tests plus executor cleanup regressions. |
| REQ-005 | When a process restarts with nonterminal jobs, ScorchKit shall mark them interrupted; when resume is requested, ScorchKit shall reauthorize the immutable request, link a new attempt, and exclude completed modules. | Recovery/resume conformance tests and changed-engagement denial. |
| REQ-006 | When either job store implementation is selected, ScorchKit shall preserve equivalent serialization, ordering, and stale-revision behavior. | One store contract suite run against memory and migrated PostgreSQL. |
| REQ-007 | When MCP is started without a configured database, ScorchKit shall remain usable for stateless scans and job control and shall fail database-only operations explicitly. | Stdio server startup test, loopback MCP scan job, and DB-tool negatives. |
| REQ-008 | When CLI or MCP clients use the lifecycle, ScorchKit shall expose start/run, status, cancel, recover, and resume through host-owned interfaces while the library publishes structured state only. | CLI process contracts, MCP integration tests, and source inspection for terminal isolation. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put job types and the store trait under `runner::job`, with storage adapters depending on that contract. | SK-033 can later move the stable contract into executor/core without making execution depend on SQL or MCP. |
| 2 | Use optimistic revisions for every persisted mutation. | Cancellation, progress, and terminal completion can race without allowing stale success to overwrite cancellation. |
| 3 | Add a reliable per-job progress sink at the orchestrator boundary rather than treating best-effort `EventBus` delivery as durable evidence. | Broadcast lag is valid for observability but not for recovery state. |
| 4 | Persist findings as part of a completed module update. | A resumed job may safely skip a module only when its evidence was committed atomically with completion. |
| 5 | Resume into a successor attempt and re-run authorization against the current engagement before constructing effects. | History stays immutable and a stored request cannot outlive or broaden authorization. |
| 6 | Keep synchronous MCP `scan` as a compatibility wrapper while adding explicit asynchronous job operations. | Existing clients remain source-compatible until SK-032 versions the typed MCP surface. |
| 7 | Represent the MCP database pool as optional and guard every database-only method through one helper. | Stateless server startup must not manufacture a lazy pool or defer a misleading connection failure. |
| 8 | Keep the legacy checkpoint CLI path readable during SK-029 and document job mode as its replacement. | Recovery behavior changes in a controlled path; removal can happen after compatibility evidence. |
| 9 | Preserve the completed 279-mutant DIFF run, repair its 61 survivors, and validate only that exact survivor set. | The owner stopped repeat mutation sweeps and required repaired-scope reruns; the sealed focused result remains tied to the completed broad baseline. |

## Owner-approved focused repair scope

On 2026-08-16 the repository owner directed: “we should not be doing full scans again on mutation”
and required mutation reruns only for fixed code, with a later full run. The later “approved and
commit” instruction confirms local delivery after this proof. The exact repair scope is the complete
61-survivor set from the completed 279-mutant DIFF baseline, covering 23 functions in four files:

- `src/cli/job.rs`: `comma_separated`
- `src/mcp/server.rs`: `serve`
- `src/mcp/tools.rs`: `ScorchKitServer::do_correlate_findings`,
  `ScorchKitServer::do_project_findings`, `ScorchKitServer::do_scan_job_resume`,
  `ScorchKitServer::do_scan_progress`, `ScorchKitServer::scan_job_cancel`,
  `ScorchKitServer::scan_job_resume`, and `completed_job_result`
- `src/runner/job.rs`: `<impl JobStore for InMemoryJobStore>::create`,
  `<impl JobStore for InMemoryJobStore>::list`,
  `<impl JobStore for InMemoryJobStore>::list_recoverable`,
  `ActiveRunGuard::track_heartbeat`, `ScanJob::transition`, `ScanJob::validate_create`,
  `ScanJob::validate_replacement`, `ScanJob::validate_successor`, `ScanJobProgress::normalize`,
  `ScanJobProgress::processed_modules`, `ScanJobService::finish_failed`, `ScanJobService::list`,
  `ScanJobService::try_recover`, and `lease_deadline`

The broad raw inventory and outcomes, exact survivor inventory and recheck, four pre-repair input
snapshots, mutation-input hashes, and reconstructed 233/233 viable score are sealed under
`.git/scorchkit-mutants-focused-ticket-003`. No repeat 279-mutant or repository-wide run is in
scope.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-003-scan-job-lifecycle.md`
- AAR: `docs/planning/knowledge/aar/AAR-003-scan-job-lifecycle.md`
- Architecture: `docs/architecture/jobs.md`, `docs/architecture/executor.md`,
  `docs/architecture/storage.md`, `docs/architecture/mcp.md`, and `docs/architecture/cli.md`.

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
