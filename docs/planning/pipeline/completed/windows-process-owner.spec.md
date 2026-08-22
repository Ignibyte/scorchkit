---
title: Add Windows Job Object process ownership
pipeline_id: a81bce64-b43b-4a12-a121-6be485404508
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-023
ticket_doc: docs/planning/tickets/closed/TICKET-023-windows-process-owner.md
aar: docs/planning/knowledge/aar/AAR-023-windows-process-owner.md
created: 2026-08-22
---

# Add Windows Job Object process ownership — spec

## Intent

Ship SK-045 by enabling Windows builds with the same owned descendant-process lifecycle already
enforced on Unix. The one-shot executor and long-lived Interactsh session create Windows children
suspended, establish kill-on-close Job Object ownership, and resume only after that boundary is
ready; Unix behavior and all public tool-result contracts remain unchanged.

## Scope

- In: a platform-owned child abstraction in `scorchkit-tools`; Windows suspended spawn and Job
  Object ownership; one-shot and Interactsh lifecycle integration; forced ownership-failure and
  descendant-cleanup tests; Windows workspace CI; supported-host documentation.
- Out: Windows-specific scanners or UI; weaker cleanup, timeout, output, artifact, policy, or audit
  semantics; changes to process result schemas; replacement of the proven Unix process-group
  backend; support for non-Unix, non-Windows targets.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the bounded tool executor or Interactsh launches a process on Windows, ScorchKit shall create it suspended, assign it and inheriting descendants to an owned kill-on-close Job Object, and resume it only after ownership succeeds. | Windows pre-resume marker test, process-tree fixture, and implementation inspection. |
| REQ-002 | When a Windows-owned process succeeds, exits nonzero, times out, is cancelled, exceeds an output or artifact limit, is explicitly stopped, or loses its owner, ScorchKit shall terminate and release its descendants within two seconds. | Windows lifecycle matrix using a child-and-descendant fixture and bounded process-state assertions. |
| REQ-003 | When Windows Job Object ownership cannot be established, ScorchKit shall return a typed infrastructure failure before the suspended process performs scanner work. | Forced ownership-setup failure with an absent side-effect marker. |
| REQ-004 | When the same bounded invocation runs on Windows or Unix, ScorchKit shall preserve executable resolution, stdin, stdout, stderr, exit-policy, timeout, output-limit, artifact-limit, and `ToolOutput` serialization behavior. | Cross-platform executor contract fixtures and existing Unix lifecycle suite. |
| REQ-005 | When the supported workspace is built and tested in CI, ScorchKit shall compile on Windows and execute the Windows process-owner lifecycle suite. | Required `windows-latest` workspace Clippy/test job plus local Windows-target compilation. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep the existing Unix process-group owner and its bounded macOS exit-race reconciliation unchanged. | SK-045 adds a platform peer and must not regress the already sealed Unix lifecycle. |
| 2 | On Windows, use a target-only safe process-wrapper dependency that creates the process suspended, assigns a kill-on-close Job Object, and resumes only after assignment. | This prevents descendants escaping between spawn and ownership while retaining the repository-wide unsafe-source ban. |
| 3 | Wrap the Tokio child and platform owner behind one `scorchkit-tools` owned-process type used by both one-shot and Interactsh paths. | One owner keeps wait, output capture, stop, and drop semantics aligned without leaking platform APIs into scanner adapters. |
| 4 | Wait for the direct child during normal I/O, then terminate and reap the complete owned tree before interpreting success or failure. | A successful parent may leave descendants; waiting for the whole Job first would instead convert that case into a timeout. |
| 5 | Fail closed on any Windows ownership setup error and provide no direct-child-only fallback. | Running scanner work without descendant ownership would violate the security invariant. |
| 6 | Keep a two-second Windows cleanup bound and existing public invocation/result schemas. | Platform enablement must preserve cancellation and compatibility contracts. |
| 7 | Add a native Windows CI job that runs workspace Clippy/tests; validate delivery through ordinary DIFF mode. | Cross-compilation cannot execute Job Object semantics, and FULL mutation is reserved for scheduled/release work. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-023-windows-process-owner.md`
- AAR: `docs/planning/knowledge/aar/AAR-023-windows-process-owner.md`
- Architecture:
  - `docs/architecture/runner.md`
  - `docs/architecture/executor.md`
  - `docs/architecture/overview.md`
  - `docs/architecture/vision.md`
  - `docs/architecture/workspace.md`

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
