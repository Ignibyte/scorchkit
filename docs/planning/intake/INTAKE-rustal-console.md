---
title: INTAKE-rustal-console
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Optional Rustal local operator console

## Problem or opportunity

A full ScorchKit suite needs durable navigation, live job status, evidence drill-down, triage, and
engagement editing beyond compact conversation components. Rustal already provides a Rust web
framework with compiled pages, modules, authentication/RBAC, audit, PostgreSQL support, and
server-sent updates, but ScorchKit core must remain usable without it.

## Proposed outcome

A separate `scorchkit-console` application built with Rustal consumes the ScorchKit control API and
shared view models. It offers a local operator dashboard without owning ScorchKit policy, evidence,
jobs, or storage.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the console starts in its default profile, it shall bind only to loopback or an operating-system-protected local socket and shall connect to ScorchKit through the versioned control API rather than internal Rust types or database tables. | Startup, dependency, API-client, non-loopback denial, and direct-database negative tests. |
| REQ-002 | When an operator views live work, the console shall render job, module, coverage, cancellation, and terminal-state events from the canonical event stream and shall recover after a bounded reconnect. | Browser event-stream and reconnect tests. |
| REQ-003 | When findings are inspected or triaged, the console shall display scanner evidence, model analysis, transition history, suppressions, attack paths, and degraded coverage as distinct data. | Browser snapshots and cross-surface parity tests. |
| REQ-004 | When an operator edits an engagement, starts or cancels work, or changes triage state, the console shall call an authenticated API command and shall not infer permission from a rendered page, session label, or project membership. | RBAC, CSRF, spoofing, denial, and audit tests. |
| REQ-005 | When ScorchKit is built without the console, its core library, CLI, local MCP, configuration, storage, and execution contracts shall remain complete and shall have no Rustal dependency edge. | Workspace dependency and headless contract tests. |
| REQ-006 | When the console becomes shippable, ScorchKit shall replace the current web not-applicable gate skips with executable browser, rendering, and asset-drift evidence appropriate to the delivered surface. | Gate selftest and browser/build lanes. |

## Scope notes

- In: separate Rustal application, compiled/server-rendered pages, shared view models, live local
  operation, engagement/job/evidence/triage UI, browser delivery gates.
- Out: ScorchKit core dependency on Rustal, direct ScorchKit database writes, public hosting,
  multi-tenant service, marketplace, or frontend authorization shortcuts.
