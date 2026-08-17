---
aar: AAR-003-scan-job-lifecycle
ticket: TICKET-003
pipeline: scan-job-lifecycle
status: submitted
opened: 2026-08-16
submitted: 2026-08-16
effectiveness: 5 - recalled rules shaped the design and inspection closed every discovered lifecycle defect
---

# AAR-003 — Durable scan job lifecycle and storage abstraction

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Resume can otherwise turn stored context into authorization. | Yes — the successor attempt must reauthorize before rebuilding its context. |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | A job adds setup, persistence, and terminal publication around SK-028. | Yes — cancellation linearization covers those adjacent steps. |
| `PR-scorchkit-observable-seams-001` | A status wrapper could exist without controlling execution. | Yes — the job service owns the actual token and persisted transition. |
| `PR-scorchkit-global-set-lock-001` | Startup recovery and concurrent writers operate over shared rows. | Yes — optimistic revisions and one recovery claim prevent duplicate ownership. |
| `PR-scorchkit-ticket-diff-baseline-001` | SK-028 began on an accumulated diff and needed focused evidence. | Yes — baseline `d65a67a` was committed before TICKET-003 opened. |
| `docs/architecture/executor.md` | SK-028 intentionally excluded durable jobs and partial results. | Yes — persistence stays outside `JobExecutor`. |

## What happened

SK-029 added a provider-neutral `ScanJob` lifecycle around DAST execution. The service authorizes
before persistence, owns cancellation and recovery, commits module progress through a bounded
reliable channel, and stores immutable attempts through either an in-memory or PostgreSQL adapter.
CLI and MCP clients can start, inspect, cancel, recover, and resume jobs. MCP also starts without a
database for stateless work while database-only tools fail explicitly.

The inspection found eight high or medium lifecycle defects before delivery. The fixes added drop
cleanup, idempotent cross-service cancellation, unique successor lineage, credential-bearing URL
rejection, fail-closed control-task behavior, validation inside both stores, and bounded progress,
listing, and recovery. The final focused-repair gate passed all 19 applicable lanes with 79.55% line
coverage, 1,433/1,433 Nextest cases, PostgreSQL integration, CLI/MCP process contracts, and sealed
mutation evidence reconstructing 233/233 viable outcomes. A separate final-tree follow-up caught
all 41 mutants generated for the two mechanically edited validator functions.

## Novel findings

- A public storage trait is part of the lifecycle security boundary. Service-layer validation did
  not stop another caller from changing immutable request fields, forging successor lineage, or
  bypassing legal transitions.
- A best-effort event bus cannot be used as a recovery commit point. Completed-module evidence needs
  one bounded reliable path that commits findings and module completion together.
- A fail-closed process test can still be ambiguous when two branches both exit unsuccessfully. The
  assertion must identify which failure source won.
- Focused mutation evidence needs ticket-neutral discovery, timeout accounting, exact input
  transitions, and a digest bound to the delivery receipt. A ticket-number special case was not a
  reusable repository control.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-job-owner-drop-001` | Aborting the run future left heartbeat and active-token ownership alive. | Lifecycle inspection and future-abort regression. |
| `BF-scorchkit-concurrent-cancel-same-state-001` | A losing cancellation writer retried a same-state transition and returned an error. | Cross-service cancellation inspection. |
| `BF-scorchkit-resume-fork-001` | Concurrent resume calls could create more than one successor attempt. | Store-lineage inspection and concurrency tests. |
| `BF-scorchkit-ambiguous-failure-source-001` | An exit-only startup test could not distinguish database failure from stateless EOF. | Focused mutation repair preflight. |
| `BF-scorchkit-focused-evidence-ticket-coupling-001` | Focused evidence verification assumed one old ticket shape and could not reconstruct timeout-bearing or multi-snapshot repairs. | Gate and verifier inspection. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-store-invariants-falsification-001` | Enforce creation, replacement, transition, and lineage invariants inside every public store implementation and test direct callers against the shared contract. | A service is not the only possible caller of a public storage trait. |
| `PR-scorchkit-exact-failure-source-001` | When several fail-closed branches produce the same status, assert the selected error or state, not only that the operation failed. | Status-only tests can pass after control flow is inverted. |
| `PR-scorchkit-focused-evidence-generic-001` | Discover focused evidence from approved ticket metadata and verify raw outcomes, timeouts, snapshots, input hashes, and evidence digest without ticket-number branches. | A repository quality control must work for the next ticket without code changes. |
| `PR-scorchkit-clippy-before-mutation-seal-001` | Run strict all-target Clippy after adding mutation assertions and before sealing the current-tree mutation hash. | Mechanical ownership repairs after sealing require another exact function-level proof. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. The recalled rules directly determined authorization on resume, whole-lifecycle
cancellation, optimistic concurrency, and the clean SK-028 baseline. Inspection still found eight
concrete defects, but all were fixed before validation and each fix received a direct regression.
No rule was weakened, no remote target was used, and mutation reruns stayed within the owner's
approved survivor and follow-up function scopes.
