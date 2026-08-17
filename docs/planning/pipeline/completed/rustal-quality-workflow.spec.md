---
title: Adopt Rustal-quality workflow and prove feature readiness
pipeline_id: b1b510c8-0096-4083-af37-2ffaea595b10
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-001
ticket_doc: docs/planning/tickets/closed/TICKET-001-rustal-quality-workflow.md
aar: docs/planning/knowledge/aar/AAR-001-rustal-quality-workflow.md
created: 2026-08-15
---

# Adopt Rustal-quality workflow and prove feature readiness — spec

## Intent

Ship the repository infrastructure required to take any ScorchKit change from a local numbered
ticket through confirmed planning, design, implementation, adversarial inspection, validation,
completion, and receipt-gated delivery. Dogfood that workflow on the current product refactor until
the security, correctness, database, coverage, and mutation baselines are green and the remaining
technical debt has an evidence-backed roadmap.

## Scope

- In: policy docs, ticket and knowledge stores, deterministic phase tooling, Codex skill adapter,
  gate-state hashing, Git hook, gate/CI parity, mutation-runner alignment, self-tests, accepted
  security and correctness fixes, product boundary refactors, mutation-blind review, completed DIFF
  evidence, focused mutation repair, scheduled full mutation evidence, and the feature-readiness
  roadmap.
- Out: remote or third-party target scans, web UI and its three gates, and new product features that
  depend on the completed baseline.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ready work is created, ScorchKit shall create exactly one linked ticket/spec/notes/AAR set and refuse another active set. | Pipeline selftest plus live artifact census. |
| REQ-002 | When phases advance, ScorchKit shall enforce ordered states and evidence checks through one canonical script. | Negative transition probes and live dogfood run. |
| REQ-003 | When local or CI quality runs, ScorchKit shall preserve Rustal gate numbering and semantics for gates 1–16 and 20, name web-only skips 17–19, and append project gates 21–22. | Gate selftest, fast gate, CI inspection. |
| REQ-004 | When delivery validation is green, ScorchKit shall bind it to exact worktree content and Git shall reject missing or stale receipts. | Hook receipt selftest and live receipt verification. |
| REQ-005 | When supported features change, gate:2 and CI shall derive their Clippy states from the manifest automatically. | Feature-state selftest and derived output census. |
| REQ-006 | When Codex handles ScorchKit implementation work, a valid repository skill shall guide the agent through the same canonical scripts and artifacts. | Skill quick validator and metadata inspection. |
| REQ-007 | When cargo-mutants runs, all large disposable I/O shall use local scratch with 95% MSI and compact durable evidence. | Config inventory and bounded real mutant run. |
| REQ-008 | When any public path can create a network, filesystem, cloud, credential, or subprocess effect, it shall require one engagement decision for the canonical target, capability, and effect before creating the effectful resource. | Facade, CLI, MCP, project, schedule, and executor policy contracts. |
| REQ-009 | When HTTP redirects or DNS resolution change a web destination, the client shall reauthorize the resulting URL and every address before connecting. | Loopback redirect, IPv4/IPv6, private/metadata address, and DNS-change tests. |
| REQ-010 | When an owned external process ends abnormally or its output reaches a terminal, ScorchKit shall terminate the process tree and neutralize terminal controls without changing structured evidence. | Process-tree lifecycle tests and terminal rendering fixtures/property tests. |
| REQ-011 | When due-schedule callers overlap, the executor shall finish within a bound, avoid pool starvation, and persist at most one scan per claimed schedule. | One-slot and N-caller migrated-PostgreSQL integration tests. |
| REQ-012 | When feature-readiness validation runs under the 2026-08-16 owner amendment, ScorchKit shall retain the completed canonical DIFF result, close the mutation-blind ledger, validate only repaired mutation seams at the baked floor, and record the full inventory as scheduled evidence without claiming an incomplete run passed. | Reviewed blind-file ledger, prior DIFF output, focused outcomes and exact recheck, interrupted-full evidence, and roadmap schedule. |
| REQ-013 | When the ticket completes, the roadmap shall identify closed work and every accepted remaining debt item with order, dependency, and executable exit evidence. | Final source census, inspect ledger, scan report, gate evidence, and roadmap review. |
| REQ-014 | When TICKET-001 uses the owner-approved focused repair path, the delivery gate shall reconstruct counts and survivor identity from raw outcomes, reject undeclared mutation-input or evidence changes, prove any later repair transition from sealed old content, rerun all non-mutation delivery lanes, and issue an explicit focused receipt without running cargo-mutants. | Evidence-verifier transition negatives, script and hook selftests, focused-repair gate output, and receipt metadata readback. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep policy and state in versioned repository files. | No agent host or sidecar should own delivery truth. |
| 2 | Use a real Git pre-commit hook for receipt enforcement. | It applies equally to agents and humans. |
| 3 | Preserve gate IDs 17–19 as explicit web skips. | Reusing IDs would stale Rustal-derived documentation and evidence. |
| 4 | Append PostgreSQL and CLI/MCP checks as gates 21–22. | These are project-specific delivery requirements, not web substitutes. |
| 5 | Use the explicit focused-repair receipt for TICKET-001 only. | The owner stopped broad rescans after repair. The §19 verifier preserves the 95% floor, exact survivor identity, input hash, evidence digest, and all current non-mutation lanes. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-001-rustal-quality-workflow.md`
- AAR: `docs/planning/knowledge/aar/AAR-001-rustal-quality-workflow.md`
- Architecture: `CONSTITUTION.md`, `AGENTS.md`, `SECURITY.md`

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | security fixes, baseline debt, tests, mutation-blind review, prior DIFF evidence, and focused repair mutation | green focused-repair gate, bound evidence, and complete ledgers |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
