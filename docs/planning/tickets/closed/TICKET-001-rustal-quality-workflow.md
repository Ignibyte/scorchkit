---
title: TICKET-001-rustal-quality-workflow
status: done
ticket_number: 001
type: chore
created: 2026-08-15
closed: 2026-08-16
intake:
pipeline_spec: docs/planning/pipeline/completed/rustal-quality-workflow.spec.md
---

# Adopt Rustal-quality workflow and prove feature readiness

## Summary

Adopt a repository-owned, Rustal-style ticket-to-delivery workflow, then use it to remove the
current product and quality baseline debt. Delivery requires a worktree-bound green receipt, a
reviewed mutation-blind ledger, focused validation of repaired mutation seams, and a reviewed
technical-debt roadmap. A complete full-repository mutation campaign remains scheduled evidence
under the repository owner's 2026-08-16 scope amendment.

## Why

ScorchKit's legacy pipeline records were driven by Claude commands and a Forge sidecar that no
longer exists. The project needs the same rigor without tying policy or state to one agent host.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ready work is created, ScorchKit shall allocate one canonical ticket with a linked spec, notes pair, and open AAR while refusing a second active pipeline. | `bin/pipeline.sh selftest`; live TICKET-001 artifact census. |
| REQ-002 | When a phase transition is requested, ScorchKit shall accept it only from the preceding PASS state and only after phase-specific evidence exists. | State-machine negative tests and live phase transitions. |
| REQ-003 | When the quality gate runs, ScorchKit shall execute Rustal's non-web gates with stable numbering, emit named skips for web gates 17–19, and run PostgreSQL plus CLI/MCP contract gates 21–22. | `GATE_SELFTEST=1 bash bin/gate.sh`; canonical fast-gate output; `CONSTITUTION.md` parity table. |
| REQ-004 | When a DIFF or FULL gate is green, ScorchKit shall write a content receipt that remains valid across staging but becomes invalid after any worktree content change. | `.githooks/pre-commit --selftest`; `bin/pipeline.sh receipt`. |
| REQ-005 | When Clippy runs locally or in CI, ScorchKit shall derive default, all-feature, and isolated feature states from `Cargo.toml` rather than a copied feature list. | `bin/feature-states.sh --selftest`; CI workflow inspection. |
| REQ-006 | When Codex receives implementation work in this repository, it shall be able to discover a repo-scoped pipeline skill that drives the same agent-neutral scripts and files. | Skill validator; `.agents/skills/scorchkit-pipeline/agents/openai.yaml`. |
| REQ-007 | When mutation testing runs from the HDD/SMB checkout, ScorchKit shall keep worker builds and detailed results on local scratch, enforce MSI 95%, and retain compact evidence under `.git`. | One-mutant end-to-end shard and `bin/mutants.sh --inspect`. |
| REQ-008 | When a facade, CLI, MCP, project, or scheduled operation can create a network, filesystem, cloud, credential, or subprocess effect, ScorchKit shall deny it before resource creation unless one engagement authorizes the canonical target, capability, and effect. | Policy contract tests across every public effect entry point plus mutation and local loopback proofs. |
| REQ-009 | When an authorized web operation redirects or resolves a hostname, ScorchKit shall authorize every resulting URL and address against the same engagement before connecting. | Loopback redirect, IPv4/IPv6 resolution, private-address, metadata-address, and DNS-change regression tests. |
| REQ-010 | When an external process times out, is cancelled, exceeds its output limit, or is dropped, ScorchKit shall terminate its owned process tree and render untrusted output without terminal control effects. | Parent/descendant lifecycle tests and terminal-control property/fixture tests. |
| REQ-011 | When any number of callers request due-schedule execution, ScorchKit shall execute each claimed due row at most once without exhausting the PostgreSQL pool or holding a transaction across scan effects. | One-slot and N-caller PostgreSQL tests with bounded completion and exact persisted scan counts. |
| REQ-012 | When feature-readiness validation runs under the 2026-08-16 owner amendment, ScorchKit shall retain the completed canonical DIFF evidence, review every mutation-blind changed file, validate only the repaired mutation seams at the 95% floor, and schedule the full inventory without presenting an interrupted run as green. | Canonical DIFF ledger, focused repair outcomes under `.git/scorchkit-mutants-focused-ticket-001`, interrupted-run evidence under `.git/scorchkit-mutants-last`, and the scheduled roadmap item. |
| REQ-013 | When the baseline is declared feature-ready, ScorchKit shall publish a source-backed roadmap that separates closed work, accepted technical debt, ordered refactor batches, dependencies, and exit evidence. | Roadmap census against scan findings, inspect ledger, gate receipts, and remaining source debt. |
| REQ-014 | When TICKET-001 delivery follows the approved focused repair campaign, ScorchKit shall reconstruct the result from raw outcomes, reject changed mutation inputs or evidence, rerun every non-mutation delivery lane, and write a receipt that identifies and binds focused evidence without launching cargo-mutants. | Focused evidence selftest and verifier; gate, pipeline, and hook selftests; `bash bin/gate.sh --focused-repair`; versioned receipt readback. |

## Scope

- In: constitution, ticket/spec/notes/AAR templates and state machine, knowledge register,
  repository skill, feature-state derivation, quality-gate parity, receipt and Git hook, CI parity,
  mutation scratch alignment, authorization and execution-boundary refactors, accepted security
  fixes, mutation-blind review, canonical DIFF evidence, focused mutation repair, scheduled full
  mutation evidence, roadmap, and agent guidance.
- Out: browser UI, Playwright, website rendering, CSS build gates, remote or third-party scan
  execution, and new product features beyond the feature-readiness baseline.

## Locked decisions

- The workflow core is agent-neutral; Codex receives a thin repo-scoped skill adapter.
- Git, not an agent transcript parser, enforces the final delivery receipt.
- Rustal gate numbers remain stable; non-applicable web gates are visible skips, not repurposed IDs.
- ScorchKit-specific database and contract gates append as 21 and 22.
- The 2026-08-16 owner direction authorizes a focused-repair receipt for TICKET-001 under the explicit
  `CONSTITUTION.md` §19 conditions. Ordinary future tickets continue to use DIFF or FULL.

## Recon

- Rustal's binding workflow is plan → design → implement → inspect → validate → complete → delivery.
- Rustal's non-web quality set is gates 1–16 and 20; web-only gates are 17–19.
- ScorchKit had 14 static checks but no feature-state deriver, phase state machine, receipt, or commit
  enforcement. Its database and contract checks occupied Rustal's web gate numbers.
- Official OpenAI documentation places repo-scoped skills under `.agents/skills`.

## Notes

- Completed pipeline: `docs/planning/pipeline/completed/rustal-quality-workflow.spec.md`

## Log

- 2026-08-15: opened.
- 2026-08-15: repository owner directed exact Rustal-quality workflow parity except web checks.
- 2026-08-15: repository owner expanded the ticket to include the product refactor, complete
  baseline remediation, full mutation sweep, thorough code review, and sealed technical-debt
  roadmap before feature development begins.
- 2026-08-16: repository owner stopped the long full mutation sweep and directed validation to run
  only against repaired seams. The incomplete full result remains labeled incomplete, and a fresh
  full inventory moved to scheduled evidence rather than TICKET-001 acceptance.
- 2026-08-16: the focused-repair gate passed 19 applicable gates, verified 162/162 viable repaired
  mutations without launching cargo-mutants, and produced the versioned receipt consumed by the
  Validate transition.
- 2026-08-16: a post-archive coverage pass exposed and repaired the bounded process-exit teardown
  race. Mutation remained limited to the two repaired functions: five viable caught, zero missed,
  and one unviable, raising cumulative focused evidence to 167/167 viable caught.
