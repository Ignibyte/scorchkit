---
title: INTAKE-dependency-debt
status: candidate
created: 2026-08-17
ticket: TICKET-024
pipeline_spec: docs/planning/pipeline/active/dependency-debt.spec.md
---

# Dependency and advisory debt retirement

## Problem or opportunity

Reachable unmaintained transitive dependencies and the time-bounded disabled-MySQL advisory
exception remain accepted debt. Leaving them indefinite weakens the repository's own supply-chain
posture while ScorchKit claims to assess application dependencies.

## Proposed outcome

The reachable `fxhash` and `number_prefix` paths will be replaced or upgraded, the reviewed MySQL
exception will be removed, and the strict audit, license, source, and unused-dependency gates will
pass without broad ignores.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the workspace dependency graph is resolved, ScorchKit shall not contain reachable unmaintained `fxhash` or `number_prefix` paths. | Cargo tree and cargo-deny evidence. |
| REQ-002 | When disabled MySQL features are evaluated, ScorchKit shall remove the time-bounded advisory exception without enabling an affected path. | Feature-state audit and dependency tests. |
| REQ-003 | When replacements alter public or stored behavior, ScorchKit shall preserve compatibility or version the change explicitly. | Package, storage, CLI, and MCP regression tests. |
| REQ-004 | When the ticket validates, cargo audit, cargo deny, and cargo machete shall pass without a new broad ignore or unused direct dependency. | Canonical gate evidence. |

## Scope notes

- In: named dependency paths, advisory exception, feature-state verification, lockfile changes.
- Out: unrelated dependency upgrades, reduced audit strictness, new advisory baselines.
