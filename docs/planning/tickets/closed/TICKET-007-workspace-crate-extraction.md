---
title: TICKET-007-workspace-crate-extraction
status: done
ticket_number: 007
type: refactor
created: 2026-08-17
closed: 2026-08-17
intake:
pipeline_spec: docs/planning/pipeline/completed/workspace-crate-extraction.spec.md
focused_repair: approved
---

# Behavior-preserving workspace crate extraction

## Summary

Convert the single-package Rust project into a workspace whose policy, domain, configuration,
executor, process, scanner-family, storage, MCP, CLI, and agent contracts have named package
owners. Keep `scorchkit` as the composition and compatibility facade so existing import paths,
features, commands, MCP tools, wire formats, policy decisions, and scanner behavior remain stable.

## Why

SK-028 through SK-032 stabilized the execution, job, AI-provider, Codex-host, and MCP boundaries.
Leaving those contracts inside one crate still permits reverse dependencies and makes every future
scanner refactor rebuild and reason about the entire application. This extraction makes dependency
direction machine-checkable before SK-034 reduces adapter duplication.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the workspace is resolved, Cargo shall expose named policy, core, configuration, executor, process-tool, web, code, infrastructure, cloud, storage, MCP, CLI, and agent packages with no dependency on the root composition package. | Metadata graph contract test and package checks. |
| REQ-002 | When existing Rust consumers use `scorchkit` paths, the compatibility facade shall expose the same public types and functions without duplicate domain type identities. | Existing library, doctest, and compile-contract suites. |
| REQ-003 | When policy, finding, evidence, target, result, event, scheduler, or subprocess behavior executes, the extracted package owner shall provide the implementation and preserve the prior result or denial. | Package unit tests plus existing policy/executor/process suites. |
| REQ-004 | When family modules are registered, each family shall consume its package-owned category and descriptor contract while concrete adapters remain behaviorally unchanged in the composition crate. | Registry census and family contract tests. |
| REQ-005 | When storage, MCP, CLI, or agent boundary values are serialized or parsed, their extracted package-owned models shall preserve the current JSON, schema, annotations, arguments, and manifest shapes. | Existing storage/MCP/CLI/agent contract suites and snapshots. |
| REQ-006 | When features are selected independently or together, the workspace shall compile without enabling a stronger scanner family or external effect implicitly. | Feature-matrix Clippy and all-feature tests. |
| REQ-007 | When a lower-layer package is inspected, it shall not import CLI, MCP, storage, agent-host, provider, or root-composition code against the documented dependency direction. | Exact Cargo metadata allow-list test. |
| REQ-008 | When SK-033 is delivered, no scan target, network effect, database migration, installed plugin, remote service, or agent-provider call shall be added or initiated by the refactor itself. | Diff inspection and local contract-only validation. |

## Scope

- In: Cargo workspace and package manifests; extracted stable policy/domain/configuration/executor/
  subprocess implementations; package-owned family descriptors and categories; package-owned
  storage/MCP/CLI/agent boundary models; compatibility re-exports; dependency-graph enforcement;
  focused architecture, contributor, and roadmap documentation.
- Out: scanner algorithm changes; new modules or effects; remote MCP; authentication changes;
  storage schema changes; public wire-format changes; provider transport work; moving every concrete
  scanner adapter before SK-034; full mutation campaign; push or pull request.

## Locked decisions

- Preserve `scorchkit` as the public composition crate and binary package.
- Extract stable contracts before concrete adapters; do not combine crate movement with scanner
  behavior redesign.
- Lower-layer workspace packages may not depend on the root `scorchkit` package.
- Keep context construction and effect authorization sealed in the composition layer during this
  behavior-preserving pass.
- Preserve feature names and the default feature set.
- Inspect the DIFF mutation selection without compiling mutants. If code movement makes the
  selection broad, execute only the functions repaired during inspection and seal their exact raw
  inventory and outcomes for delivery. Do not launch the same selection a second time while its
  mutation inputs remain exact.

## Recon

- The repository currently has one package, 15 top-level source domains, roughly 80,000 Rust lines,
  and extensive `crate::` coupling through contexts, configuration, and orchestrators.
- Pure policy decisions and scope rules have no host dependency and can move outright.
- Findings, evidence, targets, results, and events form a stable domain cluster; the unified error
  depends only on that cluster's libraries plus policy violations.
- The generic job scheduler and shared subprocess implementation already state that they are
  provider-neutral boundaries and can move without scanner behavior changes.
- Family context constructors are deliberately crate-private security seams. Moving them in this
  ticket would either widen construction authority or require an authorization-token redesign, so
  family packages will own stable categories/descriptors while composition retains sealed contexts.
- Storage, MCP, CLI, and agent modules mix stable boundary types with application orchestration.
  Their stable models move first; effectful adapters remain in composition and consume those types.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/workspace-crate-extraction.spec.md`

## Log

- 2026-08-17: opened.
- 2026-08-17: plan confirmed by the owner's approved back-to-back SK-029 through SK-033 sequence
  and explicit local-commit direction; broad mutation reruns and remote delivery remain out of
  scope.
- 2026-08-17: the owner approved completion and commit while retaining the earlier instruction not
  to repeat broad mutation work. TICKET-007 therefore records the Constitution section 19 focused
  delivery path for reuse of green, sealed mutation evidence after archival.
- 2026-08-17: inventory-only DIFF inspection selected 841 mutations in 268 functions across 49
  source files because moved code appears new to Git. Execution is narrowed to the 11 policy, job,
  and MCP seams repaired during inspection; the 841-mutant selection remains deferred.
