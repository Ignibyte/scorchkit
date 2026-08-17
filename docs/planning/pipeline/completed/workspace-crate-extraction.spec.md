---
title: Behavior-preserving workspace crate extraction
pipeline_id: 28a05b12-0b49-43c5-9e30-8fd47a4555ec
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-007
ticket_doc: docs/planning/tickets/closed/TICKET-007-workspace-crate-extraction.md
aar: docs/planning/knowledge/aar/AAR-007-workspace-crate-extraction.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-007
created: 2026-08-17
---

# Behavior-preserving workspace crate extraction — spec

## Intent

Ship a behavior-preserving Cargo workspace extraction that assigns stable contracts to named,
agent-neutral packages and makes dependency direction executable. `scorchkit` remains the root
composition and compatibility facade while lower packages own policy, core domain, configuration,
generic execution, process, family, storage-model, MCP-contract, CLI-argument, and agent-manifest
boundaries.

## Scope

- In: package manifests and workspace graph; stable implementation moves; leaf contract ownership;
  compatibility shims; feature propagation; graph and type-identity tests; architecture and operator
  documentation.
- Out: scanner behavior redesign; new effects, targets, modules, migrations, or provider calls;
  remote interfaces; widening sealed context constructors; concrete adapter deduplication owned by
  SK-034; full mutation campaign; push or PR.

## Acceptance criteria (EARS)

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

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep `scorchkit` as the composition crate and binary. | Preserves every existing public path and executable contract while packages are separated underneath it. |
| 2 | Move stable implementations outright; move only stable models from leaf adapters. | Contexts and orchestrators are highly coupled and combining behavioral redesign with package moves would hide regressions. |
| 3 | Do not expose family context constructors across crates. | Those constructors are a security boundary; widening visibility would allow policy-sealed contexts to be fabricated. |
| 4 | Add an explicit support package for configuration. | Every family consumes configuration, and placing it in core or CLI would reverse the intended graph. |
| 5 | Give each family a package-owned category and immutable descriptor type now. | Registries gain a common stable vocabulary without forcing an unsafe context/trait migration. |
| 6 | Keep root features and defaults stable, forwarding only the package features they require. | Existing builds and effect availability must not change due to workspace layout. |
| 7 | Enforce allowed edges from Cargo metadata in a test. | Directory names and diagrams do not prevent architectural drift. |
| 8 | Inspect the DIFF selection, but execute mutation tests only for inspection-repaired functions when code movement makes the nominal DIFF broad. | The owner explicitly stopped repeated broad mutation scans and directed validation to the fixed functions. |

## Owner-approved focused delivery scope

The repository owner directed that broad mutation work must not be repeated and validation must run
only against repaired functions, then approved completion and a local commit. Inventory-only DIFF
inspection selected 841 mutations in 268 functions across 49 source files because behavior-
preserving moves appear new to Git. That selection is deferred. TICKET-007 instead executes the 11
policy, job, and MCP functions whose visibility or compatibility seams were repaired during
inspection. The raw inventory and outcomes will be sealed under
`.git/scorchkit-mutants-focused-ticket-007` and reused for post-archive delivery only while the
exact mutation-input hash and named function inventory remain unchanged. Any later Rust, test,
manifest, configuration, example, migration, or rule change revokes that evidence and requires a
new scoped mutation decision.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-007-workspace-crate-extraction.md`
- AAR: `docs/planning/knowledge/aar/AAR-007-workspace-crate-extraction.md`
- Architecture: `docs/architecture/overview.md`, `docs/architecture/engine.md`,
  `docs/architecture/runner.md`, `docs/architecture/mcp.md`, `docs/architecture/agent.md`

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
