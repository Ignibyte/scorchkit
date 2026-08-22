---
title: Retire dependency and advisory debt
pipeline_id: dd91e729-dcc8-49b5-a66b-c5d41e926126
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-024
ticket_doc: docs/planning/tickets/closed/TICKET-024-dependency-debt.md
aar: docs/planning/knowledge/aar/AAR-024-dependency-debt.md
created: 2026-08-22
---

# Retire dependency and advisory debt — spec

## Intent

Retire the three named supply-chain debt paths through maintained upstream releases, prune the
disabled MySQL advisory from the lockfile, and make the unignored dependency policy executable in
both local gates and CI without changing ScorchKit's public behavior or production feature surface.

## Scope

- In: maintained `scraper`, `indicatif`, and SQLx upgrades; exact SQLx feature declarations;
  lockfile replacement; advisory-ignore removal; dependency-graph and behavior regressions.
- Out: unrelated upgrades, new database drivers, native cloud-provider restoration, reduced policy
  strictness, or changes to scanner effects and evidence.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the workspace dependency graph and lockfile are resolved, ScorchKit shall contain neither `fxhash` nor `number_prefix`. | Exact all-target tree and lockfile negatives, Cargo Deny, and parser/progress tests. |
| REQ-002 | When PostgreSQL-only production and test features are resolved, ScorchKit shall not activate `sqlx-mysql`, shall not lock the vulnerable `rsa` package, and shall run Cargo Audit without `RUSTSEC-2023-0071` suppression. | Metadata/tree activation negative, RSA lockfile negative, gate and CI contract checks, unignored audit, and PostgreSQL integration. |
| REQ-003 | When maintained parser and progress dependencies replace their predecessors, ScorchKit shall preserve existing HTML discovery, form/link extraction, progress rendering, CLI output, and serialized scan behavior. | Focused unit/integration regressions, strict Nextest, and CLI/MCP contracts. |
| REQ-004 | When SQLx is upgraded, ScorchKit shall preserve migrations, PostgreSQL queries, transactions, stored identities, CLI operations, and MCP persistence without enabling non-PostgreSQL drivers. | Exact feature contract and all migrated PostgreSQL suites. |
| REQ-005 | When dependency policy validates, Cargo Audit, Cargo Deny, and Cargo Machete shall pass without new advisory ignores, source exceptions, or unused direct dependencies. | Canonical DIFF gate and configuration assertions. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Upgrade the three direct consumers instead of patching or forking their unmaintained transitives. | Maintained upstream releases already replace the named packages and retain the small APIs ScorchKit uses. |
| 2 | Declare SQLx defaults off in production and dev dependencies and enable only Tokio, Rustls, PostgreSQL, UUID, Chrono, JSON, migration, derive, and macro support where actually needed. | The lockfile and release graph must not imply unsupported database drivers. |
| 3 | Remove all three reviewed exceptions in the same change that proves their packages absent. | Policy must describe the current graph rather than retain stale suppressions. |
| 4 | Preserve public wire, database, and command contracts; accept source edits only for documented upstream API changes. | This is dependency retirement, not a behavioral or schema migration. |
| 5 | Validate with ordinary DIFF mode. | The ticket changes manifests and tests but is not an owner-approved focused repair or the scheduled FULL campaign. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-024-dependency-debt.md`
- AAR: `docs/planning/knowledge/aar/AAR-024-dependency-debt.md`
- Architecture: `docs/architecture/storage.md`, `docs/architecture/workspace.md`

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
