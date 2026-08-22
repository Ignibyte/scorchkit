---
title: TICKET-024-dependency-debt
status: done
ticket_number: 024
type: chore
created: 2026-08-22
closed: 2026-08-22
intake:
  - docs/planning/intake/INTAKE-dependency-debt.md
pipeline_spec: docs/planning/pipeline/completed/dependency-debt.spec.md
---

# Retire dependency and advisory debt

## Summary

Upgrade the maintained HTML parser, progress renderer, and PostgreSQL dependency families so the
workspace lockfile no longer contains the named unmaintained `fxhash` or `number_prefix` crates or
the disabled-MySQL `rsa` advisory. Remove the corresponding reviewed exceptions from Cargo Deny,
the gate, and CI while preserving HTML extraction, progress, storage, CLI, and MCP behavior.

## Why

ScorchKit assesses application dependency risk and should not indefinitely carry replaceable
supply-chain debt in its own supported graph. Maintained upstream releases now provide direct
replacement paths, making SK-046 executable before the signed-release work in SK-048.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the workspace dependency graph and lockfile are resolved, ScorchKit shall contain neither `fxhash` nor `number_prefix`. | Exact `cargo tree --workspace --all-features --target all` negatives, lockfile census, Cargo Deny, and parser/progress regressions. |
| REQ-002 | When PostgreSQL-only production and test features are resolved, ScorchKit shall not activate `sqlx-mysql`, shall not lock the vulnerable `rsa` package, and shall run Cargo Audit without `RUSTSEC-2023-0071` suppression. | Cargo metadata/tree activation negative, RSA lockfile negative, gate/CI command inspection, unignored `cargo audit`, and PostgreSQL integration. |
| REQ-003 | When maintained parser and progress dependencies replace their predecessors, ScorchKit shall preserve existing HTML discovery, form/link extraction, progress rendering, CLI output, and serialized scan behavior. | Existing focused parser/scanner/progress tests plus strict Nextest and CLI/MCP contracts. |
| REQ-004 | When SQLx is upgraded, ScorchKit shall preserve migrations, PostgreSQL queries, transactions, stored identities, CLI operations, and MCP persistence without enabling non-PostgreSQL drivers. | Feature-graph contract, migrated PostgreSQL suites, storage tests, and CLI/MCP contracts. |
| REQ-005 | When dependency policy validates, Cargo Audit, Cargo Deny, and Cargo Machete shall pass without new advisory ignores, source exceptions, or unused direct dependencies. | Canonical DIFF gate and exact policy/configuration assertions. |

## Scope

- In: `scraper`, `indicatif`, and SQLx family upgrades; exact production/dev feature declarations;
  lockfile pruning; removal of the two unmaintained Cargo Deny entries and the gate/CI RSA audit
  exception; compatibility tests and dependency-policy contracts.
- Out: unrelated dependency modernization; enabling MySQL, SQLite, or quarantined native cloud
  providers; lower audit or license strictness; new ignores, baselines, retries, or skips.

## Locked decisions

- Use current maintained crates.io releases: `scraper` 0.27, `indicatif` 0.18, and SQLx 0.9.
- Keep SQLx `default-features = false` in production and test declarations and name only the
  PostgreSQL/runtime/data features ScorchKit uses.
- Keep ScorchKit's production feature surface unchanged; dependency retirement must not register
  quarantined provider adapters or add runtime effects.
- Remove policy exceptions only after exact lockfile and all-target feature-graph negatives prove
  `fxhash`, `number_prefix`, and vulnerable `rsa` are absent and the MySQL driver is inactive.
- Treat the user's request to continue the next five roadmap tickets as confirmation of this
  bounded SK-046 plan and its subsequent design.

## Recon

- No active bulletins apply. `WORK-099-cargo-deny-hygiene` established that Cargo Audit and Cargo
  Deny inspect different surfaces and both must be checked directly.
- `PR-scorchkit-workspace-gate-scope-001` requires dependency and feature checks across the complete
  workspace after manifest changes.
- Current exact paths are `scraper 0.22 -> selectors 0.26 -> fxhash` and `indicatif 0.17 ->
  number_prefix`; `scraper` 0.27 uses `selectors` 0.38 with `rustc-hash`, while `indicatif` 0.18
  uses maintained `unit-prefix`.
- SQLx 0.8 leaves vulnerable `rsa` in the resolved lockfile through its disabled MySQL family even
  though that driver is absent from the active PostgreSQL graph. SQLx 0.9 makes RSA an explicit
  MySQL-only feature and supports the current stable toolchain; Cargo may still lock optional
  driver package metadata, so activation and vulnerable-package absence are tested separately.
- The workspace currently compiles PostgreSQL through explicit production features, but the root
  dev declaration still accepts SQLx defaults; the replacement will make both declarations exact.
- Current HTML use is limited to stable `Html::parse_document`, selector parsing, element
  selection, and attribute access. Progress use is limited to spinner construction, templates,
  messages, finish/abandon, and hidden bars.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/dependency-debt.spec.md`

## Log

- 2026-08-22: opened.
- 2026-08-22: upgraded the three dependency families, removed the reviewed exceptions, repaired
  SQLx 0.9 local peer identity compatibility, and passed the exact-tree DIFF gate at 84.59% line
  coverage and 100% viable MSI with all PostgreSQL and CLI/MCP contracts green.
