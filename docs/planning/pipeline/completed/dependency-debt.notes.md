---
title: Retire dependency and advisory debt — notes
pipeline_id: dd91e729-dcc8-49b5-a66b-c5d41e926126
---

# Retire dependency and advisory debt — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - No active bulletins apply.
  - `WORK-099-cargo-deny-hygiene` warns that Cargo Audit reads the complete lockfile while Cargo
    Deny evaluates its own configured graph and advisory policy; both are required evidence.
  - `PR-scorchkit-workspace-gate-scope-001` requires manifest and dependency validation across the
    complete workspace and every derived feature state.
  - `docs/architecture/storage.md` keeps SQLx PostgreSQL-only and runtime-queried so builds and
    release binaries do not need a database connection.
  - The current support boundary keeps native cloud SDK modules quarantined; their unrelated
    informational advisories are not a reason to enable, broaden, or silently remove those paths.
- Recon evidence:
  - `cargo tree --workspace --all-features -i fxhash` reports
    `scraper 0.22 -> selectors 0.26 -> fxhash 0.2.1`.
  - `cargo tree --workspace --all-features -i number_prefix` reports
    `indicatif 0.17.11 -> number_prefix 0.4.0`.
  - Current crates.io metadata reports `scraper` 0.27.0 using `selectors` 0.38.0 with
    `rustc-hash`, and `indicatif` 0.18.6 using `unit-prefix` 0.5.1.
  - Unignored `cargo audit --json` finds one vulnerability: `RUSTSEC-2023-0071` in lockfile-only
    `rsa` 0.9.10. The active all-feature/all-target Cargo tree contains neither `rsa` nor
    `sqlx-mysql`, proving this is the disabled-driver lockfile case documented by the existing
    exception.
  - SQLx 0.9.0 supports Rust 1.94; the workspace toolchain is Rust 1.96. Its optional MySQL driver
    moved to RSA 0.10.0-rc.18, outside the advisory, while explicit PostgreSQL features avoid the
    driver entirely.
  - `cargo deny check` is green before the change with the two named unmaintained exceptions;
    policy removal must keep it green.
- Operator confirmation: the user's directive to continue the next five roadmap tickets confirms
  the ordered SK-046 plan and authorizes autonomous phase transitions within its locked scope.

## Phase 2 — Design

- Architecture:
  - Keep the root `scorchkit` package as the only composition owner. This ticket changes dependency
    implementations, not package boundaries, public type identity, feature names, or registry
    contents.
  - Upgrade `scraper` in place because ScorchKit uses only its stable parsed-document, selector,
    traversal, and attribute APIs. Existing scanner/recon modules remain unchanged unless compiler
    evidence identifies an upstream signature change.
  - Upgrade `indicatif` in place because terminal progress remains a CLI-owned renderer. Library
    execution continues to publish structured events and does not gain terminal output.
  - Upgrade every direct SQLx declaration together. Production and dev declarations disable
    defaults and enumerate only Tokio/Rustls/PostgreSQL plus the existing data, migration, derive,
    and macro capabilities. Runtime query APIs remain in the root adapter; no migration, query,
    stored schema, database engine, or lower-package ownership changes.
  - Remove the `fxhash` and `number_prefix` Cargo Deny entries and both RSA audit command-line
    suppressions only after the new lockfile proves the three retired package names absent and the
    feature graph proves optional MySQL remains inactive.
  - Add an executable repository contract that reads manifests, the lockfile, Cargo Deny, the gate,
    and CI so future dependency drift cannot silently restore the retired paths or exception.
  - Security boundary: no target, network, filesystem, credential, cloud, or subprocess effect is
    added. Native provider SDKs remain quarantined and all authorization, redaction, timeout, and
    evidence contracts are unchanged.
- Compatibility:
  - Public Rust, CLI, MCP, JSON, database, migration, and report contracts remain byte/schema
    compatible. No feature is renamed and default features remain empty.
  - SQLx remains runtime-queried and PostgreSQL-only, retaining build portability and avoiding a
    build-time `DATABASE_URL`.
  - Existing HTML parser fixtures pin discovered links, forms, script sources, metadata, and
    scanner inputs. Existing progress tests pin hidden/no-result/success/error rendering behavior.
- File manifest:
  - `Cargo.toml`: upgrade `scraper`, `indicatif`, root SQLx production/dev declarations and make dev
    defaults explicit.
  - `crates/scorchkit-storage/Cargo.toml`: upgrade the package-owned SQLx declaration.
  - `Cargo.lock`: resolve maintained families and evict retired packages.
  - `deny.toml`: delete only the two now-obsolete unmaintained advisory entries.
  - `bin/gate.sh`: run unignored `cargo audit`.
  - `.github/workflows/ci.yml`: match the unignored audit command.
  - `tests/quality_gate_contract.rs`: assert exact manifest feature policy, retired lockfile
    packages, and absence of audit/deny suppressions.
  - `docs/architecture/storage.md`: document exact PostgreSQL-only dependency resolution.
  - `README.md`, `CHANGELOG.md`, `docs/planning/ROADMAP.md`, ticket/spec/notes/AAR/knowledge index:
    update durable delivery evidence during completion.
  - Source files: modify only if an upstream API incompatibility is demonstrated by compilation or
    focused tests; record any such deviation before passing implementation.
- Regression test plan:
  - Run the new dependency-policy contract alone after lockfile resolution.
  - Run focused progress, recon HTML, and affected scanner parser tests under all features.
  - Run workspace/all-target/all-feature Clippy and `bash bin/gate.sh --fast` during development.
  - Run exact `cargo tree`/lockfile negatives for `fxhash`, `number_prefix`, and `rsa`, plus an
    active-tree negative for `sqlx-mysql`; run unignored `cargo audit`, `cargo deny check`, and
    `cargo machete`.
  - Validate with
    `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff`, including
    migrated PostgreSQL and CLI/MCP contract lanes, then rerun DIFF after archive for delivery.
- Operator confirmation: the user's ordered five-ticket directive and the ticket's locked decision
  authorize this bounded design; no broader dependency or provider work is implied.

## Phase 3 — Implement

- Files and behavior changed:
  - Upgraded `scraper` to 0.27 and `indicatif` to 0.18. Their maintained transitive families
    replace `fxhash` and `number_prefix`; existing HTML discovery and progress rendering contracts
    pass unchanged.
  - Upgraded all direct SQLx declarations to 0.9 with defaults disabled and PostgreSQL-only
    features. The active all-feature/all-target graph contains no MySQL driver, and `rsa` is absent
    from the lockfile.
  - Removed the two obsolete Cargo Deny exceptions and the RSA Cargo Audit suppression from the
    local gate and CI. Unignored Cargo Audit, Cargo Deny, and Cargo Machete are green.
  - Added an executable dependency-policy contract covering exact direct versions and features,
    retired lockfile packages, the storage-only `whoami` platform feature, and suppression absence.
  - Preserved local `postgresql:///database` peer-auth behavior across SQLx 0.9 by enabling
    `whoami` platform support only with `storage`, parsing through one shared connection-options
    boundary, preserving explicit URL/query usernames, and keeping invalid URL diagnostics
    credential-safe. Project bootstrap now uses that shared connection boundary too.
  - Marked four test-only dynamically generated PostgreSQL identifiers with `AssertSqlSafe` after
    proving their interpolated suffix is exactly 32 locally generated ASCII hex bytes.
  - Documented the exact active SQLx driver graph in `docs/architecture/storage.md`.
- Design deviations:
  - SQLx 0.9 retains optional MySQL and SQLite package metadata in `Cargo.lock`; Cargo metadata and
    the all-feature/all-target tree prove neither driver is active. The acceptance contract tests
    the supported security property instead of falsely requiring optional package metadata to be
    absent.
  - SQLx 0.9 changed its dynamic-query API and its disabled `whoami` feature produced the literal
    user `anonymous` for username-less local DSNs. The implementation therefore includes the
    documented test-only DDL proof and a shared local-identity compatibility adapter, both within
    the locked source-edit allowance for demonstrated upstream incompatibilities.
  - Enabling `whoami`'s `std` feature adds target-specific Redox and Apple configuration metadata
    to the lockfile; it adds no runtime effect on other targets and remains storage-feature gated.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | All maintained APIs compile across every feature state; parser, progress, CLI, MCP, PostgreSQL, and doctest behavior is unchanged. The SQLx 0.9 username regression is covered for omitted, authority, and query usernames. | none | Accept; workspace/all-feature tests and FAST are green. |
| 2 | Security | The invalid-DSN regression covered URL syntax rejection but not the later SQLx option-parser rejection path, leaving one credential-redaction branch without direct proof. | low | Fixed by adding a parseable DSN with an invalid `sslmode` carrying redaction markers; both error paths return a generic message and the focused tests pass. |
| 3 | Security | Dynamic PostgreSQL fixture DDL cannot use bind parameters, so its explicit safety wrapper requires proof that no operator-controlled bytes reach an identifier. | none | Accept; suffix length and ASCII-hex alphabet are asserted before every derived identifier, and the use is test-only. No production dynamic SQL was found. |
| 4 | Data integrity | SQLx package metadata still includes optional MySQL/SQLite packages, which could be mistaken for active drivers; no migration or schema file changed. | none | Accept; manifests disable defaults, all-target output prints no reverse dependency for `sqlx-mysql`, the vulnerable `rsa` package is absent, and all migrated storage/transaction suites pass. |
| 5 | Simplification | Project bootstrap previously created a pool outside the shared storage adapter, which would have retained divergent SQLx connection semantics. | low | Fixed during implementation by routing it through `connect_with_max`; inspection finds no direct production `PgPoolOptions` call outside `src/storage/mod.rs`. |
| 6 | Mutation readiness | The changed storage adapter has nine configured production mutants; username boolean mutations are observable through the omitted/authority/query tests and pool-return mutations through database suites. | none | Accept; `bash bin/mutants.sh --inspect` reports a valid 9,772-mutant workspace inventory and DIFF validation will execute the changed scope. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo test --all-features storage::tests`: 8 passed after the inspection repair.
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 cargo test --workspace
    --all-features`: the complete workspace, integration, and doctest suite passed.
  - Exact package/tree checks found no `fxhash`, `number_prefix`, or `rsa` package and no active
    reverse dependency for `sqlx-mysql`.
  - Unignored `cargo audit`, `cargo deny check`, and `cargo machete` passed. Cargo Audit reports
    five visible allowed informational warnings from unrelated quarantined/native dependency paths;
    no advisory is suppressed by this ticket.
  - `bash bin/mutants.sh --inspect`: 9,772 configured workspace mutants across 298 source files;
    composition binary excluded and policy kernel included as designed.
- Gate run and receipt:
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff`:
    19 applicable lanes passed and none failed.
  - Coverage: 84.59% lines, above the 62% floor.
  - Changed-scope mutation: 9 attempted, 7 caught, 2 unviable, 0 missed; 100% viable MSI against
    the 95% floor.
  - Strict Nextest started 1,937 tests with 10 repository-declared skips and no retries or failures.
  - PostgreSQL integration and CLI/MCP contract lanes passed.
  - Receipt: `.git/scorchkit-gate-receipt` for the exact pre-completion worktree.
- Documented skips with reasons:
  - Gates 17–19 remain the named not-applicable browser/rendering/asset skips because ScorchKit has
    no web UI. No new test, advisory, coverage, mutation, or feature exclusion was added.

## Phase 5 — Complete

- Docs updated: the changelog, roadmap, storage architecture, ticket, dependency contract, and
  validation evidence describe the maintained parser/progress/SQLx graph, removed exceptions,
  local peer-auth compatibility, and SK-047 as the next ordered item.
- AAR submitted: `AAR-024-dependency-debt` on 2026-08-22 with effectiveness 4/5; four reusable
  prevention rules and four failure patterns are registered in the knowledge index.
- Archive: pending the repository-owned completion transition and post-archive exact-tree DIFF
  receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first manifest patch also changed Axum to a nonexistent 0.9 release. | A version-only patch matched the adjacent dependency stanza too broadly. | Restored Axum 0.8 before accepting dependency resolution. | Patch manifest entries with their dependency header as context and inspect the manifest diff before resolution. |
| 2 | The initial design expected `sqlx-mysql` to disappear from the lockfile. | SQLx publishes optional driver metadata in its resolved package family even when that feature is inactive. | Reframed the contract around inactive Cargo feature/tree evidence and absence of vulnerable `rsa`. | Distinguish lockfile package metadata from activated dependency edges during dependency planning. |
| 3 | SQLx 0.9 rejected four dynamic test fixture DDL strings at compile time. | The new API requires an explicit proof wrapper for dynamically assembled SQL. | Proved the generated identifier suffix is fixed-length ASCII hex and wrapped only those test DDL statements in `AssertSqlSafe`. | Keep production SQL parameterized and require a local alphabet/length proof before any test-only identifier interpolation. |
| 4 | The first FAST run failed ten peer-auth database tests as user `anonymous`. | SQLx 0.9 disables `whoami` defaults while calling its API; without the `std` feature the platform stub returns `anonymous`. | Enabled `whoami/std` with ScorchKit's storage feature and centralized parsed connection options with omitted/explicit username regressions. | Pin the storage feature contract and exercise username-less local PostgreSQL DSNs in ordinary tests. |
| 5 | The first repaired workspace run failed the MCP invalid-URL diagnostic contract. | The new sanitized parser error omitted the established phrase `connection failed`. | Restored the phrase without echoing the credential-bearing URL. | Treat diagnostic text asserted by CLI/MCP tests as a compatibility surface during adapter changes. |
| 6 | The first repaired FAST rerun failed Cargo formatting and Semgrep. | `whoami` was not in Cargo Sort order, and a redaction fixture variable was named `secret`. | Applied Cargo Sort plus Taplo and renamed the fixture variable without weakening either policy. | Run the exact metadata/SAST lanes after adding dependencies or security-shaped fixtures. |
| 7 | Inspection found only URL-syntax failure covered by the new DSN redaction test. | SQLx-specific option parsing is a distinct failure boundary after generic URL parsing succeeds. | Added an invalid `sslmode` case with credential-shaped markers and proved neither input is echoed. | Exercise each parser boundary independently when wrapping third-party configuration errors. |
| 8 | The first `pass validate` rejected the otherwise green DIFF receipt. | Validation results were written into the active notes after the gate sealed its exact worktree. | Recorded this defect before rerunning the same DIFF mode for a matching receipt. | Populate the validation evidence template before the receipt-producing run; after green, defer exact outcome additions to completion before its required delivery rerun. |
