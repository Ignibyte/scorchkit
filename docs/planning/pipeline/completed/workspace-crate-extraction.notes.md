---
title: Behavior-preserving workspace crate extraction — notes
pipeline_id: 28a05b12-0b49-43c5-9e30-8fd47a4555ec
---

# Behavior-preserving workspace crate extraction — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` keeps context construction sealed;
  `PR-scorchkit-executor-contract-001` identifies the shared process boundary;
  `PR-scorchkit-doc-examples-contract-001` requires public-path compile proof;
  `PR-scorchkit-public-mode-dependency-contract-001` requires every public family mode to retain
  ordering; `PR-scorchkit-ticket-diff-baseline-001` applies because commit `e860608` is the clean
  ticket boundary; `PR-scorchkit-focused-mutation-repair-001` forbids repeated broad mutation runs;
  `PR-scorchkit-effect-contract-single-source-001` keeps the MCP inventory singular.
- Operator confirmation: the owner directed SK-029 through SK-033 back to back, approved local
  commits, and explicitly prohibited full mutation rescans after focused repairs.
- Baseline: clean commit `e860608`; 15 top-level source domains; approximately 80,000 Rust lines;
  no active pipeline before TICKET-007 was created.
- Recon: pure policy/domain code can move directly. Contexts and orchestrators form the main cycle.
  Their crate-private constructors are a security boundary, so this pass extracts family vocabulary
  and keeps effectful composition sealed rather than widening constructors.

## Phase 2 — Design

- Architecture: dependency direction is `policy -> core -> config -> executor/tools -> family
  contracts -> storage/agent -> MCP/CLI -> scorchkit composition`, with only documented lateral
  edges and no lower package depending on `scorchkit`.
- File manifest: root `Cargo.toml` and lockfile; new `crates/scorchkit-*` manifests and sources;
  compatibility shims under `src/engine`, `src/runner`, `src/config`, `src/storage`, `src/mcp`,
  `src/cli`, `src/agent`, and `src/ai`; workspace graph contract tests; focused architecture,
  development, README, changelog, and roadmap updates.
- Regression test plan: package unit tests; workspace check and feature matrix; exact dependency
  graph allow-list; type-identity compile assertions; existing module census, policy, executor,
  subprocess, storage, AI, agent, CLI, and 64-tool MCP suites; fast gate during development;
  inventory-only DIFF inspection and owner-approved exact-function mutation evidence when moved
  code makes that selection broad.

## Phase 3 — Implement

- Files and behavior changed: added a 13-package Cargo workspace. Moved policy and scope into
  `scorchkit-policy`; domain, result, event, correlation, compliance, CVE, and fingerprint code into
  `scorchkit-core`; configuration and credential contracts into `scorchkit-config`; the bounded
  scheduler plus durable job/store contracts into `scorchkit-executor`; process ownership into
  `scorchkit-tools`; stable family vocabularies into four family packages; persistence models into
  `scorchkit-storage`; MCP schemas/inventory/results into `scorchkit-mcp`; CLI parsing into
  `scorchkit-cli`; and agent manifest/prompt/reasoning types into `scorchkit-agent`.
- The root package retains policy-sealed contexts, concrete scanners, family orchestrators, the
  composed scan-job service, PostgreSQL adapters, MCP transport/business methods, CLI execution,
  provider process adapters, reports, and compatibility re-exports.
- Added `tests/workspace_architecture.rs` with exact internal dependency edges, lockstep package
  versions, root-consumption checks, representative type-identity checks, and four-family registry
  descriptor checks.
- Expanded the canonical gate and CI from root-only Rust checks to workspace-wide Clippy, tests,
  Rustdoc, coverage, Nextest, Semgrep, suppression checks, source bans, and mutation inventory.
  Mutation input sealing now includes `crates/`.
- Updated architecture, development, README, changelog, and roadmap documentation. Added
  `docs/architecture/workspace.md` as the package ownership source of truth.
- Design deviations: the gate/CI expansion was not listed as a separate source file group in the
  initial manifest. Inspection showed that extraction without it would leave package unit tests,
  Rustdoc, static analysis, and mutation inventory outside the delivery contract. No scanner,
  target, migration, provider, or remote behavior was added.
- Cross-package job-store adapters require a narrow `#[doc(hidden)]` integration surface for
  lifecycle validation and transition helpers that were previously crate-private. Job documents
  were already publicly mutable, every built-in store still validates them, and no family context
  constructor or authorization proof was widened.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Architecture | The original gate and CI commands targeted only the root package, so moving implementations into workspace packages would have excluded their unit tests, Rustdoc, coverage, static analysis, and mutation inventory from delivery. | high | Fixed. Expanded the canonical gate, CI workflow, mutation runner, suppression checks, source bans, and quality-contract tests to cover the complete workspace and `crates/` tree. The mutation inventory inspection now sees 6,095 configured mutants across 257 source files. The nominal DIFF contains 841 mutations in 268 functions, so execution follows the owner-approved 11-function repair scope instead of treating code movement as a broad campaign. |
| 2 | Public API | Glob re-exports from the compatibility facade exposed integration helpers and constructors that had been crate-private before extraction. | high | Fixed. Restored private inherent methods, added narrow hidden package integration modules where cross-package composition requires them, and changed the root facade to explicit public re-exports. A compile-contract test rejects the widened legacy paths. |
| 3 | Security boundary | Moving policy and executor helpers across packages risked making authorization checks, lifecycle validation, and process-control internals callable through the public root facade. | high | Fixed. Sealed family context constructors remain root-crate private. Policy, job, MCP, executor, and subprocess adapters use private imports or hidden integration wrappers; no new effect grant or context-construction route is public. |
| 4 | Wire compatibility | Package extraction changed the generated MCP mutation-tool description because the Rustdoc text needed Clippy-compatible formatting. | medium | Fixed. Added an explicit schema description that retains the published text and restored the original JSON fixture byte-for-byte. |
| 5 | CLI compatibility | Clap derived the help tagline from the new internal package manifest, changing the existing command help. | medium | Fixed. Set the stable root-product description explicitly and retained the original CLI help contract. |
| 6 | Documentation | Moved examples and intra-doc links still named root-only paths and failed package doctests or strict Rustdoc. | medium | Fixed. Rewrote examples to their package-owned public paths and repaired moved links. Workspace Rustdoc now passes with warnings denied. |
| 7 | Version integrity | CLI and agent manifests derive their reported version from their package, so an internal-package version drift could silently change public metadata. | medium | Fixed. Internal dependencies use exact `=3.0.0` requirements and the architecture suite asserts every package version matches the root. |
| 8 | Dependency graph | A directory-level split alone would not prevent a lower package from depending on root composition or a host adapter later. | high | Fixed. Added an exact Cargo-metadata edge allow-list, a no-root-dependency assertion, representative type-identity checks, and family descriptor ownership checks. |
| 9 | Behavior preservation | A broad extraction can duplicate domain types or alter feature selection even when the code compiles. | high | Verified. Existing import paths resolve to the same `TypeId`s; all feature-state linting, all-feature workspace tests, package tests, and the registry census pass. No scanner, target, migration, provider, or remote behavior was added. |

## Phase 4 — Validate

- Tests run (commands and outcomes): workspace all-feature tests passed, including 1,031 root
  library cases, all 13 package suites, integrations, and doctests. Strict workspace Clippy and
  warning-denied Rustdoc passed. The fast gate passed 14 applicable lanes. Inventory-only mutation
  checks found 6,095 configured mutants across 257 source files and a move-inflated DIFF of 841
  mutations in 268 functions across 49 files.
- Gate run and receipt: the first focused gate exposed the workspace Nextest empty-suite assumption;
  after an exact six-package contract-only allowlist, the focused delivery gate passed 19
  applicable lanes. Coverage was 79.99%. Nextest executed 1,443 cases with six reasoned skips.
  PostgreSQL passed 64 MCP, 11 storage, and 8 storage-integration tests; CLI/MCP passed 21 CLI, two
  code-scan, 64 MCP, and 12 scan-plan cases. The receipt binds the exact worktree and sealed evidence
  digest `7905c5238f1502ecee15f8a5cdef41c58b2dc4b080aefc105c06e9b69d46db23`.
- Mutation evidence: the owner-approved 11-function scope selected 90 mutations in three files.
  Eighty-three were caught, seven were unviable, and none were missed or timed out, for 100% MSI.
  Raw outcomes, inventory, exact function names, and mutation-input hash
  `13f3280e483a730491ceb5a991f19e4ffdd00b79b49cdf9786594335d95cc10d` are sealed as
  `.git/scorchkit-mutants-focused-ticket-007`. No mutation rerun is needed or authorized while those
  inputs remain exact.
- Documented skips with reasons: gates 17–19 are the repository's named web-only skips because
  ScorchKit has no web UI, website renderer, or CSS asset pipeline. Four all-feature cases and six
  Nextest cases are existing reasoned live-network tests, not delivery proof.

## Phase 5 — Complete

- Docs updated: workspace, overview, agent, AI, executor, MCP, and storage architecture; development
  guide; README; changelog; roadmap; ticket/spec/notes; and knowledge register.
- AAR submitted: `AAR-007-workspace-crate-extraction`, 2026-08-17, effectiveness 5.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-007, remove it from the open queue,
  move the spec/notes pair to the completed pipeline directory, and rewrite their cross-links. The
  post-archive focused delivery gate then revalidates every non-mutation lane and the sealed exact
  function evidence before the local commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first local workspace test used the mount-local Cargo target and could not execute a build helper. | The workspace mount does not preserve executable behavior for build artifacts. | Reused the repository-approved local scratch target directory. | Keep all ordinary Cargo validation under the local scratch target on this host. |
| 2 | CLI help and one MCP schema description drifted after their owning types moved. | Derive macros consumed package-local metadata and Rustdoc rather than the former root values. | Made both public descriptions explicit and kept their existing fixtures. | Treat generated help and schemas as wire contracts during package moves. |
| 3 | Internal helpers appeared in the public root facade. | Glob re-exports erased the old crate-private visibility boundary. | Replaced globs with explicit compatibility exports and hidden integration adapters. | Require negative visibility contracts whenever crate extraction crosses a private seam. |
| 4 | Root-only quality commands would have left new packages partially unverified. | The single-package gate encoded its package scope implicitly. | Made workspace scope explicit in local, CI, coverage, documentation, and mutation lanes. | Architecture tests now assert the workspace-wide gate contract. |
| 5 | The first delivery gate rejected six contract-only workspace library harnesses with no local tests. | Nextest strictness assumed every non-binary harness owned tests before the repository became a workspace. | Added an exact, self-checking allowlist for the six packages whose behavior is covered by root integration and architecture suites. | The gate fails for a new empty suite and for a stale allowlist entry after package-local tests are added. |
