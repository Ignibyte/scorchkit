---
title: Synchronize ScorchKit website and public documentation — notes
pipeline_id: 830b5941-a185-497b-ac24-04c33814680d
---

# Synchronize ScorchKit website and public documentation — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-doc-examples-contract-001`: public examples are API contracts. Install and first
    scan commands must be checked against the current CLI rather than copied from old prose.
  - `PR-scorchkit-host-workflow-tool-contract-001`: claims about Codex workflows and MCP tools must
    match the executable host contract and exact tool inventory.
  - `PR-scorchkit-default-catalog-explicit-compatibility-001`: default AppSec counts must stay
    separate from the retained network, enterprise, and cloud compatibility catalog.
  - `PR-scorchkit-effect-contract-single-source-001`: public tool counts and effect labels come from
    one exhaustive inventory; the site cannot keep its own historical number.
  - `PR-scorchkit-scan-coverage-projection-parity-001`: missing optional tools and incomplete
    coverage must remain visible rather than being marketed as clean coverage.
  - `PR-scorchkit-policy-before-effects-001`: a prompt, configured target, installed tool, or
    project entry does not authorize a scan. Every first-run path must start with an engagement.
  - `AAR-017-codex-appsec-workflows`: Codex is the preferred host for labeled semantic review, while
    ScorchKit owns deterministic effects and evidence through agent-neutral contracts.
  - Active bulletins: none.
- Recon:
  - `Ignibyte/scorchkit_home` is a separate private Vite/React repository with no Pages endpoint,
    deployment history, `AGENTS.md`, or `.openai/hosting.json`.
  - The initial site is Claude-first and claims 80 modules, four output formats, 24 MCP tools, and a
    v1.0-v3.0 future roadmap. Its quick start omits targeted `init` and therefore cannot run against
    the current fail-closed engine.
  - The engine's source-backed contract is 89 web modules, 22 code modules, 67/21 application
    defaults, 39 MCP tools, four infrastructure modules, five cloud compatibility adapters, and
    terminal/JSON/HTML/SARIF/PDF output.
  - README and public tutorials mix `chadpeppers/scorchkit`, `Ignibyte/scorchkit`, and the private
    local origin `Ignibyte/scorch_kit`; the public canonical link will be `Ignibyte/scorchkit`.
  - The roadmap source census says 91/123 while the executable registry test fixes 89/122. The
    application catalog says 68 default web modules while the same test fixes 67.
  - The site compiles and serves from local scratch. Installation on `/Volumes/srv` fails because
    the mount denies execution of the downloaded `esbuild` binary.
- Operator confirmation: the owner explicitly requested the ScorchKit website timeline,
  installation, usage, README, and repository items be updated. That direction confirms this plan
  and the documentation/site design without authorizing a push or release.

## Phase 2 — Design

- Architecture:
  - Keep the existing single-page static Vite application and ScorchKit orange/charcoal identity.
  - Replace release-era feature sections with a reader path: product boundary, evidence lifecycle,
    current capabilities, layered installation, authorized first use, workflow examples, timeline,
    and contribution/docs links.
  - Centralize public repository/documentation URLs and command snippets in a small content module
    so navigation, hero, install, timeline, and footer links do not drift independently.
  - Keep interactive behavior local: copy buttons, mobile navigation, and progressive disclosure.
    No target entry, hosted scan, authentication, persistence, or external service is added.
  - Preserve `public/opengraph.jpg` and update title/description/Open Graph/X metadata to match the
    new agent-neutral positioning.
- File manifest:
  - `/Volumes/srv/stacks/scorchkit_home/src/pages/Home.tsx`, `src/components/**`, `src/index.css`,
    `src/content.ts`, `index.html`, `README.md`, and package metadata: rebuild the landing-page
    content hierarchy, commands, timeline, metadata, responsive states, and local contributor docs.
  - `README.md`: concise product boundary, accurate census, recommended supported build, safe first
    use, optional-tool layers, workflow examples, plugin/MCP boundary, and documentation index.
  - `docs/guide/getting-started.md`, `docs/tutorials/{README,01-first-scan,08-ci-cd-integration}.md`,
    and `docs/tools-checklist.md`: canonical repository/install flow and a clear core/default/tool
    distinction.
  - `docs/architecture/application-security-catalog.md` and `docs/planning/ROADMAP.md`: reconcile
    registry counts, current status, and public-doc sync with executable evidence.
  - `CHANGELOG.md`, ticket/spec/notes/AAR, and knowledge register: durable delivery record.
- Regression test plan:
  - Website: install from local scratch, TypeScript check, production build, non-error local render,
    static check for required counts/commands/links, and source inspection for navigation, focus,
    reduced motion, and code-block overflow.
  - Engine docs: run the module census, current supported-feature CLI help, repository-wide stale
    claim/URL search, Markdown-link target review, `git diff --check`, `bash bin/gate.sh --fast`
    during implementation, then `bash bin/gate.sh --diff` for validation.
  - Cross-repository review: inspect both diffs independently and confirm neither changes scanner
    behavior, authorization, external-service state, or the separate marketing-site gate status.

## Phase 3 — Implement

- Files and behavior changed:
  - Rebuilt the separate `Ignibyte/scorchkit_home` page around current product facts: an
    agent-neutral evidence engine, Codex as preferred host, 67/21 application defaults, 89/22 full
    web/code registries, 39 MCP tools, five report formats, supported Linux/macOS builds, optional
    PostgreSQL, exact-pinned AppSec tools, targeted `init`, common authorized workflows, and the
    completed/next SK-033 through SK-048 timeline.
  - Replaced the old Claude slash-command demo and release-era v1-to-v3 marketing components with
    overview, installation, usage, Codex boundary, and engineering-timeline sections. Added one
    shared content module, accessible copy controls, skip link, keyboard/Escape mobile navigation,
    visible focus states, reduced-motion behavior, overflow-safe command blocks, and current page
    metadata while preserving the existing logo and social-preview asset.
  - Simplified the single-page application shell so it no longer initializes unused query, tooltip,
    toast, or router providers. Added a generated npm lockfile and current site contributor README.
  - Updated the engine README and getting-started guide with the canonical public repository,
    `--locked` core build, supported `infra cloud mcp` feature build, PostgreSQL boundary,
    `doctor --deep`, and layered external-tool installation. Explicitly documented that
    `--all-features` is a repository-validation mode because it includes quarantined native SDK
    modules.
  - Repaired the first-scan and CI tutorials. CI now keeps the engine checkout outside assessed
    source, supplies explicit code-path or target engagements, uses global output options in the
    compiled CLI position, loads infrastructure policy from a protected reviewed config, and no
    longer installs a moving OSV Scanner or invents a binary release URL.
  - Corrected the application catalog from 68 to 67 default web modules and the roadmap from 91/123
    to the executable 89/122 census, including the 44-adapter process split. Updated the tool
    checklist, OSV installation page, tutorial index, changelog, ticket, and pipeline evidence.
- Design deviations:
  - No live website URL, GitHub Pages endpoint, deployment record, or `.openai/hosting.json` exists
    for `scorchkit_home`. This ticket prepares and validates the site source but does not create a
    new hosting identity, push either repository, or synchronize the stale public engine mirror.
  - The `/Volumes/srv` mount prevents downloaded `esbuild` binaries from executing. The exact site
    tree is therefore copied to a disposable local directory for npm installation, typecheck,
    production build, and preview. Source edits remain only in the website repository.
  - The existing social preview image is preserved. No absolute trusted production origin is known,
    so no invalid relative `og:image` URL was added.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | The compatibility-tool summary called infrastructure modules adapters and obscured which counts were compatibility-only. | Medium | Fixed the site copy to label 22 web and one code compatibility modules separately from four infrastructure modules and five cloud adapters. |
| 2 | Security | The GitHub and GitLab examples reused one fixed engagement identifier, weakening per-run audit correlation even though the identifier is not an authorization grant. | Medium | Generate a fresh UUID from the Linux runner for each CI job and interpolate it into the reviewed engagement. |
| 3 | Data integrity | Registry tests fixed the executable counts but no test coupled those counts to the three public census tables that had already drifted. | Medium | Added `public_documentation_matches_registry_census` to fail when README, roadmap, or application-catalog census rows diverge. |
| 4 | Simplification | The rebuilt single-page site retained 58 unused UI/helper files and more than 30 unused runtime dependencies, including a deprecated Recharts transitive path. | Medium | Deleted the unreferenced tree, reduced runtime dependencies to React, React DOM, and Lucide, regenerated the lockfile, and rebuilt with zero audit findings. CSS output fell from 109.35 kB to 37.19 kB. |
| 5 | Correctness | Reduced-motion CSS used the nonexistent `scroll-duration` property, so that declaration could never affect motion. | Low | Removed the invalid declaration; native smooth scrolling is disabled through the valid `scroll-behavior` override. |
| 6 | Correctness | Clipboard rejection produced an unhandled promise from the copy control. | Low | Catch clipboard failures and leave the button in its normal state. |
| 7 | Delivery boundary | The website repository has no live URL, deployment history, Pages endpoint, or Sites hosting manifest; publishing would also require an authorized source push. | Medium | Documented as an explicit source-only delivery limitation. No hosting identity, push, release, or deployment is invented by this ticket. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Website `npm install --ignore-scripts`: 86 packages audited with 0 vulnerabilities.
  - Website `npm run typecheck`: passed.
  - Website `npm run build`: passed; production output contains 1.62 kB HTML, 37.19 kB CSS,
    226.31 kB JavaScript, and the preserved 779.30 kB logo asset.
  - Website local preview request: HTTP 200.
  - `cargo fmt --all -- --check`: passed.
  - `cargo test --quiet --features 'infra cloud' --test module_census -- --nocapture`: 7 passed,
    including the new public-documentation census contract.
  - Supported-feature `scorchkit --help`, stale-claim searches, content/static-accessibility
    checks, and `git diff --check` in both repositories passed.
- Gate run and receipt:
  - `bash bin/gate.sh --fast`: green; 14 passed, 0 failed, and 8 fast-mode or not-applicable
    lanes skipped.
  - The first DIFF invocation passed 17 lanes but stopped the mutation and PostgreSQL lanes before
    mutation selection because `DATABASE_URL` was not exported. This was an invocation
    prerequisite, not a source failure; the local validation database was already healthy.
  - Pre-completion `bash bin/gate.sh --diff` with the existing local validation database: green;
    19 passed, 0 failed, and 3 named web-only lanes skipped. Nextest passed 1,874 cases with 10
    reasoned skips; PostgreSQL passed 77 MCP, 12 storage, and 10 storage-integration cases; CLI/MCP
    contracts passed 22 CLI, 2 code-scan, 77 MCP, and 12 scan-plan cases.
  - The docs/test-only Rust diff generated no viable production mutants and normalized to explicit
    100% empty-DIFF evidence: 0 caught, 0 missed, required floor 95%.
  - Exact-tree DIFF receipt: `0a7927d2b99bbbfda6034ed69f56c793b032eca19df43e8785bb1cf06340a455`.
- Documented skips with reasons:
  - Browser E2E, engine website dogfood, and built-CSS lanes do not apply to the terminal security
    engine. The separate website received its own typecheck, production build, static
    accessibility review, and HTTP preview proof.

## Phase 5 — Complete

- Docs updated:
  - Website product, installation, usage, Codex, and timeline sections plus metadata and contributor
    README.
  - Engine README, getting-started guide, first-scan and CI tutorials, tutorial index, tool
    checklist, OSV guide, application-security catalog, roadmap, changelog, and census contract.
- AAR submitted:
  - `AAR-018-public-documentation-sync` on 2026-08-21 with effectiveness 5/5; three reusable
    prevention rules and two failure patterns are registered in the knowledge index.
- Archive:
  - The pipeline-owned completion transition will close TICKET-018 and archive its spec and notes.
    A post-archive DIFF gate will bind the final exact tree before delivery.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Website dependencies installed but the Vite builder could not execute from the shared workspace mount. | `/Volumes/srv` denies execution of downloaded JavaScript native binaries. | Build and preview an exact source copy in disposable local scratch while keeping all edits in the website repository. | Use executable local scratch for future website validation on this host. |
| 2 | Public module counts disagreed across the site, README, roadmap, and application catalog. | Narrative documentation copied historical counts without an executable parity check. | Reconciled every current public census to the registry test and added a documentation-parity assertion. | Treat public examples and census rows as contract fixtures whenever registry counts change. |
