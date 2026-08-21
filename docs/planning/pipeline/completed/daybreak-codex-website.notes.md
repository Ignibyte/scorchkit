---
title: Position the website around Codex and Daybreak Blue — notes
pipeline_id: 1b30b81a-94f8-4462-914e-b409194bba1f
---

# Position the website around Codex and Daybreak Blue — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-public-census-contract-001`: public claims need executable checks rather than
    freehand duplication. The site will add a dependency-free content contract for the new copy.
  - `PR-scorchkit-site-executable-scratch-001`: the shared mount cannot execute downloaded website
    build helpers. Validation will use an exact source copy on disposable local scratch.
  - `PR-scorchkit-proof-evidence-own-provenance-001`: Daybreak/Codex interpretation must remain
    labeled host analysis and cannot become scanner evidence.
  - `PR-scorchkit-host-workflow-tool-contract-001`: the public host story must match the six Codex
    workflows and current MCP boundary rather than inventing a new orchestration surface.
  - `PR-scorchkit-workflow-gap-no-broad-substitution-001`: optional Daybreak availability cannot
    trigger a silent model or scan fallback.
  - `AAR-018-public-documentation-sync`: retain the completed site redesign and change only the
    product hierarchy, claims, metadata, and supporting checks needed for Daybreak positioning.
  - Official OpenAI Docs: Daybreak Blue is a defensive-cybersecurity frontier-model alias that
    requires separate approval and provisioning; Trusted Access is identity, workspace/project,
    offering, and surface specific.
- Operator confirmation: on 2026-08-21 the owner directed the website to be Codex-preferred,
  agent-neutral, and explicit about using Daybreak for high-quality security analysis.

## Phase 2 — Design

- Architecture:
  - Keep the engine and every provider-neutral contract unchanged. Model selection remains a Codex
    host concern outside ScorchKit authorization and evidence.
  - Reframe the existing website hero around Codex-preferred application security and optional
    Daybreak Blue use for approved defenders.
  - Replace the small Codex callout with a three-boundary presentation: Codex/Codex Security owns
    orchestration and semantic review, Daybreak Blue is an optional approved reasoning model, and
    ScorchKit owns engagement policy, deterministic scanners, evidence, and durable results.
  - Link official OpenAI model and Trusted Access pages. State access qualifications next to the
    Daybreak claim rather than hiding them in contributor documentation.
  - Preserve the existing Vite/React architecture, design system, page order, responsive behavior,
    and source-only deployment boundary.
- File manifest:
  - Website `src/content.ts`: official URLs and source-backed Codex/Daybreak/ScorchKit layer copy.
  - Website `src/components/Hero.tsx`: leading Codex/Daybreak product position.
  - Website `src/components/Usage.tsx`: three-boundary visual, links, and explicit access/evidence
    qualification.
  - Website `src/components/Nav.tsx`: accurate Codex + Daybreak section label.
  - Website `index.html`: search and social metadata.
  - Website `scripts/check-content.mjs`, `package.json`, and `README.md`: dependency-free content
    contract and contributor instructions.
  - Engine `README.md`, `docs/guide/codex-plugin.md`, and
    `docs/architecture/appsec-workflows.md`: durable source for the model-selection boundary.
  - Engine `CHANGELOG.md`, ticket/spec/notes/AAR/indexes: delivery record.
- Regression test plan:
  - Run the website content contract and fail on missing Codex-preferred, Daybreak qualification,
    official URLs, ScorchKit authority, or metadata statements, and on a Claude Code homepage claim.
  - Run website TypeScript checking and a production build from an exact disposable local-scratch
    copy because `/Volumes/srv` cannot execute downloaded build helpers.
  - Serve the built site on loopback, request it, and inspect desktop/mobile layouts through local
    screenshots when browser tooling is available.
  - Run focused documentation searches and `git diff --check` in both repositories.
  - Run `bash bin/gate.sh --fast` during implementation and the canonical ScorchKit DIFF gate for
    validation. Do not run the full gate or a repository-wide mutation scan.
- Operator confirmation: the owner's 2026-08-21 direction confirms this exact Codex-preferred,
  Daybreak-capable, agent-neutral design and its copy-only security boundary.

## Phase 3 — Implement

- Files and behavior changed:
  - Rewrote the website hero to lead with Codex-preferred application security, optional Daybreak
    Blue defensive reasoning for approved users, and ScorchKit's retained authorization/evidence
    boundary.
  - Expanded the Codex callout into a responsive three-layer presentation for Codex plus Codex
    Security, Daybreak Blue, and the ScorchKit evidence engine. Added nearby official model, scan,
    plugin, and Trusted Access links plus an explicit no-automatic-access/no-evidence-promotion
    statement.
  - Removed the remaining homepage-level Claude compatibility reference in favor of a general MCP
    compatibility statement. Historical and detailed compatibility documentation remains intact.
  - Updated navigation, page metadata, social descriptions, and the website contributor README.
  - Added `scripts/check-content.mjs` and `npm run check:content` to assert the public hierarchy,
    access qualification, official links, provenance boundary, metadata, and absence of a Claude
    Code homepage claim without adding a dependency.
  - Updated ScorchKit's README, Codex plugin guide, application-security workflow architecture, and
    changelog so the external website claim has a durable source in the engine repository.
- Design deviations:
  - No separate React component was needed for the three-layer presentation; keeping it inside the
    existing `Usage` section preserves page order and avoids another single-use abstraction.
  - The rendered copy uses “frontier defensive reasoning” rather than “highly intelligent” because
    the former is specific, source-backed, and does not promise an unmeasured outcome.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | The source contract, production render, and desktop/mobile DOM all present the same Codex-preferred, Daybreak-optional, ScorchKit-authoritative hierarchy. No overflow, browser errors, broken internal anchors, or contradictory metadata were found. | None | Accepted; no change required. |
| 2 | Security | Daybreak is described only as separately approved and provisioned host reasoning. The copy denies model-granted target authority, silent model selection, policy bypass, and promotion of model conclusions into scanner evidence. | None | Accepted; official model and Trusted Access links remain adjacent to the claim. |
| 3 | Data integrity | Scanner output remains the only scanner-evidence source, while Codex and Daybreak analysis stays separately labeled. The dependency-free content contract pins that provenance boundary and the access qualification. | None | Accepted; no change required. |
| 4 | Simplification | The change reuses the existing `Usage` section and design system, adds no runtime dependency, and changes no engine or provider contract. A new component or model-selection abstraction would add indirection without behavior. | None | Accepted; retain the narrow content-only architecture. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Website `npm run check:content`: passed against the exact source tree.
  - Website `npm run typecheck`: passed from an exact source copy on executable local scratch.
  - Website `npm run build`: passed from the same source copy; the production bundle completed
    without errors or dependency changes.
  - Website loopback preview: returned the built page; desktop 1440x1000 and mobile 390x844
    inspections found no horizontal overflow, browser errors, or warnings.
  - `git diff --check`: passed in both repositories.
  - `bash bin/gate.sh --fast`: 14 passed, 0 failed, 8 mode/applicability skips.
  - `DATABASE_URL=postgresql://chadpeppers@localhost/scorchkit_codex_validation_001 bash
    bin/gate.sh --diff`: 19 passed, 0 failed, 3 named web-only skips. Coverage, strict Nextest,
    PostgreSQL, and CLI/MCP contracts passed.
  - DIFF mutation selection contained zero viable mutations because the engine change is
    documentation and pipeline state only: 0 caught, 0 missed, 0 unviable, 100% defined empty-set
    score at the unchanged 95% floor. No full or repository-wide mutation scan ran.
- Gate run and receipt:
  - Pre-completion exact-tree DIFF receipt recorded worktree digest
    `61ac011291796d4b4b1f5bfc583da5b99937dcb3a20bae97205abe34a4137fd7`.
- Documented skips with reasons:
  - Gate 17 browser E2E, gate 18 website dogfood render, and gate 19 built CSS sheets are not
    applicable to the terminal engine. The separate website received its own build and browser QA.

## Phase 5 — Complete

- Docs updated: README, Codex plugin guide, application-security workflow architecture, changelog,
  roadmap, website contributor README, and public source/metadata are synchronized.
- AAR submitted: `AAR-019-daybreak-codex-website` with one reusable prevention rule added to the
  knowledge index.
- Archive: pending the repository-owned completion transition and post-archive DIFF receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
