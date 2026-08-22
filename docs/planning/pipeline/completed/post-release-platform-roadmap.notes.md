---
title: Document the post-release API extension and frontend roadmap — notes
pipeline_id: 9b49710d-4772-4e2c-9867-558dd48f0d2e
---

# Document the post-release API extension and frontend roadmap — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-model-access-claim-boundary-001`: model access and selection must remain separate
    from engine authorization and scanner evidence. This rules out an engine promise to force or
    silently substitute Daybreak.
  - `PR-scorchkit-host-workflow-tool-contract-001`: Codex workflows must map to shipped typed tools
    and report unsupported host capabilities instead of inventing a fallback.
  - `PR-scorchkit-public-census-contract-001`: repeated public roadmap facts need one canonical
    source. The new candidate sequence will live in `ROADMAP.md` and link to exact intake artifacts.
  - `PR-scorchkit-durable-canonical-parity-001`: future API and team-service projections must check
    canonical durable identities rather than trust duplicated columns or client state.
  - `AAR-017-codex-appsec-workflows`: the host proposes and interprets; ScorchKit policy owns
    deterministic effects and evidence.
  - `AAR-018-public-documentation-sync`: current and future capability claims must not be mixed.
    The roadmap will label SK-049 through SK-057 as candidates, not shipped features.
  - `AAR-019-daybreak-codex-website`: public model language must distinguish availability,
    selection, authority, and provenance.
  - `docs/architecture/runner.md`: ScorchKit already has an event bus and pre-scan, post-module, and
    post-scan hooks. The new pipeline will evolve that seam.
  - Active bulletins: none.
- Recon:
  - The current roadmap ends at SK-048 and has an intake artifact for every queued candidate.
  - Current hook behavior is deliberately limited: pre-scan output is informational, post-module
    may replace the findings array, and post-scan output is ignored.
  - Current AppSec workflow contracts already keep provider choice outside the engine and keep host
    analysis separate from scanner evidence.
  - Rustal is a separate Rust web framework with compiled Askama pages, module registration,
    authentication/RBAC, PostgreSQL, audit, server-sent updates, and an MCP crate. It can support an
    optional console without becoming a ScorchKit core dependency.
- Operator confirmation: after reviewing the proposed SK-049 through SK-057 sequence, the owner
  explicitly directed, “lets document the roadmap again.” That confirms this documentation plan
  and the previously presented architecture. It does not authorize production implementation or a
  remote deployment.

## Phase 2 — Design

- Architecture:
  - Keep `docs/planning/ROADMAP.md` as the single ordered source. Add SK-049 through SK-057 after
    the unchanged SK-043 through SK-048 rows and link every new row to one candidate intake.
  - Group the future sequence into platform foundations, operator surfaces, and team distribution.
    State entry and dependency boundaries rather than presenting candidates as shipped behavior.
  - Expand the target diagram around one provider-neutral control API/application service. CLI,
    MCP, conversation views, Rustal, and CI remain adapters around the same policy, jobs, evidence,
    triage, and storage services.
  - Record extension and hook safety in the roadmap: declared capabilities and effects, bounded
    out-of-process execution for third parties, typed proposals, policy revalidation, immutable raw
    evidence, and labeled model/user layers.
  - Record deployment profiles: complete local headless use first, optional conversation UI and
    Rustal local console next, then authenticated multi-user operation without direct client
    database writes.
- File manifest:
  - `docs/planning/ROADMAP.md`: ordered SK-049 through SK-057 rows, platform contracts, target
    architecture, feature sequence, and future gate applicability note.
  - `docs/planning/intake/INTAKE-control-api.md` through
    `INTAKE-extension-catalog.md`: one scoped, EARS-backed candidate artifact for each roadmap row.
  - TICKET-020, active spec/notes, and AAR-020: delivery evidence only.
- Regression test plan:
  - Check that SK-043 through SK-057 appear exactly once and in order, and that each new intake link
    resolves.
  - Search new prose for claims that UI, remote API, model selection, Rustal integration, or
    extension loading already ship.
  - Review the API, model, evidence, hook, and frontend boundaries against `SECURITY.md`,
    `CONSTITUTION.md` §14, `docs/architecture/runner.md`, and
    `docs/architecture/appsec-workflows.md`.
  - Run `git diff --check`, relevant source/document searches, `bash bin/gate.sh --fast`, then the
    ordinary documentation-only `bash bin/gate.sh --diff` with the required validation database.
    Do not run the full gate or a repository-wide mutation scan.

## Phase 3 — Implement

- Files and behavior changed:
  - Extended the ordered backlog from SK-048 through SK-057 without changing the position or scope
    of SK-043 through SK-048. Every new row links to one candidate intake and remains explicitly
    post-release.
  - Added the post-release platform contracts: one provider-neutral application service,
    narrowing configuration layers, capability-declared extensions, typed hook proposals,
    separately labeled model analysis, append-only triage, optional frontends, and a strict no-core-
    dependency boundary for Rustal.
  - Replaced the target diagram with the future client/API/application-service/evidence/extension
    layering while preserving application security as the default product scope.
  - Added future quality-gate guidance: roadmap UI candidates do not change current web skips; the
    delivering UI ticket must replace them with executable browser/rendering/asset evidence.
  - Added nine candidate intakes with observable requirements and verification methods for the
    control API, extension runtime, typed run pipeline, model analysis, finding triage,
    conversation workbench, Rustal console, team suite, and signed extension catalog.
- Design deviations:
  - The control API candidate does not promise a triage domain before SK-053 creates it. Its
    versioned application-service boundary is explicitly extensible, and SK-053 owns the later
    triage commands and projections.
  - No separate future-architecture document was added. The canonical roadmap contains the future
    contracts, while existing architecture documents continue to describe shipped behavior.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | The first target diagram placed the extension runtime below evidence and reports, which inverted the intended production flow. | Medium | Fixed the diagram so policy and jobs invoke the extension/hook runtime, which produces inputs and evidence before analysis, triage, storage, and reports. |
| 2 | Security | The control API required an authenticated principal for effectful commands but did not define how the default local transport established that principal. | High | Required an operating-system-protected socket or explicitly authenticated loopback transport, rejected client identity metadata as authority, and added local spoofing/permission verification requirements. |
| 3 | Data integrity | The extension requirement listed storage as an extension effect, which could be read as permission to write canonical findings or evidence directly. | High | Removed storage from the extension capability list and required engine-owned validation and persistence with no database, canonical path, or finding-state handle exposed to third parties. |
| 4 | Security | The Rustal console's “explicitly configured local interface” could include a non-loopback wildcard bind before the team identity and isolation work exists. | High | Restricted the default console to loopback or an operating-system-protected local socket and added a non-loopback denial test. |
| 5 | Simplification | The signed extension catalog depended on the multi-user suite even though local offline catalogs and runtime conformance do not need team services. | Low | Removed SK-056 from SK-057's dependency list while retaining its later roadmap position. |
| 6 | Correctness | SK-049 initially named triage as an API domain even though SK-053 owns the triage lifecycle. | Medium | Limited SK-049 to current domains and stated that later domain work extends the same versioned application-service boundary. |
| 7 | Correctness / delivery | The first metadata wrap used Markdown trailing spaces, which failed `git diff --check`. | Low | Kept the status on one line and reran the whitespace check. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - Candidate structure check: SK-043 through SK-057 appear once and in order; each SK-049 through
    SK-057 intake link resolves; passed.
  - Boundary review: new API, extension, hook, model, evidence, local frontend, and team-service
    requirements preserve engine-owned authorization, canonical persistence, and provenance;
    passed after the seven inspection dispositions above.
  - `git diff --check`: passed.
  - `bash bin/pipeline.sh check`: passed.
  - `bash bin/gate.sh --fast`: 14 passed, 0 failed, 8 mode or applicability skips.
  - `DATABASE_URL=postgresql://chadpeppers@localhost/scorchkit_codex_validation_001 bash
    bin/gate.sh --diff`: 19 passed, 0 failed, 3 named web-only skips. Coverage, strict Nextest,
    PostgreSQL integration, and CLI/MCP contracts passed.
  - The documentation-only DIFF selected no changed Rust mutation targets and did not start a full
    or repository-wide mutation campaign.
- Gate run and receipt:
  - The final pre-completion exact-tree DIFF receipt is generated after the changelog, AAR, and
    validation record are finalized and before the phase transition.
- Documented skips with reasons:
  - Gate 17 browser E2E, gate 18 website dogfood rendering, and gate 19 built CSS sheets remain
    inapplicable because ScorchKit does not yet ship a web UI. The roadmap requires the ticket that
    delivers a UI to replace those skips with executable browser, render, and asset evidence.

## Phase 5 — Complete

- Docs updated: the canonical roadmap, nine candidate intakes, changelog, ticket, pipeline evidence,
  and retrospective describe the same SK-049 through SK-057 sequence and safety boundaries.
- AAR submitted: `AAR-020-post-release-platform-roadmap` on 2026-08-21 with effectiveness 5/5.
- Archive: pending the repository-owned completion transition and post-archive exact-tree DIFF
  receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
