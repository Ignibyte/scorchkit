---
title: Add an optional Rustal local operator console — notes
pipeline_id: ee5066c5-5f66-4260-8da8-3e70a0aa9325
---

# Add an optional Rustal local operator console — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001`,
  `PR-scorchkit-attribution-not-authorization-001`,
  `PR-scorchkit-durable-canonical-parity-001`,
  `PR-scorchkit-projection-validate-canonical-001`,
  `PR-scorchkit-local-api-principal-boundary-001`,
  `PR-scorchkit-local-frontend-bind-boundary-001`,
  `PR-scorchkit-secretless-control-target-001`,
  `PR-scorchkit-immutable-store-pagination-001`,
  `PR-scorchkit-ui-fixture-canonical-shape-001`, and
  `PR-scorchkit-loopback-harness-nonblocking-driver-001`.
- Comparable evidence: TICKET-027 established authenticated loopback control, typed DTOs,
  canonical reads, page/event bounds, and immutable engagement authority; TICKET-032 established
  escaped optional UI projections and browser/render/CSS gates. AAR-020 already forbids a local
  frontend from using loopback as identity or writing ScorchKit storage directly.
- Rustal recon: sibling Rustal 0.48.0 at
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728` provides a loopback-default `AppBuilder`, typed state,
  compiled page seam, security middleware, and finite SSE producer. Its Git remote is private and
  unavailable here and the crate is not on crates.io. Existing sibling apps use source-path
  dependencies, so this app remains outside the ScorchKit workspace and pins the exact source
  revision through a mandatory preflight.
- Scope correction: the control service owns `Arc<AppConfig>` and deliberately has no engagement
  mutation. The console renders engagement posture read-only and edits only registered targets and
  per-run restrictions through existing commands. It never labels project membership as policy.
- Mutation direction: use one DIFF inventory only. If survivors appear, preserve it and rerun only
  the exact repaired survivor names; do not launch a second broad run.
- Operator confirmation: the user's standing direction is to commit completed work, move directly
  to the next roadmap ticket, continue autonomously, and avoid another long broad mutation run.

## Phase 2 — Design

- Architecture: the app is an independently locked Rustal binary under `apps/`, not a root Cargo
  workspace member. It talks only authenticated loopback HTTP using `scorchkit-control` DTOs. One
  validated server configuration owns the sensitive bearer header, exact engagement, allowed Host
  and Origin, CSRF secret, and hard bounds. Pages and POST actions use Rustal routes; the browser
  has no direct control API access. One background task consumes canonical upstream SSE into a
  fixed monotonic mirror, while finite same-origin SSE replays fit Rustal's nonblocking producer
  contract and let browser EventSource reconnect.
- Authority: active engagement is rendered read-only. Project target registration, run selection,
  job lifecycle, and finding triage invoke exact v1 commands and are independently reauthorized by
  ScorchKit. A console route, page, CSRF token, or local browser supplies no engagement grant.
- Dependency boundary: `bin/console.sh` resolves the sibling Rustal checkout relative to the
  ScorchKit repository, requires HEAD
  `8b741c4c0e4c87542dea575aea9be9acfa3bf728`, and rejects tracked or untracked Rustal crate-source
  drift before app build/test/start. The root workspace neither resolves nor compiles Rustal.
- File manifest: the planned app manifest, lockfile, source modules, templates, assets, fixtures,
  helper, gate wiring, architecture/docs, and focused contract tests are listed in the spec. Root
  source changes are limited to delivery wiring and dependency-boundary assertions.
- Regression test plan: configuration and redaction matrices; mock-control typed request/response
  tests; fragmented SSE and bounded mirror tests; real Rustal dispatch tests for GET/POST security;
  canonical DTO render snapshots; async browser navigation/event/action proof; responsive and
  accessibility renders; asset/source drift checks; root workspace dependency negatives.
- Compatibility: the root library, CLI, MCP, control API, storage, and execution behavior stay
  unchanged. Existing v1 control envelopes are consumed, not extended. Console startup requires
  the separately running `scorchkit control-api` and exact local operator configuration.
- Operator confirmation: the user's standing direction to move through the roadmap and commit each
  completed ticket confirms this design. The engagement refinement narrows the candidate to the
  already shipped immutable authority boundary instead of adding a materially new policy writer.

## Phase 3 — Implement

- Files and behavior changed:
  - Added the independently locked `apps/scorchkit-console` Rustal binary, typed authenticated
    control client, exact loopback configuration, bounded event mirror, guarded Rustal routes,
    compiled Askama views, self-contained assets, app tests, and an app-local target ignore.
  - Added `bin/console.sh` with exact sibling-revision and dependency-source cleanliness preflight;
    root workspace metadata proves neither the app nor Rustal entered the core dependency graph.
  - Added real Rustal dispatch tests and a Chrome/ChromeDriver harness covering navigation, escaped
    hostile records, same-origin mutation, exact control commands, live events, mobile layout,
    forced colors, reduced motion, overflow, and asset/source policy.
  - Extended gate audit, static-source, browser, render, CSS, and selftest lanes for the optional
    app while leaving the root deny and mutation graphs unchanged.
  - Added operator, security, control-boundary, workspace, architecture, roadmap, intake, ticket,
    changelog, and app-startup documentation.
- Design deviations:
  - The sibling Rustal checkout advanced from the initially inspected
    `d2f7a99c6c230b98da8869edb32b0360ec24efc3` revision to
    `8b741c4c0e4c87542dea575aea9be9acfa3bf728` during implementation. The source diff between
    those revisions for `crates/rustal` and `crates/rustal-derive` was empty, the dependency source
    was clean, and every pin was moved together to the exact new HEAD.
  - The finding page exposes durable correlation decisions rather than claiming an attack-path
    query that v1 control does not provide.
  - Evidence selection is one bounded JSON form field because Rustal's current form decoder cannot
    deserialize repeated keys into a sequence.
  - The console uses `Referrer-Policy: same-origin`; `no-referrer` suppressed the browser Origin
    header required by the exact same-origin POST guard.
  - Upstream cursor-expiry/future responses reset only from typed control error codes and bounded
    retention details; ordinary failures remain fail-closed and cannot move the cursor.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Authorization and credential boundary | The default `reqwest` client could honor ambient proxy variables and send the loopback control bearer to that proxy. | high | Fixed with `.no_proxy()`, retained literal-loopback URL validation and redirect denial, and added an executable dependency-boundary assertion. |
| 2 | Event integrity and availability | Initial retention loss, upstream sequence restart, empty live streams, and aggregate transport chunks were not all modeled distinctly. | high | Fixed with typed bounded cursor reset, explicit live connection marking, per-frame streaming limits, and direct tests. |
| 3 | Untrusted presentation | Canonical severity text was escaped but also interpolated into a CSS class, allowing whitespace-separated presentation classes. | medium | Added a closed severity-to-class mapping while preserving escaped display text; real dispatch and browser tests use an adversarial class-shaped severity. |
| 4 | Configuration and resource bounds | Validated configuration fields remained publicly mutable, and the public mirror constructor accepted an unbounded capacity. | medium | Made validated fields crate-private and clamped every mirror construction to the fixed application maximum. |
| 5 | API and error semantics | A malformed locally rejected command appeared as a 502 upstream failure. | medium | Added a private local-validation error class and now return a safe 400 before any API request; captured-request assertions prove no dispatch. |
| 6 | Supply chain and gate ordering | App checks originally lived after mutation, the nested build tree was not excluded from Gitleaks, and app dependency sorting/machete were outside their root-only lanes. | medium | Moved app check into gate 3, excluded only the generated target tree, and added independent sort/machete contracts. Root mutation scope remains unchanged. |
| 7 | Browser security and accessibility | Host/Origin/CSRF/header interaction, active markup, keyboard controls, forced colors, reduced motion, and mobile overflow needed executable composition proof. | medium | Real Chrome allowed the legitimate guarded mutation, rejected hostile behavior, and passed representative render assertions after the flex fix. |
| 8 | Compatibility and dependency direction | The optional app could accidentally become a root workspace member or introduce Rustal into core packages. | high | Root `cargo metadata`, manifest-path assertions, and all-feature headless tests prove the app and Rustal remain outside the core graph. |
| 9 | Upstream dependency health | Pinned Rustal currently brings unmaintained `rustls-pemfile` 2.2.0 (`RUSTSEC-2025-0134`). | low | Accepted as an explicit upstream warning: it is not a vulnerability and the loopback HTTP console does not use Rustal TLS. Audit remains executable; no advisory ignore or false deny claim was added. |

## Phase 4 — Validate

- Tests run (commands and outcomes): `bash bin/console.sh check` passed 13 unit and five
  integration tests plus doc tests after the final inspection fixes; `bash bin/console.sh build`
  passed; `node tests/rustal_console_ui.mjs browser`, `render`, and `css` each passed against the
  real Rustal application. Focused workspace-architecture and quality-gate-contract tests passed,
  as did gate selftest, direct Gitleaks, Semgrep, typos, app Machete, root/app formatting, and
  `git diff --check`. The corrected `bash bin/gate.sh --fast` development run passed all 14 active
  lanes with zero failures; its eight omissions were the mode's documented expensive lanes.
- Gate run and receipt: one
  `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff` passed all 22
  lanes with zero failures or skips. It recorded 85.62% line coverage, 2,197 strict Nextest cases
  with 10 reasoned live-tool/network skips, authenticated PostgreSQL and CLI/MCP contracts, and
  green browser/render/CSS evidence for both optional frontends. The root mutation graph remained
  unchanged by this separately locked app: DIFF reported no viable mutants to filter, compiled no
  mutant, recorded 100% MSI with zero survivors, and required no follow-up run. The mutation-blind
  list is the seven app source modules, its integration test, and the two root static-contract
  tests; app behavior has direct unit, real Rustal HTTP, mock-control, and Chrome evidence. After
  completion changes the worktree, delivery reruns the same DIFF mode for the commit-bound receipt.
- Documented skips with reasons: app `cargo deny` is not claimed because pinned upstream Rustal
  currently resolves unmaintained `rustls-pemfile` 2.2.0 (`RUSTSEC-2025-0134`); this is not a
  vulnerability and the loopback HTTP app does not use Rustal TLS. App `cargo audit` and the root
  deny lane remain executable, and no advisory ignore was added. No remote/public target, live
  model or external service, FULL/no-mode gate, or independently repeated broad mutation run is
  authorized or used.

## Phase 5 — Complete

- Docs updated: README, SECURITY, changelog, control/workspace/console architecture, roadmap
  status/evidence/backlog, intake/ticket indexes, knowledge register/AAR, app operator guide, gate
  contracts, and the pipeline spec/notes describe the separately locked loopback console, exact
  authority and dependency boundaries, executable UI evidence, and empty root mutation selection.
- AAR submitted: `docs/planning/knowledge/aar/AAR-033-rustal-console.md` on 2026-08-24 with
  effectiveness 4/5 and ten reusable failure/prevention pairs.
- Archive: `bash bin/pipeline.sh pass complete` will close TICKET-033, remove it from the open
  queue, archive this spec/notes pair, and rewrite active/open cross-links. Authenticated
  post-archive delivery reruns `bash bin/gate.sh --diff`; the unchanged root mutation graph must
  again complete an empty changed-line selection without compiling mutants before the local
  commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | A clean route with no query returned 500. | Rustal's `Query` extractor requires a query component even when the payload fields are optional. | Captured the raw optional URI query in request parts and parsed a closed vocabulary. | Test the absent-component path whenever an extractor represents optional data. |
| 2 | Repeated evidence form keys did not decode into `Vec<String>`. | The active `serde_urlencoded` decoder does not support that sequence shape. | Encoded one bounded JSON array field and checked uniqueness, count, and lowercase SHA-256 identity. | Exercise generated forms through the exact framework decoder, including collection cardinalities. |
| 3 | Legitimate Chrome mutation forms were rejected. | `Referrer-Policy: no-referrer` removed Origin on same-origin POST while the server required exact Origin. | Switched to `same-origin` and retained exact Origin, Host, CSRF, and fetch-site guards. | Prove the complete browser security-header set through a real successful mutation. |
| 4 | A hostile long title caused mobile horizontal overflow. | Flex min-content sizing allowed the heading to push the severity badge past the viewport. | Added explicit flex min-width, wrapping, and badge bounds. | Render adversarial canonical strings at mobile width and assert document overflow. |
| 5 | A late-starting console could retry an expired event cursor forever, and a large chunk of valid small frames hit the frame bound. | Reconnect did not consume typed retention details, and the decoder bounded transport chunks instead of individual frames. | Added closed expired/future reset rules, live connection marking, and a streaming per-frame decoder. | Test event retention loss, server sequence restart, empty live streams, and chunks larger than the individual-frame ceiling. |
| 6 | A triage integration fixture failed local request validation. | The fixture used a readable evidence label where the public command requires a lowercase SHA-256 identity. | Replaced fixture values with exact digest identities and validated the browser form at the same boundary. | Deserialize and validate asymmetric fixtures through both response and follow-up command contracts. |
| 7 | Gitleaks scanned the optional app's large generated target tree and flagged test credentials. | Root-only generated-path exclusions and credential-shaped high-entropy literals did not fit the new nested app. | Added the exact generated-tree exclusion and constructed recognizable test-only bearer values without secret-shaped literals. | Extend static-tool scope and exact generated exclusions together whenever adding an out-of-workspace app. |
| 8 | Invalid control request fields returned a gateway error even though no request left the console. | Local request validation and authenticated upstream errors shared one erased `anyhow` path. | Added an unexposed local validation marker and mapped it to a safe 400. | Preserve local, transport, and authenticated-service failure classes through adapters. |
