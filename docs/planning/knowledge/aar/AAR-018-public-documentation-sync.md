---
aar: AAR-018-public-documentation-sync
ticket: TICKET-018
pipeline: public-documentation-sync
status: submitted
opened: 2026-08-21
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-018 — Synchronize ScorchKit website and public documentation

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-doc-examples-contract-001` | The old site runs `run` without creating an engagement. | Yes; all short paths will be checked against current CLI behavior. |
| `PR-scorchkit-host-workflow-tool-contract-001` | The site advertises 24 obsolete Claude MCP tools. | Yes; host copy will follow the 39-tool executable contract and provider-neutral boundary. |
| `PR-scorchkit-default-catalog-explicit-compatibility-001` | Old marketing totals combine default and compatibility scanners. | Yes; the redesign separates 67/21 defaults from the 89/22 complete registries. |
| `PR-scorchkit-scan-coverage-projection-parity-001` | “Install everything” can imply complete coverage despite missing or inapplicable tools. | Yes; optional integrations and coverage gaps remain explicit. |
| `PR-scorchkit-policy-before-effects-001` | Installed tools, targets, and prompts could be mistaken for permission. | Yes; authorization leads every install/use path. |
| `AAR-017-codex-appsec-workflows` | The website is still Claude-first after the product became Codex-preferred and agent-neutral. | Yes; host analysis and engine evidence are described separately. |

## What happened

- Rebuilt the separate static website around the shipped agent-neutral application-security
  boundary, exact capability census, layered install, authorization-first usage, Codex role, and
  completed/next SK-033 through SK-048 timeline.
- Synchronized the engine README, getting-started and tutorial paths, tool guidance, application
  catalog, roadmap, and changelog with the current CLI, policy, registry, and MCP contracts.
- Removed 58 unused website UI/helper files and more than 30 unused runtime dependencies. The
  production CSS output fell from 109.35 kB to 37.19 kB, and npm reported zero vulnerabilities.
- Added an executable public-documentation census assertion so the README, roadmap, and
  application catalog cannot silently return to historical module counts.
- The pre-completion DIFF gate passed all 19 applicable lanes with a receipt for the exact tree.

## Novel findings

- Executable registry tests do not prevent public count drift unless repeated narrative census rows
  are themselves contract fixtures.
- A CI engagement identifier is audit correlation, not authority, but reusing a fixed identifier
  across jobs still erases useful run identity. Each job should create a fresh identifier while
  retaining explicit scope, capability, and effect grants.
- This host's shared workspace mount can store npm packages but cannot execute downloaded native
  JavaScript build helpers. An exact source copy on executable local scratch provides valid build
  evidence without moving source ownership.
- The website repository has no live URL, Pages deployment, deployment history, or Sites manifest.
  Updating source and publishing it are separate delivery actions and must not be conflated.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-public-census-drift-001` | Public website, roadmap, and catalog counts diverged from the executable registries. | Planning recon and cross-file census review. |
| `BF-scorchkit-shared-mount-site-builder-exec-001` | Vite dependencies installed on the shared mount, but its downloaded native builder could not execute there. | Initial website production build. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-public-census-contract-001` | Bind every repeated current public capability census to an executable documentation-parity test sourced from the registry contract. | Registry tests alone do not observe stale website, README, roadmap, or catalog prose. |
| `PR-scorchkit-ci-engagement-run-identity-001` | Give each CI engagement a fresh run identifier while keeping authorization in explicit scope, capability, and effect grants. | A stable identifier grants nothing and weakens audit correlation when reused across runs. |
| `PR-scorchkit-site-executable-scratch-001` | When the shared workspace cannot execute native JavaScript build helpers, validate an exact source copy on disposable executable local scratch. | Build evidence must reflect the real source without weakening mount or execution policy. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled documentation-contract, host-contract, catalog, coverage, and policy rules
changed the content hierarchy before implementation: the site now starts from authorization,
separates application defaults from compatibility inventory, and keeps Codex analysis distinct from
scanner evidence. Adversarial review found and repaired CI trace reuse, count-label ambiguity,
invalid reduced-motion CSS, an unhandled clipboard failure, and unnecessary site dependencies. The
website typecheck/build/preview passed, the new census contract passed 7/7 focused tests, and the
pre-completion DIFF gate passed all 19 applicable lanes.
