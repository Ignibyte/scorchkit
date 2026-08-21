---
title: TICKET-018-public-documentation-sync
status: done
ticket_number: 018
type: chore
created: 2026-08-21
closed: 2026-08-21
intake:
pipeline_spec: docs/planning/pipeline/completed/public-documentation-sync.spec.md
---

# Synchronize ScorchKit website and public documentation

## Summary

Replace the obsolete ScorchKit marketing-site narrative and synchronize the repository's public
entry points with the shipped 3.0 application-security engine. The website will explain what is
available now, how to install a supported build, how to authorize and run a first scan, which
external tools are optional, and what is completed or next on the product timeline.

## Why

The separate `Ignibyte/scorchkit_home` site still describes a Claude-first 80-module product with
24 MCP tools, an obsolete v1-to-v3 roadmap, and a first-run command that omits the required
engagement. Repository documentation also mixes three clone URLs and the roadmap census disagrees
with executable registry tests. These public surfaces can direct users to the wrong source and teach
a command sequence that fails closed in the current engine.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a user opens the ScorchKit website, the site shall describe ScorchKit as an agent-neutral application-security engine with Codex as the preferred host and shall keep scanner evidence separate from AI analysis. | Website build plus copy review against `README.md`, `SECURITY.md`, and the agent architecture. |
| REQ-002 | When the website or README states capability counts, it shall use the executable registry and MCP contract counts: 67 default web modules, 21 default code modules, 89/22 complete compatibility registries, 39 MCP tools, and five report formats. | `tests/module_census.rs`, MCP inventory fixtures, CLI help, and cross-file content checks. |
| REQ-003 | When a user follows installation guidance, the public docs shall identify Linux/macOS support, the Rust toolchain, the canonical repository URL, a core build and a supported full-feature build, the binary location, and the separate PostgreSQL requirement for persistence/MCP. | Website typecheck/build and reviewed command parity with Cargo features and CLI help. |
| REQ-004 | When a user follows the first-scan workflow, the public docs shall require an owned or explicitly authorized target, run targeted `init` before `run`, and explain that configuration or project registration does not grant effects. | Cross-file copy review against `SECURITY.md` and CLI initialization contracts. |
| REQ-005 | When a user asks how to install scanner integrations, the public docs shall distinguish built-in checks from optional tools, direct users to `doctor --deep` and the versioned tool checklist, and shall not imply that ambient tools or installation grants authorization. | Website/repository link and copy checks against `src/cli/doctor.rs` and `docs/tools-checklist.md`. |
| REQ-006 | When a user reads the public timeline, the website shall show SK-033 through SK-042 as completed outcomes and SK-043 through SK-048 as the ordered next work without restoring deprecated cloud-native work to the core sequence. | Timeline comparison with `docs/planning/ROADMAP.md`. |
| REQ-007 | When the documentation update ships, the README, getting-started guide, first-scan tutorial, CI tutorial, architecture catalog, roadmap, changelog, and documentation index shall agree on repository identity, current counts, install path, and support boundaries. | Repository search, link review, diff inspection, and DIFF gate. |
| REQ-008 | When the landing page is rendered on a phone, desktop, keyboard-only session, or reduced-motion client, its navigation, copy controls, headings, focus indicators, and long code blocks shall remain usable. | Typecheck, production build, and responsive/accessibility source inspection. |

## Scope

- In: the separate `Ignibyte/scorchkit_home` Vite site; ScorchKit's README, public getting-started
  and tutorial entry points, tool/install index, roadmap census/status, changelog, and durable
  pipeline evidence.
- Out: scanner behavior, policy or effect changes, a hosted scanning service, remote MCP, Windows
  support, dependency upgrades unrelated to making the existing site build, publishing a new
  ScorchKit release, synchronizing the stale public source mirror, and changing gate applicability
  for the separate marketing site.

## Locked decisions

- The executable registry tests and CLI help outrank old marketing counts.
- The canonical public repository link is `https://github.com/Ignibyte/scorchkit`; the local
  delivery remote remains unchanged.
- Installation is layered: core binary, supported optional Cargo features, then only the external
  scanners needed for the selected workflow.
- The marketing site is separate from the ScorchKit engine and is not a web scanning UI.
- No push, release, or public-site deployment is performed by the engine repository pipeline.

## Recon

- `Ignibyte/scorchkit_home` is a separate private Vite/React repository with no Pages deployment or
  repository instructions. Its only commit is the obsolete initial marketing site.
- The current site claims 80 modules, four formats, and 24 MCP tools, presents Claude as the product
  owner, and runs `run` before `init`.
- `tests/module_census.rs` fixes the complete web/code registries at 89/22 and the default
  application catalogs at 67/21; the MCP contract is 39 tools and CLI help exposes five formats.
- The public `Ignibyte/scorchkit` mirror is at 3.0.0 but has not received the private repository's
  August application-security work. This ticket updates links and documentation only; source-mirror
  publication remains a separate release action.
- The website build must run from local scratch because the `/Volumes/srv` mount does not execute
  downloaded `esbuild` binaries.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/public-documentation-sync.spec.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: owner requested a website, timeline, installation, usage, README, and repository-doc
  refresh; this is the plan and design confirmation for the documentation-only pivot.
