---
title: Synchronize ScorchKit website and public documentation
pipeline_id: 830b5941-a185-497b-ac24-04c33814680d
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-018
ticket_doc: docs/planning/tickets/closed/TICKET-018-public-documentation-sync.md
aar: docs/planning/knowledge/aar/AAR-018-public-documentation-sync.md
created: 2026-08-21
---

# Synchronize ScorchKit website and public documentation — spec

## Intent

Ship one current, safe public explanation of ScorchKit across its separate marketing site and the
engine repository. Users should be able to understand the product boundary, install the supported
binary, add only the integrations their workflow needs, authorize a first target, run the first
scan, and read the real completed/next timeline without consulting stale release-era copy.

## Scope

- In: `Ignibyte/scorchkit_home`; repository README and public operator/tutorial indexes; canonical
  repository links; install/use examples; source-backed capability census; product timeline;
  metadata, responsive behavior, accessibility, and copy controls; ticket/AAR/changelog evidence.
- Out: Rust behavior, policy grants, new scanner adapters, marketplace installation, public source
  mirror synchronization, release/tag work, hosted scan execution, remote MCP, Windows, and quality
  gate or Constitution changes.

## Acceptance criteria (EARS)

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

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Use executable registry tests, MCP inventory fixtures, and CLI help as the factual source. | Release-era marketing copy and narrative docs have already drifted. |
| 2 | Keep the website a static product/documentation surface. | ScorchKit does not ship a web scanning UI, remote MCP endpoint, or hosted scanner. |
| 3 | Teach a layered install rather than an “install everything” bootstrap. | Built-ins work without external scanners, several integrations require exact reviewed versions, and installed tools do not grant effects. |
| 4 | Use targeted `init` before the first scan in every short path. | The current engine fails closed without an engagement and initialization performs DNS-only scope preparation. |
| 5 | Compress the internal roadmap into shipped capability eras plus the exact ordered next queue. | A public timeline needs readable outcomes without inventing release dates or changing backlog order. |
| 6 | Preserve the current visual identity and existing social preview asset while replacing stale copy and interaction structure. | The brand is still recognizable and the request does not change branding. |
| 7 | Validate the site from local executable scratch and the engine docs through the normal DIFF gate. | The network mount blocks downloaded JavaScript build binaries, and each repository needs its own real evidence. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-018-public-documentation-sync.md`
- AAR: `docs/planning/knowledge/aar/AAR-018-public-documentation-sync.md`
- Product roadmap: `docs/planning/ROADMAP.md`
- Public site source: `/Volumes/srv/stacks/scorchkit_home`

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
