---
title: Codex-first plugin and workflow skills
pipeline_id: 18311993-f79a-4319-8eee-d8fb19da3ba9
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-005
ticket_doc: docs/planning/tickets/closed/TICKET-005-codex-first-plugin.md
aar: docs/planning/knowledge/aar/AAR-005-codex-first-plugin.md
created: 2026-08-17
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-005
---

# Codex-first plugin and workflow skills — spec

## Intent

Package ScorchKit's Codex-first operating surface without coupling the engine to Codex. Codex loads
one repository-owned plugin, discovers the local stdio MCP server, and selects a focused skill for
engagement preparation, planning, execution, reporting, or remediation verification. Every skill
uses MCP tools directly and treats the configured engagement policy as authoritative. The package
becomes the executable host contract that SK-032 and SK-033 must preserve.

## Scope

- In: plugin manifest and MCP descriptor; five focused skills and `agents/openai.yaml` metadata;
  repository-owned package validator; gate integration; existing loopback MCP transport and project
  contract evidence; optional include/skip selectors on persisted project scans; operator
  documentation; architecture, roadmap, and changelog updates.
- Out: MCP `structuredContent`, annotations, principal propagation, or tool regrouping; core crate
  extraction; personal or repository marketplace mutation; installing or reinstalling the plugin;
  remote MCP; new scan or provider effects; new authorization grants; raw CLI workflow
  instructions; remote or third-party target testing.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When Codex loads the ScorchKit plugin, it shall discover one valid manifest, one local stdio MCP server, and five focused workflow skills. | Official validators and repository package contract. |
| REQ-002 | When a skill operates ScorchKit, it shall use MCP tools/resources and contain no terminal, shell, Cargo, or raw ScorchKit CLI workflow. | Static negative package contract. |
| REQ-003 | When engagement preparation is requested, the skill shall confirm the exact authorized target, use project/target state only as inventory, and identify engine policy as the authorization source. | Required phrases/tools and policy-negative regressions. |
| REQ-004 | When planning is requested, the skill shall inspect target/module state, produce a reviewable plan, and not execute a scan. | Required-tool and forbidden-effect assertions. |
| REQ-005 | When execution is requested, the skill shall choose the least-powerful sufficient profile, use durable jobs for non-persistent work or project scanning with approved module selectors for persistence, and preserve identifiers and evidence. | Skill contract and focused duplex/project MCP tests. |
| REQ-006 | When reporting is requested, the skill shall read posture, findings, evidence, and correlation before optional labeled AI interpretation, without changing finding state. | Evidence-order and forbidden-state assertions. |
| REQ-007 | When remediation verification is requested, the skill shall capture a baseline, rescan the same registered authorized target at user direction, compare evidence, and verify only evidence-supported fixes. | Skill contract and finding lifecycle regressions. |
| REQ-008 | When the package is introduced, production Rust shall remain agent-neutral and current JSON-in-text MCP compatibility shall be documented rather than represented as native structured content. | Source/dependency inspection and architecture review. |
| REQ-009 | When plugin files change, fast and delivery validation shall run a repository-owned plugin contract independent of the local Codex installation. | Gate selftest and matching receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put the package under `plugins/scorchkit` with a standard `.codex-plugin/plugin.json`, `.mcp.json`, and `skills/` tree. | The host adapter is distributable while remaining outside engine crates. |
| 2 | Bundle five phase-specific skills: `prepare-security-engagement`, `plan-security-engagement`, `run-security-engagement`, `report-security-findings`, and `verify-security-remediation`. | Narrow triggers prevent an informational request from implicitly expanding into scan or state effects. |
| 3 | Declare `scorchkit serve` as stdio startup metadata and pass through only `DATABASE_URL`; do not store values, targets, or credentials. | The binary remains operator-installed and workspace configuration remains the authorization source. |
| 4 | Do not add or modify a marketplace and do not install the package during this ticket. | Package creation was authorized; user-level plugin state and catalog changes were not. |
| 5 | Keep operational skills free of shell instructions and stop with a clear setup error when the MCP server is unavailable. | Codex should operate through MCP, and a missing adapter must not trigger an improvised CLI bypass. |
| 6 | Use the current typed input schemas and JSON MCP content, while naming native structured results as SK-032 debt. | The package gets a truthful current contract without preempting the transport redesign. |
| 7 | Add optional `modules` and `skip` fields to `ProjectScanParams` and apply them after the authorized profile filter. | The published `plan_scan` → `project_scan` workflow must be executable without broadening the profile or duplicating a scan. |
| 8 | Reuse existing authorized loopback and database MCP contracts, adding only focused project-selector regressions plus a repository-owned static package validator. | The plugin contract is proven at its actual MCP and package boundaries. |
| 9 | Run one normal DIFF mutation pass scoped to the changed MCP functions, seal a green result, and reuse it after archive only while mutation inputs are unchanged. | This respects the owner's no-repeat direction while retaining a canonical post-archive receipt. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-005-codex-first-plugin.md`
- AAR: `docs/planning/knowledge/aar/AAR-005-codex-first-plugin.md`
- Architecture: `docs/architecture/agent.md` and `docs/architecture/mcp.md`

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
