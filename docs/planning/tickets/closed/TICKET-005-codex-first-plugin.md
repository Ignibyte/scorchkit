---
title: TICKET-005-codex-first-plugin
status: done
ticket_number: 005
type: feature
created: 2026-08-17
closed: 2026-08-17
intake:
pipeline_spec: docs/planning/pipeline/completed/codex-first-plugin.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-005
---

# Codex-first plugin and workflow skills

## Summary

Ship a repository-owned Codex plugin that connects to ScorchKit's existing local stdio MCP server
and bundles five focused operational skills: engagement preparation, scan planning, scan execution,
finding reporting, and remediation verification. The skills use MCP tools directly, never terminal
instructions, and keep authorization inside the engine's configured engagement policy.

## Why

SK-029 established durable scan jobs and SK-030 fixed the provider-neutral reasoning contract. Codex
can now be the preferred operating host without moving workflow or authorization semantics into the
core engine. Packaging that host layer before the MCP result and crate refactors gives SK-032 and
SK-033 an executable consumer contract to preserve.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When Codex loads the ScorchKit plugin, the package shall expose a valid manifest, the local `scorchkit serve` stdio MCP server, and exactly five focused workflow skills. | Official plugin validator, skill validators, and repository package contract. |
| REQ-002 | When a workflow skill operates ScorchKit, it shall use MCP tools and resources directly and shall not direct Codex to run terminal, shell, Cargo, or raw ScorchKit CLI commands. | Static negative contract plus skill review. |
| REQ-003 | When preparing an engagement, the skill shall require the exact target and explicit user authorization, treat project target registration as inventory only, and leave the configured engine engagement as the sole authorization source. | Skill contract assertions and policy-negative MCP regressions. |
| REQ-004 | When planning a scan, the skill shall gather typed MCP module and target information, return a reviewable plan, and stop before scan execution unless the user separately requested execution. | Required-tool and phase-separation contract. |
| REQ-005 | When executing an authorized scan, the skill shall select the least-powerful sufficient profile, prefer durable scan jobs for non-persistent work, pass approved module selectors into project scanning when persistence is requested, and preserve job or scan identifiers and terminal evidence. | Skill contract plus loopback MCP job and project regressions. |
| REQ-006 | When reporting findings, the skill shall read scanner evidence and posture before optional AI interpretation, label provider analysis as interpretation, and avoid finding-state changes. | Required-tool, evidence-ordering, and forbidden-tool assertions. |
| REQ-007 | When verifying remediation, the skill shall establish a pre-scan baseline, rescan the same registered and authorized target only at the user's direction, compare evidence, and mark a finding verified only when follow-up evidence supports it. | Skill contract and existing finding-lifecycle/project-scan tests. |
| REQ-008 | When the Codex package is added, ScorchKit's core shall remain host-neutral and the package shall depend only on the standard MCP boundary; JSON-in-text compatibility shall remain explicit until SK-032 adds `structuredContent` and annotations. | Dependency/source inspection and architecture documentation. |
| REQ-009 | When plugin files change, the canonical fast and delivery gates shall validate the package and skill contracts without requiring a host-local skill installation. | Repository-owned validator wired into the gate plus DIFF receipt. |

## Scope

- In: repo-owned plugin manifest and stdio MCP descriptor; five Codex workflow skills and UI
  metadata; repository-owned package validation; loopback and existing MCP contract evidence;
  optional module/skip selectors for persisted project scans; Codex plugin documentation; roadmap
  and changelog updates.
- Out: MCP `structuredContent`, annotations, principal binding, or tool regrouping (SK-032); crate
  extraction (SK-033); a marketplace entry or mutation of the user's installed plugins; remote MCP
  transport; new scan capabilities; new authorization paths; shell-driven operational skills;
  provider API changes; remote or third-party targets.

## Locked decisions

- The plugin lives at `plugins/scorchkit` and uses plugin version `0.1.0`; it is a distributable
  repository artifact, not a personal marketplace installation.
- The package declares `scorchkit` with `args = ["serve"]` over stdio and inherits only named
  runtime environment variables. It stores no database URL, token, credential, or target.
- Each skill owns one phase and uses ScorchKit MCP tool names directly. Shared safety rules are
  repeated narrowly where an omitted rule could create an effect.
- A project and its registered targets are inventory, never authorization. The immutable server
  engagement remains authoritative and must deny before effects.
- “Typed MCP content” in SK-031 means MCP-declared input schemas and JSON content consumed through
  MCP. Native `structuredContent`, annotations, read/state/effect separation, and principal context
  remain SK-032 work.
- No repository or personal marketplace is added because the owner requested package delivery, not
  installation or catalog mutation. Validation does not change the user's Codex plugin state.

## Recon

- The existing server exposes 30 tools over local stdio, generated input schemas, JSON result
  content, six project resources, and five prompts. Result bodies are still JSON serialized into
  text for compatibility.
- `scorchkit serve` loads `scorchkit.toml` or `config.toml` from its working directory and fails
  effectful operations closed when no engagement is configured. `DATABASE_URL` is optional for
  stateless jobs and required for project, finding, schedule, and resource operations.
- Durable `scan_job_start` currently has no project field. The execution skill must use durable jobs
  for non-persistent scans and `project_scan` for persisted project scans rather than duplicate one
  scan through both paths. Recon found that `plan_scan` returns module recommendations while
  `project_scan` could not accept them; this ticket adds the same optional include/skip selectors
  already supported by stateless scans.
- Existing duplex MCP tests prove an authorized loopback job and database-backed tests prove
  project registration, scan persistence, posture, and finding lifecycle. This ticket can bind the
  package to those contracts without changing Rust behavior.
- Official OpenAI documentation defines a plugin as a package of skills, an MCP server, or both and
  uses `.codex-plugin/plugin.json`, `skills/`, and an optional `.mcp.json`. The repository's plugin
  creator and skill creator validators provide an independent development check.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/codex-first-plugin.spec.md`

## Log

- 2026-08-17: opened.
- 2026-08-17: the repository owner directed SK-029 through SK-033 back to back, approved a local
  commit for each ticket, and prohibited repeated broad mutation scans. No push, PR, plugin
  installation, marketplace mutation, remote target, or full mutation inventory is authorized.
- 2026-08-17: the normal DIFF gate passed 19 applicable lanes with zero failures, measured 79.54%
  line coverage, ran 1,433 strict cases, and caught 2/2 viable changed-function mutations with zero
  survivors. The result is sealed for the approved post-archive non-mutation delivery proof.
