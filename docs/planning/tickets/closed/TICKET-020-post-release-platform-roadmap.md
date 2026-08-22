---
title: TICKET-020-post-release-platform-roadmap
status: done
ticket_number: 020
type: docs
created: 2026-08-21
closed: 2026-08-21
intake:
pipeline_spec: docs/planning/pipeline/completed/post-release-platform-roadmap.spec.md
---

# Document the post-release API extension and frontend roadmap

## Summary

Extend the canonical roadmap beyond the current SK-043 through SK-048 delivery queue. Define a
post-release platform sequence for a versioned control API, capability-declared extensions, typed
run preprocessors and hooks, provider-neutral model analysis, durable finding triage, conversation
views, an optional Rustal console, a multi-user suite, and signed extension distribution.

## Why

The first real-project run produced useful candidate findings and uncertain results, which exposed
the need for durable validation and false-positive disposition rather than a scanner-only result
list. The owner also wants ScorchKit to remain useful through a prompt in Codex or Claude while
growing into an optional full suite. The present roadmap stops at release engineering and does not
record the API, extension, model, triage, or frontend contracts needed to reach that product shape.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a reader follows the ordered backlog, the roadmap shall retain SK-043 through SK-048 in their existing order and place the new platform phase after them. | Roadmap table comparison and diff review. |
| REQ-002 | When the post-release platform phase is read, the roadmap shall define separate candidates for the control API, extension runtime, typed run pipeline, model analysis, finding triage, conversation UI, Rustal console, team suite, and extension catalog. | Roadmap and intake-document census. |
| REQ-003 | When an API, extension, hook, model, or frontend candidate is described, the roadmap shall preserve engagement policy as the execution authority and scanner evidence as an immutable layer separate from host or model analysis. | Review against `SECURITY.md`, `CONSTITUTION.md` §14, and architecture documents. |
| REQ-004 | When a frontend candidate is described, the roadmap shall keep CLI and MCP useful without UI, retain local operation as the default, and require every frontend to use the same application service rather than write ScorchKit storage directly. | Roadmap architecture review and candidate intake checks. |
| REQ-005 | When the future hook and extension surface is described, the roadmap shall build on the current event bus and three hook points, require typed capability-declared proposals, and require policy revalidation before any proposal changes execution. | Review against `docs/architecture/runner.md` and candidate intake. |
| REQ-006 | When the Rustal console is described, the roadmap shall treat Rustal as an optional separate client and shall not add a Rustal dependency to ScorchKit core. | Roadmap dependency text and intake review. |

## Scope

- In: `docs/planning/ROADMAP.md`; one intake artifact for each SK-049 through SK-057 candidate;
  ticket, spec, notes, and AAR evidence needed to deliver the documentation.
- Out: API or UI implementation; changes to scan behavior, configuration, policy, storage, model
  selection, hooks, MCP transport, website source, Rustal source, release artifacts, or gate
  applicability.

## Locked decisions

- SK-043 through SK-048 remain the active ordered queue. Platform expansion begins only after
  SK-048.
- ScorchKit remains agent-neutral and Codex-preferred. No model or host becomes an authorization
  boundary or scanner-evidence source.
- The control API owns shared application commands, queries, configuration resolution, and events.
  MCP, CLI, conversation UI, and Rustal are clients of that boundary.
- First-party extensions may remain compiled Rust. Third-party extensions use an isolated,
  capability-declared out-of-process boundary rather than an in-process native ABI.
- Raw scanner evidence is immutable. Hooks, models, and users add labeled proposals, analyses, and
  dispositions.
- Local headless operation remains complete. UI and multi-user services are optional layers.

## Recon

- No active bulletins exist and the pipeline preflight reports no active ticket.
- `docs/architecture/runner.md` records the current pre-scan, post-module, and post-scan hook
  behavior plus the event bus. Hook v2 should strengthen this seam rather than add a parallel
  lifecycle.
- `docs/architecture/appsec-workflows.md` already separates host analysis, operator-selected models,
  engine authorization, and scanner evidence.
- TICKET-018 established that public roadmap claims need a canonical source. TICKET-019 established
  that model access and selection must remain separate from engine authority and provenance.
- Rustal already supplies compiled Rust pages, modules, RBAC, PostgreSQL, audit, server-sent
  updates, and MCP foundations. A future console can use those facilities as a separate API client.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/post-release-platform-roadmap.spec.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: owner approved documenting the previously discussed post-release API, extension,
  model, triage, conversation, Rustal, and full-suite roadmap.
- 2026-08-21: plan passed and design started from the owner-approved nine-candidate sequence.
- 2026-08-21: implemented the roadmap expansion and nine candidate intake specifications without
  changing production behavior or current queue order.
