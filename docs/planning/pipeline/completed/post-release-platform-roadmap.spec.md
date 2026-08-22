---
title: Document the post-release API extension and frontend roadmap
pipeline_id: 9b49710d-4772-4e2c-9867-558dd48f0d2e
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-020
ticket_doc: docs/planning/tickets/closed/TICKET-020-post-release-platform-roadmap.md
aar: docs/planning/knowledge/aar/AAR-020-post-release-platform-roadmap.md
created: 2026-08-21
---

# Document the post-release API extension and frontend roadmap — spec

## Intent

Publish an implementation-ready post-release platform sequence without changing current behavior.
The roadmap will preserve SK-043 through SK-048 and then define the contracts needed for ScorchKit
to operate through a versioned API, capability-declared extensions, provider-neutral reasoning,
durable triage, conversation-native views, a Rustal console, and an optional team service.

## Scope

- In: canonical roadmap structure and target architecture; SK-049 through SK-057 candidate intakes;
  pipeline documentation and knowledge recall.
- Out: production code, API schemas, new network listeners, extension loading, hook execution
  changes, model calls, UI code, Rustal changes, storage migrations, website changes, or releases.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a reader follows the ordered backlog, the roadmap shall retain SK-043 through SK-048 in their existing order and place the new platform phase after them. | Roadmap table comparison and diff review. |
| REQ-002 | When the post-release platform phase is read, the roadmap shall define separate candidates for the control API, extension runtime, typed run pipeline, model analysis, finding triage, conversation UI, Rustal console, team suite, and extension catalog. | Roadmap and intake-document census. |
| REQ-003 | When an API, extension, hook, model, or frontend candidate is described, the roadmap shall preserve engagement policy as the execution authority and scanner evidence as an immutable layer separate from host or model analysis. | Review against `SECURITY.md`, `CONSTITUTION.md` §14, and architecture documents. |
| REQ-004 | When a frontend candidate is described, the roadmap shall keep CLI and MCP useful without UI, retain local operation as the default, and require every frontend to use the same application service rather than write ScorchKit storage directly. | Roadmap architecture review and candidate intake checks. |
| REQ-005 | When the future hook and extension surface is described, the roadmap shall build on the current event bus and three hook points, require typed capability-declared proposals, and require policy revalidation before any proposal changes execution. | Review against `docs/architecture/runner.md` and candidate intake. |
| REQ-006 | When the Rustal console is described, the roadmap shall treat Rustal as an optional separate client and shall not add a Rustal dependency to ScorchKit core. | Roadmap dependency text and intake review. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Finish SK-043 through SK-048 before platform expansion. | The current queue closes notification, remote transport, Windows ownership, dependency, quality, and release prerequisites. |
| 2 | Put one provider-neutral application service behind API, MCP, CLI, and UI surfaces. | Separate frontend business logic would drift and could bypass policy or evidence invariants. |
| 3 | Use compiled Rust for first-party modules and a capability-declared out-of-process protocol for third-party extensions. | A native plugin ABI would put untrusted code inside the policy and evidence process. |
| 4 | Promote current hooks into typed proposals with explicit phase semantics. | Existing hook points and the event bus are useful foundations, but arbitrary JSON must not silently widen scope or rewrite raw evidence. |
| 5 | Keep model output and user triage as append-only labeled layers over immutable scanner evidence. | False-positive handling and semantic review require provenance without erasing what the scanner observed. |
| 6 | Make conversation views and the Rustal console optional clients. | Headless CLI/MCP operation must remain complete, and ScorchKit core must not depend on a frontend framework. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-020-post-release-platform-roadmap.md`
- AAR: `docs/planning/knowledge/aar/AAR-020-post-release-platform-roadmap.md`
- Architecture:
  - `docs/planning/ROADMAP.md`
  - `docs/architecture/runner.md`
  - `docs/architecture/appsec-workflows.md`
  - `docs/architecture/application-security-evidence.md`

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
