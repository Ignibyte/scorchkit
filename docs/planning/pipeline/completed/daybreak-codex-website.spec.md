---
title: Position the website around Codex and Daybreak Blue
pipeline_id: 1b30b81a-94f8-4462-914e-b409194bba1f
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-019
ticket_doc: docs/planning/tickets/closed/TICKET-019-daybreak-codex-website.md
aar: docs/planning/knowledge/aar/AAR-019-daybreak-codex-website.md
created: 2026-08-21
---

# Position the website around Codex and Daybreak Blue — spec

## Intent

Promote the shipped Codex-first workflow to the website's primary product story and show how an
approved Daybreak Blue model can reason across ScorchKit evidence without changing ScorchKit's
agent-neutral authority, execution, or provenance boundaries.

## Scope

- In: the separate Vite/React site hero, navigation, Codex section, metadata, content source, README,
  and a dependency-free copy contract; corresponding ScorchKit public documentation and delivery
  records.
- Out: model enrollment or provisioning, agent-provider code, scan execution, target access,
  deployment, publishing, and broad security or mutation scans unrelated to this documentation diff.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a visitor opens the home page, the site shall identify ScorchKit as agent-neutral, Codex-preferred, and able to work with Daybreak Blue for approved defensive users. | Content contract, rendered preview, and metadata inspection. |
| REQ-002 | When the Codex section is read, the site shall distinguish Codex orchestration, optional Daybreak Blue reasoning, and ScorchKit-owned authorization, execution, and evidence. | Content contract and rendered desktop/mobile inspection. |
| REQ-003 | When Daybreak availability is described, the site shall state that access is separately approved and provisioned and link to official OpenAI model and Trusted Access documentation. | Exact URL and qualification assertions in the website content check. |
| REQ-004 | When another agent host is considered, the public copy shall preserve agent neutrality and shall not present Claude Code or any vendor as owning ScorchKit's core workflow state or evidence. | Negative content search plus engine documentation review. |
| REQ-005 | When search or social metadata is rendered, the title and descriptions shall present Codex-preferred application security and optional Daybreak use without claiming automatic model selection. | Static metadata assertions. |
| REQ-006 | When the source is delivered, the exact website tree shall pass its content check, TypeScript check, production build, and local preview, and the engine tree shall pass the required repository gate. | Website scripts and ScorchKit DIFF receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep ScorchKit agent-neutral and make Codex the preferred presentation host. | The engine already exposes provider-neutral contracts while the Codex plugin is the strongest supported workflow. |
| 2 | Present Daybreak Blue as optional approved reasoning, not as a bundled scanner or automatic model. | Official OpenAI Docs require separate approval and provisioning, and host analysis cannot become ScorchKit evidence. |
| 3 | Use official OpenAI links for model and Trusted Access claims. | Availability and model positioning can change outside this repository. |
| 4 | Add no core or provider behavior. | The requested change is public positioning; the architecture already supports model selection at the host layer. |
| 5 | Keep delivery source-only. | No live URL, deployment record, Pages endpoint, or Sites manifest exists for the website repository. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-019-daybreak-codex-website.md`
- AAR: `docs/planning/knowledge/aar/AAR-019-daybreak-codex-website.md`
- Architecture:
  - `docs/architecture/appsec-workflows.md`
  - `docs/architecture/agent.md`
  - `docs/guide/codex-plugin.md`

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
