---
title: {{TITLE}}
pipeline_id: {{UUID}}
status: Phase 1 — Plan: in progress
ticket: TICKET-{{NUMBER}}
ticket_doc: docs/planning/tickets/open/TICKET-{{NUMBER}}-{{SLUG}}.md
aar: docs/planning/knowledge/aar/AAR-{{NUMBER}}-{{SLUG}}.md
created: {{DATE}}
---

# {{TITLE}} — spec

## Intent

<Describe what ships and why now.>

## Scope

- In:
- Out:

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When `<trigger>`, ScorchKit shall `<observable response>`. | `<test, gate, or review evidence>` |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | | |

## Linked artifacts

- Ticket: `docs/planning/tickets/open/TICKET-{{NUMBER}}-{{SLUG}}.md`
- AAR: `docs/planning/knowledge/aar/AAR-{{NUMBER}}-{{SLUG}}.md`
- Architecture:

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
