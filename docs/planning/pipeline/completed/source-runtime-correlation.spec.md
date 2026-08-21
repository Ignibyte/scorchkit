---
title: Source-to-runtime attack-path correlation and focused verification
pipeline_id: fa239f34-f7e8-46b3-b770-59f982e3fdee
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-015
ticket_doc: docs/planning/tickets/closed/TICKET-015-source-runtime-correlation.md
aar: docs/planning/knowledge/aar/AAR-015-source-runtime-correlation.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-015
created: 2026-08-21
---

# Source-to-runtime attack-path correlation and focused verification — spec

## Intent

Ship one provider-neutral application attack-path contract over finding-v2 evidence. It correlates
typed source, runtime, package, route, parameter, weakness, application, and deployment identities;
assigns only evidence-supported states; appends comparable verification transitions; derives inert
focused verification selections; and preserves that contract through PostgreSQL, MCP, and reports.
This replaces "confirmed" language based on title/module coincidence with an auditable proof model
needed by the next application-pentest ticket.

## Scope

- In: typed correlation facets; deterministic path and transition identities; suspected, reachable,
  reproduced, mitigated, and regressed states; evidence and finding references; comparable coverage;
  exact focused selectors; storage; MCP; text/JSON/Mermaid projections; legacy labeling; focused
  validation.
- Out: automatic requests or tests; exploit orchestration; general infrastructure/cloud attack
  graphs; cross-project linking; secrets in selectors; agent text as proof; rewriting finding
  confidence or evidence; a repository-wide mutation run.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When source and runtime observations share a normalized route, parameter, component, application, deployment, or weakness identity, ScorchKit shall produce a deterministic correlation candidate without modifying either finding or its scanner confidence. | Facet cross-product, permutation, identity, and input snapshot tests. |
| REQ-002 | When runtime evidence reproduces a static hypothesis, ScorchKit shall require a source flow, redacted HTTP proof, matching weakness and precise application facet, and compatible revision/deployment provenance before assigning reproduced. | Exact proof-condition matrix and versioned fixture. |
| REQ-003 | When verification does not reproduce a path, ScorchKit shall record conditions and shall assign mitigated only for complete comparable coverage. | State-machine coverage matrix. |
| REQ-004 | When later comparable proof reproduces a mitigated path, ScorchKit shall append a regressed transition and retain all prior proof. | Transition order, idempotence, and round-trip tests. |
| REQ-005 | When source/runtime provenance exists, ScorchKit shall derive minimal exact rule, template, request, and test selectors without executing them or retaining credential values. | Minimality, redaction, and deterministic-selection tests. |
| REQ-006 | When paths cross storage, MCP, or report boundaries, every schema, identity, state, facet, reference, gap, transition, and selection shall remain equivalent. | PostgreSQL, MCP, text, JSON, and Mermaid parity tests. |
| REQ-007 | When legacy heuristic chains are retained, ScorchKit shall label them unverified and shall not use heuristic or agent-only data in canonical state. | Compatibility and adversarial negatives. |
| REQ-008 | When TICKET-015 is delivered, validation shall use focused mutation evidence for changed or inspection-repaired functions only. | Sealed focused-repair evidence and receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put `AttackPath`, proof, transition, and selection types in `scorchkit-core`. | Domain truth must not depend on MCP, PostgreSQL, CLI, reports, or an agent vendor. |
| 2 | Use normalized typed facets and length-prefixed deterministic identities. | Titles and delimiter-concatenated strings are ambiguous and unstable. |
| 3 | Keep weakness-only pairs suspected; require a precise shared application facet for reachability. | A shared CWE across unrelated endpoints is not reachability. |
| 4 | Require source flow, HTTP proof, and comparable revision/deployment for reproduced. | Runtime detection alone does not prove the same deployed code path. |
| 5 | Make verification an append-only state machine with explicit coverage. | A failed or incomplete negative cannot disprove a static hypothesis or erase prior proof. |
| 6 | Derive exact inert selectors from scanner provenance and redacted HTTP metadata. | Correlation proposes the smallest follow-up but never authorizes or performs effects. |
| 7 | Store canonical path JSON and transitions transactionally under project/path identity. | Current tracked findings preserve evidence, but no durable path history exists. |
| 8 | Preserve old heuristic output only under an explicit legacy/unverified label. | Compatibility must not inherit new proof semantics. |
| 9 | Use focused mutation repair only. | The owner prohibited repeated full and repository-wide mutation scans. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-015-source-runtime-correlation.md`
- AAR: `docs/planning/knowledge/aar/AAR-015-source-runtime-correlation.md`
- Architecture: `docs/architecture/source-runtime-correlation.md`

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
