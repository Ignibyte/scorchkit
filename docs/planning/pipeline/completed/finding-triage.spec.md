---
title: Durable finding validation and triage lifecycle
pipeline_id: 8c4c93ca-e8f2-432f-a8fd-ff1b058d6851
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-031
ticket_doc: docs/planning/tickets/closed/TICKET-031-finding-triage.md
aar: docs/planning/knowledge/aar/AAR-031-finding-triage.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-031
created: 2026-08-24
---

# Durable finding validation and triage lifecycle — spec

## Intent

Ship a provider-neutral canonical finding-triage lifecycle that preserves scanner truth while
recording every validation, correlation, suppression, risk, fix, and regression decision as a
bounded append-only record. The current state is reproducible from history, model recommendations
remain non-authoritative provenance, and every client uses the same validated control projection.

## Scope

- In: core triage records and validators; append-only PostgreSQL persistence and migration;
  transition/correlation/suppression commands; deterministic rediscovery transitions; canonical
  control/CLI/MCP/report projection; legacy status mapping; tests and docs.
- Out: scanner-evidence mutation or deletion, permanent global ignore lists, frontend code,
  multi-user identity, model-owned state changes, network effects, live providers/targets, FULL
  mutation, push, or PR.
- Focused repair: exactly the 195 completed DIFF survivors in 47 functions across seven files;
  retain the 598-mutant raw baseline and recheck those exact names without another broad run.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authorized actor triages a finding, ScorchKit shall append one canonical transition containing the exact prior and next closed state, actor, reason, time, evidence references, and optional model-analysis reference without changing the original scanner finding or evidence. | Core state/identity tables, authorization-before-write tests, append/conflict tests, and scanner-record byte-invariance checks. |
| REQ-002 | When findings are deduplicated or correlated, ScorchKit shall append a canonical decision that retains every contributing finding, scanner, and evidence identity plus the normalized facets and a bounded redacted explanation. | Multi-scanner/source-runtime fixtures, ordering/identity/limit tables, and durable parity tests. |
| REQ-003 | When a suppression is created, ScorchKit shall require an exact project plus finding, rule, target, or rule-target scope, a reason, actor, creation time, and a future expiry or review time; only an unexpired exact match shall be active and no suppression shall remove the finding or evidence from canonical reads. | Scope/expiry/review/mismatch truth table, public visibility checks, and exact-boundary tests. |
| REQ-004 | When model analysis recommends a disposition, ScorchKit shall preserve the recommendation and provenance separately and shall reject any state transition that lacks an independently authorized actor command or cites analysis not belonging to the same finding. | Model/user disagreement, cross-finding reference, missing engagement/grant, and audit-order tests. |
| REQ-005 | When a fixed finding reappears under the same stable identity, or a prior disposition no longer matches materially changed evidence, ScorchKit shall append a deterministic regressed or needs-context transition instead of silently retaining the prior disposition. | Repeated-scan, changed-evidence, idempotency, and concurrent-ingest tests. |
| REQ-006 | When triage is read through control API, CLI, MCP, or reports, ScorchKit shall project the same current state, complete ordered history, correlation decisions, evidence links, and active-suppression verdict and shall fail the complete read on malformed or divergent durable child state. | Cross-surface snapshots, external schema fixture, PostgreSQL corruption matrix, and report projection tests. |
| REQ-007 | When existing finding status commands and stored legacy statuses are used, ScorchKit shall map them explicitly into the new transition vocabulary without deleting history or changing headless CLI/MCP compatibility. | Migration matrix and legacy CLI/MCP command/result fixtures. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put the closed state machine, transition/suppression/correlation identities, bounds, normalization, and matching in `scorchkit-core`. | Policy, storage, CLI, MCP, reports, and model providers must not define lifecycle truth. |
| 2 | Store append-only canonical children and retain an indexed `triage_state` projection that must equal reconstructed history. | Reads remain efficient without making a mutable projection authoritative. |
| 3 | Keep raw finding/evidence bytes unchanged and attach triage only in the public resource projection. | Detector truth remains immutable and triage disagreement remains separately labeled. |
| 4 | Route all state-changing operations through `ControlService` with an exact engagement and `local_state` authorization before storage mutation. | A CLI, MCP tool, HTTP client, or future component cannot obtain authority from its presentation surface. |
| 5 | Accept model-analysis identity only as an optional same-finding provenance reference. | A model recommendation cannot transition state or broaden authority. |
| 6 | Treat suppression as an exact time-bounded visibility verdict, never a deletion/filtering primitive at the canonical read boundary. | Expiry and identity drift become visible and historical evidence remains available. |
| 7 | Translate legacy `VulnStatus` inputs through one explicit mapping and keep old command names as adapters. | Existing headless clients remain compatible while the durable authority changes. |
| 8 | Run one DIFF validation and limit any repair to its exact completed survivor set. | This preserves ordinary ticket evidence without repeating broad mutation work. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-031-finding-triage.md`
- AAR: `docs/planning/knowledge/aar/AAR-031-finding-triage.md`
- Architecture: `docs/architecture/finding-triage.md`,
  `docs/architecture/application-security-evidence.md`,
  `docs/architecture/control-api.md`, and `docs/architecture/model-analysis.md`.

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
