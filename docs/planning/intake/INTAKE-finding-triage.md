---
title: INTAKE-finding-triage
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Durable finding validation and triage lifecycle

## Problem or opportunity

Real scans produce detector results that can be valid, context-dependent, duplicated, or false
positive. ScorchKit preserves evidence and correlation but lacks one durable lifecycle for model
assessment, user disposition, suppression, accepted risk, remediation, and regression verification.

## Proposed outcome

Each finding retains immutable scanner evidence while append-only transitions record correlation,
validation, human decisions, accepted risk, suppressions, fixes, and regressions. Disagreement
between detectors, models, and users remains visible.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a finding is triaged, ScorchKit shall append a versioned transition to a closed state vocabulary that includes needs-context, validated, likely, false-positive, accepted-risk, fixed, and regressed without changing the original scanner record. | State-machine, immutability, and migration tests. |
| REQ-002 | When findings are deduplicated or correlated, ScorchKit shall retain every contributing scanner identity and evidence reference and shall explain the stable correlation decision. | Multi-scanner and source/runtime correlation fixtures. |
| REQ-003 | When a suppression is created, ScorchKit shall require a scope, reason, actor, creation time, expiry or review date, and applicable finding/rule/target identity; expired or mismatched suppressions shall not hide a result. | Scope, expiry, identity-change, and authorization matrix. |
| REQ-004 | When model analysis recommends a disposition, ScorchKit shall preserve the recommendation and provenance separately and shall require an authorized transition before durable finding state changes. | Model/user disagreement and authority tests. |
| REQ-005 | When a fixed finding reappears or its evidence identity materially changes, ScorchKit shall create a regression or needs-review transition rather than silently apply the prior disposition. | Fixed/reappeared and changed-evidence fixtures. |
| REQ-006 | When triage is read through CLI, MCP, API, reports, or a frontend, ScorchKit shall project the same current state, complete transition history, evidence links, and active suppression status. | Cross-surface parity and corrupt-row tests. |

## Scope notes

- In: append-only triage, validation state, deduplication, correlation explanation, scoped
  suppression, accepted risk, fix/regression state, audit and projection parity.
- Out: deletion of scanner evidence, global permanent ignore lists without review, or automatic
  model-owned dispositions.
