---
title: INTAKE-typed-run-pipeline
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Typed run preprocessors and lifecycle hooks

## Problem or opportunity

ScorchKit already has an event bus and pre-scan, post-module, and post-scan scripts. Their current
contracts are deliberately narrow: pre-scan output is informational, post-module may replace a
findings array, and post-scan output is ignored. Arbitrary JSON replacement is not a sufficient
foundation for configurable preprocessing, correlation, exports, or third-party extensions.

## Proposed outcome

The current lifecycle becomes a versioned typed run pipeline covering intake validation,
preprocessing, plan proposals, authorization, execution, normalization, enrichment, correlation,
analysis attachment, reporting, and notification. Hooks propose changes; ScorchKit validates and
reauthorizes them before use.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a processor or hook registers for a lifecycle phase, ScorchKit shall require a versioned input/output schema, declared capabilities, failure mode, ordering rule, and resource budget. | Registry and invalid-contract tests. |
| REQ-002 | When a preprocessor proposes a target, module, credential, capability, or effect change, ScorchKit shall canonicalize and reauthorize the proposal and shall reject any expansion not granted by the engagement. | Proposal and policy-clamp matrix with no-side-effect negatives. |
| REQ-003 | When post-module processing filters, deduplicates, enriches, or correlates findings, ScorchKit shall preserve the original scanner finding and evidence and shall record the derived proposal and disposition separately. | Immutable-evidence and projection tests. |
| REQ-004 | When a required policy or integrity hook fails, ScorchKit shall fail closed; when an optional enrichment or notification hook fails, ScorchKit shall expose a degraded or queued outcome according to its declared contract. | Failure-mode and terminal-state matrix. |
| REQ-005 | When cancellation, timeout, or output overflow occurs during a processor or hook, ScorchKit shall stop its owned work through the shared executor and shall not publish a false successful phase. | Cancellation, timeout, overflow, and cleanup fixtures. |
| REQ-006 | When a notification phase emits external work, ScorchKit shall enqueue a redacted event through the SK-043 durable policy-owned queue rather than extend scan completion. | Queue integration and scan-independence tests. |

## Scope notes

- In: typed phases, proposal validation, hook compatibility/migration, ordering, failure semantics,
  cancellation, derived-record provenance, durable notification handoff.
- Out: policy bypass through hooks, destructive rewriting of scanner evidence, unbounded scripts,
  or a second event system beside the existing bus.
