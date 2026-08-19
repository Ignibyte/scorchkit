---
title: INTAKE-deep-sast-adapters
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Deep SAST adapters and pinned rule provenance

## Problem or opportunity

Semgrep currently uses an automatic ruleset without pinned rule provenance, PHPStan is presented as
a security scanner despite being primarily a correctness analyzer, and ScorchKit has no deep
CodeQL or PHP taint-analysis adapter.

## Proposed outcome

Fast and deep SAST will be separate, language-aware capabilities: pinned Semgrep rules for frequent
analysis, optional CodeQL for supported languages, Psalm taint analysis for PHP, and PHPStan kept as
a distinct correctness signal.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When Semgrep runs through a reproducible profile, ScorchKit shall record a pinned rule-pack identity and reject unapproved network-fetched configuration. | Invocation fixtures and denied-configuration tests. |
| REQ-002 | When a supported-language deep profile selects CodeQL, ScorchKit shall construct and analyze a bounded database while preserving SARIF paths and query provenance. | Local fixture repositories and SARIF golden tests. |
| REQ-003 | When PHP taint analysis is requested, ScorchKit shall run Psalm separately from PHPStan and preserve source-to-sink flow locations. | Vulnerable and sanitized PHP fixtures. |
| REQ-004 | When a repository language is unsupported by a selected deep analyzer, ScorchKit shall report a typed not-applicable outcome without silently claiming coverage. | Language selection matrix tests. |
| REQ-005 | When static results are normalized, ScorchKit shall retain every available flow step, rule identity, confidence, and original scanner evidence. | Adapter parser and evidence-v2 round-trip tests. |

## Scope notes

- In: Semgrep rule governance, CodeQL adapter, Psalm adapter, language selection, SARIF/data-flow
  preservation, deterministic local fixtures.
- Out: hosted commercial SAST services as a required dependency; PHP support through CodeQL;
  runtime validation.
