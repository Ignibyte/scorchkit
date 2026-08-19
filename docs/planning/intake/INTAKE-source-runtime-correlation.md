---
title: INTAKE-source-runtime-correlation
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Source-to-runtime attack-path correlation and focused verification

## Problem or opportunity

Existing correlation rules pair findings through coarse module and category matches. They cannot
reliably connect a code source-to-sink path, application route, dependency, runtime request, and
repair verification into one defensible attack path.

## Proposed outcome

ScorchKit will correlate static hypotheses with runtime observations using typed route, parameter,
component, weakness, and provenance keys, producing one attack path that distinguishes suspected,
reachable, reproduced, mitigated, and regressed states.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When SAST and DAST observations share a route, parameter, component, or weakness identity, ScorchKit shall create a deterministic correlation candidate without altering either observation. | Correlation matrix and non-mutation tests. |
| REQ-002 | When runtime evidence reproduces a static hypothesis, ScorchKit shall promote the attack path to verified while preserving both provenance chains. | Vulnerable loopback application fixtures. |
| REQ-003 | When runtime evidence does not reproduce a hypothesis, ScorchKit shall record the attempted conditions and shall not mark the source finding as disproved without sufficient coverage. | Negative and incomplete-coverage fixtures. |
| REQ-004 | When a verified finding is repaired, ScorchKit shall derive the smallest rule, template, request, and test selection needed for focused verification. | Selection and regression fixtures. |
| REQ-005 | When correlation confidence changes, ScorchKit shall record the transition and responsible evidence rather than replacing the original scanner confidence. | State-transition and storage round-trip tests. |

## Scope notes

- In: typed correlation keys, attack-path states, evidence lineage, focused verification selection,
  deterministic scoring inputs.
- Out: agent-only claims treated as runtime proof, automatic exploitation, global risk scoring
  unrelated to application reachability.
