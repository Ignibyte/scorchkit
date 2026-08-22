---
title: INTAKE-model-analysis
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Provider-neutral model analysis roles and evaluations

## Problem or opportunity

ScorchKit has typed AI planning, analysis, correlation, and remediation contracts and a Codex-first
host workflow. It does not yet define how host-managed, service-managed, and local models satisfy
specific analysis roles, report availability, preserve provenance, or prove useful behavior against
a repeatable evaluation corpus.

## Proposed outcome

Approved hosts and model providers implement versioned roles for planning, validation, correlation,
attack-path reasoning, remediation, and verification. Codex and separately provisioned defensive
models remain preferred host capabilities, while the engine stays provider-neutral and refuses
silent model substitution.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a workflow requests a model role, ScorchKit shall resolve only an explicitly configured compatible provider and model and shall return a typed unavailable state rather than silently substitute another model or broaden scanner work. | Provider/readiness matrix and missing-capability tests. |
| REQ-002 | When a host-managed, service-managed, or local provider returns analysis, ScorchKit shall record the provider, exact model, role, contract version, input evidence digests, workflow version, timestamp, confidence, and execution location. | Provenance fixtures across storage, API, MCP, and reports. |
| REQ-003 | When model analysis references a finding or attack path, ScorchKit shall store it as a separate labeled layer and shall not allow it to create scanner evidence, change engagement grants, or silently transition finding state. | Authority-bypass and evidence-separation tests. |
| REQ-004 | When a service-managed model sends data outside the host, ScorchKit shall apply explicit endpoint, credential, redaction, retention, timeout, and output policies before the request. | Authorized mock-provider, secret, endpoint, timeout, and size-limit tests. |
| REQ-005 | When a model/provider version is proposed for a role, ScorchKit shall evaluate it against a versioned application-security corpus containing valid findings, false positives, missing context, attack paths, and unsafe tool proposals before marking it eligible. | Deterministic evaluation runner and regression corpus. |

## Scope notes

- In: provider-neutral roles, readiness, host/service/local adapters, provenance, data policy, and
  evaluation contracts.
- Out: granting Daybreak or other model access, automatic enrollment, provider-specific core types,
  model authority over effects, or relabeling analysis as deterministic evidence.
