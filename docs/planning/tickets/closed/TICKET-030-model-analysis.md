---
title: TICKET-030-model-analysis
status: done
ticket_number: 030
type: feature
created: 2026-08-24
closed: 2026-08-24
intake: docs/planning/intake/INTAKE-model-analysis.md
pipeline_spec: docs/planning/pipeline/completed/model-analysis.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-030
---

# Provider-neutral model analysis roles and evaluations

## Summary

Add one provider-neutral model-analysis contract for six reasoning roles, exact role-to-model
resolution, typed readiness, host/service/local adapters, complete labeled provenance, and a
deterministic AppSec evaluation corpus. Model output remains interpretation and cannot authorize an
effect, create scanner evidence, or transition finding state.

## Why

SK-030 established typed AI task envelopes and SK-049 through SK-051 established the control,
extension, and lifecycle boundaries. ScorchKit now needs an exact, observable way to decide whether
a configured model can perform a role without silently substituting another model or treating a
model claim as engine evidence or authority.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a workflow requests planning, finding validation, correlation, attack-path reasoning, remediation, or verification, ScorchKit shall resolve only the one explicitly configured compatible provider and exact model for that role and shall return a typed unavailable state instead of substituting another model or broadening scanner work. | Exhaustive role/readiness matrix, duplicate-binding negatives, and exact-provider/model response tests. |
| REQ-002 | When ScorchKit reports model readiness, it shall distinguish disabled, unconfigured, invalid, unavailable, evaluation-required, and ready states without executing the model or exposing credentials. | Core and control-projection truth tables plus credential-safe serialization tests. |
| REQ-003 | When a host-managed, service-managed, or local adapter returns analysis, ScorchKit shall validate the exact provider, model, role, contract version, and response kind and shall record input evidence digests, workflow version, timestamp, confidence, and execution location in deterministic labeled provenance. | Adapter envelope rejection tests and provenance identity/serde fixtures through storage, control/MCP canonical results, HTML, terminal, PDF, and SARIF. |
| REQ-004 | When model analysis references a finding or attack path, ScorchKit shall keep it in the append-only agent-analysis layer and shall not allow it to create scanner evidence, change engagement grants, or transition finding lifecycle state. | Finding identity/evidence/status invariance tests and durable child-record parity checks. |
| REQ-005 | When a service-managed adapter is configured or invoked, ScorchKit shall require a credential-free exact HTTP(S) endpoint, environment-indirect credential, mandatory redaction and no-retention policy, bounded input/output/time, engagement authorization, credential-use authorization, and an audit decision before the no-redirect request. | Configuration boundary table and authorized/denied loopback service tests for endpoint, credential, redaction, audit order, timeout, and byte ceilings. |
| REQ-006 | When a provider/model/role is proposed for use, ScorchKit shall evaluate its typed answers against the complete versioned AppSec corpus for valid findings, false positives, missing context, attack paths, and unsafe tool proposals and shall mark only an exact all-pass result eligible. | Corpus completeness contract, duplicate/missing/wrong-answer tests, exact eligibility-key tests, and adapter-driven evaluation fixture. |
| REQ-007 | When existing `scorchkit.ai/v1` planning and analysis configuration is used without the new model-role configuration, ScorchKit shall preserve its current Codex-first/Claude-compatible behavior and deterministic fallbacks. | Existing AI provider, CLI, MCP, autonomous-runner, and configuration compatibility suites. |

## Scope

- In: provider-neutral role/request/response/provenance/evaluation contracts; explicit role
  configuration; exact resolution and readiness; bounded host/local process and policy-owned
  service adapters; evaluation runner; analysis-layer storage validation and report projections;
  control readiness projection; tests and durable documentation.
- Out: granting or enrolling any model, choosing a model for the operator, provider-specific core
  types, OAuth/OIDC, multi-tenant model credentials, model-created evidence or grants, automatic
  finding transitions, remote/public test targets, changes to legacy `scorchkit.ai/v1`, and a FULL
  mutation inventory.

## Locked decisions

- The exact configured provider/model binding is authoritative for one role; no fallback candidate
  is searched.
- Eligibility binds provider, exact model, role, analysis contract, and corpus version and requires
  every corpus case to pass.
- Service-managed v1 permits only credential-free HTTP(S), environment-indirect bearer
  credentials, no redirects, mandatory redaction, and declared no retention.
- Model records extend the existing labeled agent-analysis child layer; scanner evidence, finding
  identity, policy, and lifecycle remain unchanged.
- Existing `ai` configuration remains the compatibility path; the new `model_analysis` section is
  disabled by default.
- Validation uses one normal DIFF run. If it identifies survivors, only the exact survivor set is
  repaired and rechecked; no repeated broad mutation run or no-argument/full gate is authorized.

## Recon

- Intake: `docs/planning/intake/INTAKE-model-analysis.md`.
- Reused seams: `scorchkit-core` canonical finding/analysis records, `AiProvider` typed consumption
  checks, the policy-owned HTTP client, bounded `ToolExecutor`, PostgreSQL analysis children,
  control canonical findings, and existing report renderers.
- The current durable finding stores child analysis rows but public reads do not independently
  verify those rows against the canonical analysis document; this ticket closes that parity gap.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/model-analysis.spec.md`
- Operator directed work to continue to the next ticket and authorized local commits. No push, PR,
  model enrollment, remote provider call, or remote target is authorized.

## Log

- 2026-08-24: opened.
- 2026-08-24: intake promoted; plan scoped to exact role resolution, labeled analysis, bounded
  adapters, readiness, and deterministic evaluation while preserving the legacy AI compatibility
  path.
- 2026-08-24: the owner directed ScorchKit to squash only the completed DIFF run's 71 survivors,
  avoid another broad mutation run, commit the finished ticket, and move to the next ticket. The
  approved repair scope is exactly those 71 names in 17 functions across six files, with one
  residual name permitted a separately sealed exact follow-up.
