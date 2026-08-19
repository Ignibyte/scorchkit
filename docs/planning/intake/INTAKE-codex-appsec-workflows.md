---
title: INTAKE-codex-appsec-workflows
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Codex-first application-security workflows and tiered scan profiles

## Problem or opportunity

The Codex plugin has generic preparation, planning, execution, reporting, and remediation skills,
but it does not yet present the new application-security lifecycle or prevent irrelevant scanner
families from dominating tool selection.

## Proposed outcome

Codex will receive an application-focused, change-aware workflow across source, dependencies,
artifacts, runtime validation, correlation, remediation, and focused verification while every
contract remains usable by other agents.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When Codex prepares an application assessment, ScorchKit shall expose repository languages, manifests, routes, artifacts, registered targets, available personas, and allowed effect classes through typed agent-neutral contracts. | MCP and plugin transport contract tests. |
| REQ-002 | When a commit profile is selected, ScorchKit shall run only bounded changed-scope secrets, fast SAST, and changed-dependency checks. | Exact profile selection tests. |
| REQ-003 | When PR, staging, release, or deep profiles are selected, ScorchKit shall expand capability in the documented order without silently increasing effect class. | Full profile/effect truth table. |
| REQ-004 | When Codex proposes a scan or repair, ScorchKit shall treat the proposal as untrusted context until policy and adapter validation approve each effect. | Privileged-prompt and attribution-bypass tests. |
| REQ-005 | When a repair is ready for verification, ScorchKit shall prefer the correlated focused checks and shall leave broad scans as explicit scheduled or operator-selected work. | Focused-selection workflow tests. |

## Scope notes

- In: Codex-first skills and MCP contracts, commit/PR/staging/release/deep profiles, changed-scope
  planning, remediation verification, other-agent compatibility.
- Out: agent-specific authority, implicit target registration, automatic broad rescans after every
  mutation, scanner implementations.
