---
title: TICKET-004-typed-ai-provider-contracts
status: done
ticket_number: 004
type: feature
created: 2026-08-16
closed: 2026-08-17
intake:
pipeline_spec: docs/planning/pipeline/completed/typed-ai-provider-contracts.spec.md
focused_repair: approved
---

# Typed and versioned AI provider contracts

## Summary

Replace the raw `AiProvider::generate(system, user)` boundary with provider-neutral planning,
analysis, correlation, and remediation operations. Each operation accepts a typed request and
returns a typed payload inside the same versioned task envelope. Codex remains the preferred CLI
adapter and Claude remains compatible, but neither provider owns prompt schemas, response parsing,
workflow state, scanner evidence, or fallback behavior.

## Why

The current trait lets every caller invent prompt text and interpret arbitrary output. Planning and
analysis use it directly, while correlation and remediation only expose raw prompt pairs and are not
connected to a provider contract. This makes provider equivalence hard to prove and allows prompt or
response changes to bypass compile-time review. SK-029 fixed the job boundary. Typed reasoning
contracts must be fixed next so SK-031 can package Codex workflows and SK-033 can move code without
moving behavior.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a reasoning caller invokes a provider, ScorchKit shall expose a typed planning, analysis, correlation, or remediation method and shall not expose a raw system/user generation method on the provider trait. | Compile-time provider fixture plus source contract test. |
| REQ-002 | When a typed request is rendered for a provider host, ScorchKit shall include the stable `scorchkit.ai/v1` schema identifier and exact task discriminator in the request and required response shape. | Golden prompt-envelope fixtures for all four tasks. |
| REQ-003 | When provider output is decoded, ScorchKit shall accept only the expected schema version and task and shall reject missing, future, or cross-task envelopes before a workflow consumes the payload. | Decoder table tests with valid, missing, wrong-version, and wrong-task fixtures. |
| REQ-004 | When Codex or Claude executes the same typed request, ScorchKit shall render the same contract payload and decode the same typed fixture while keeping provider-specific CLI arguments and envelope normalization inside the adapter. | Shared four-task adapter suite against recording executors. |
| REQ-005 | When planning or analysis succeeds, ScorchKit shall preserve module allow-list validation, typed analysis variants, model/cost metadata, and scanner evidence separation without passing raw prompt strings across the provider boundary. | Planner and analyst service tests plus existing CLI/MCP regressions. |
| REQ-006 | When correlation or remediation AI is disabled, unavailable, malformed, or rejected, ScorchKit shall preserve deterministic rule correlation and deterministic remediation walks without changing scan success. | Disabled, unavailable, malformed, and success-path service tests. |
| REQ-007 | When a provider process may start, ScorchKit shall retain the existing authorization-before-effects host checks, bounded execution, read-only ephemeral Codex mode, and one-turn Claude compatibility mode. | Policy negative tests, exact invocation fixtures, and bounded executor regressions. |
| REQ-008 | When the public contract changes, ScorchKit shall document the versioning and compatibility policy and shall keep typed schemas independent of CLI, MCP, storage, and agent hosts. | Architecture review, public serde round trips, and dependency inspection. |

## Scope

- In: typed task requests and responses; a versioned task envelope; provider metadata and errors;
  four provider trait methods; Codex and Claude transport adapters; planning and analysis migration;
  provider-backed correlation and remediation services with deterministic fallback; shared fixtures;
  architecture, roadmap, and changelog updates.
- Out: remote provider APIs; remote MCP transport; Codex plugin packaging (SK-031); MCP structured
  content and annotations (SK-032); crate extraction (SK-033); scanner or finding schema changes;
  prompt-driven authorization; broad mutation inventory; any remote scan target.

## Locked decisions

- `scorchkit.ai/v1` and the task discriminator are required on every provider response. Version or
  task mismatch is an explicit provider-contract error, not a raw-text success.
- Workflow code constructs typed requests. One provider adapter owns prompt rendering, process
  invocation, provider envelope normalization, and typed response decoding.
- Codex and Claude receive the same serialized task contract. Only invocation mechanics differ.
- Planning failure keeps the requested deterministic profile. Analysis failure remains separate
  from scan success. Correlation falls back to rule results and remediation falls back to the local
  risk-ordered walk.
- Provider metadata is labeled interpretation metadata and never becomes scanner evidence.
- Keep the current bounded process executor and host authorization call sites. This ticket does not
  grant new effects or add a provider network client.

## Recon

- `AiProvider` currently has one `generate(&str, &str)` method. `ScanPlanner` and `AiAnalyst` build
  prompt text and parse normalized output outside the adapter.
- `ai::correlator` and `ai::remediation` return `(system, user)` prompt pairs, but no production
  provider service calls them. Their deterministic rule/walk behavior is already a safe fallback.
- Claude JSON-envelope normalization lives inside `CliAiProvider`. `response.rs` still contains a
  second legacy Claude parser, so normalization and typed decoding do not have one owner.
- Existing structured analysis types cover summary, prioritization, remediation, and filtering.
  Planning and engine attack-chain types are serializable. The missing pieces are typed inputs,
  task/version envelopes, provider methods, and shared adapter fixtures.
- CLI, MCP, and the autonomous runner already treat planning or analysis failure as non-fatal to
  deterministic scanning. Existing policy checks authorize `ExternalTool` before provider use.
- Baseline commit `9c6b4a2` contains the closed SK-029 job lifecycle and gives TICKET-004 an exact
  Git boundary.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/typed-ai-provider-contracts.spec.md`

## Log

- 2026-08-16: opened.
- 2026-08-16: repository owner directed SK-029 through SK-033 back to back and approved local
  per-ticket commits. No push, PR, remote target, or broad mutation run is authorized.
- 2026-08-17: the completed DIFF gate selected 84 SK-030 mutations across 29 functions/eight files,
  caught all 26 viable cases, rejected 58 as unviable, and had zero survivors (100% MSI). The owner
  had stopped repeat mutation scans and approved the local commit, so post-validation and
  post-archive delivery use the sealed zero-survivor baseline while mutation inputs remain exact.
