---
title: Typed and versioned AI provider contracts
pipeline_id: d9bf41e6-ed24-412e-84ef-846b4d1efcdc
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-004
ticket_doc: docs/planning/tickets/closed/TICKET-004-typed-ai-provider-contracts.md
aar: docs/planning/knowledge/aar/AAR-004-typed-ai-provider-contracts.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-004
created: 2026-08-16
---

# Typed and versioned AI provider contracts — spec

## Intent

Ship the stable reasoning boundary required by the Codex-first host work. A caller submits a typed,
versioned planning, analysis, correlation, or remediation request. The configured adapter renders
that contract for its CLI host, decodes only the matching typed response, and returns labeled
metadata. Provider failure never changes deterministic scan results, rule correlation, local
remediation, evidence, or authorization.

## Scope

- In: versioned task envelopes; typed request payloads; typed provider responses and errors; four
  provider operations; Codex/Claude transport normalization; migrated planner and analyst;
  provider-backed correlator and remediator with deterministic fallbacks; fixture and host tests;
  public documentation.
- Out: provider HTTP APIs, remote authentication, agent plugin packaging, typed MCP content, crate
  extraction, scanner/evidence schema changes, provider-created grants, broad mutation inventory,
  and non-loopback effects.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a reasoning caller invokes a provider, ScorchKit shall expose one of four typed task methods and no raw system/user method. | Trait fixture and source contract. |
| REQ-002 | When a typed task is rendered, ScorchKit shall include `scorchkit.ai/v1`, the exact task, typed input, and the required response envelope. | Four golden request/prompt fixtures. |
| REQ-003 | When output is decoded, ScorchKit shall reject missing, unsupported, or cross-task schema envelopes. | Decoder table tests. |
| REQ-004 | When Codex and Claude receive the same task, ScorchKit shall preserve an identical contract payload and typed result across both adapters. | Shared recording-executor suite. |
| REQ-005 | When planning or analysis succeeds, ScorchKit shall preserve validation, typed result variants, metadata, and evidence separation. | Planner, analyst, CLI, and MCP regressions. |
| REQ-006 | When AI correlation or remediation cannot return a valid typed result, ScorchKit shall return deterministic correlation or remediation output without changing scan success. | Success/failure/disabled service tests. |
| REQ-007 | When a provider process starts, ScorchKit shall preserve authorization-before-effects and its bounded, non-interactive provider invocation. | Policy negatives and invocation contracts. |
| REQ-008 | When the contract is published, ScorchKit shall document schema evolution and keep it independent of all host and storage layers. | Public serde fixtures and architecture review. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Use one required schema identifier, `scorchkit.ai/v1`, plus an exact task tag on request and response envelopes. | Version and task mismatches become observable rather than being parsed as the wrong payload. |
| 2 | Put contract types and rendering/decoding in `ai::contracts`; keep CLI process mechanics in `ai::provider`. | Domain schemas remain independent of Codex, Claude, CLI, MCP, and storage. |
| 3 | Give `AiProvider` four typed methods and remove `generate`. | Callers cannot bypass the reviewed task contract with ad hoc prompt strings. |
| 4 | Use the same contract renderer and decoder for Codex and Claude. | Shared fixtures can prove semantic equivalence while invocation flags remain adapter-specific. |
| 5 | Treat malformed, wrong-version, and wrong-task output as an error. | Typed success must mean the expected contract was actually returned. |
| 6 | Keep deterministic fallbacks in workflow services, not provider adapters. | Scan, correlation, and remediation behavior stays stable when AI is disabled or unavailable. |
| 7 | Preserve existing process limits and authorization call sites. | Typed reasoning adds no new effect or scope grant. |

## Owner-approved focused delivery scope

The repository owner directed that mutation runs must not be repeated after worktree-only delivery
changes and that reruns remain limited to repaired functions, with a repository-wide run deferred.
The completed SK-030 DIFF baseline selected 84 mutations in 29 functions across eight Rust files. It
caught all 26 viable mutations, reported 58 compiler-rejected mutations as unviable, and had zero
survivors. There is therefore no repaired-function recheck scope. The exact raw DIFF inventory and
outcomes are sealed under `.git/scorchkit-mutants-focused-ticket-004`; post-validation and
post-archive delivery may verify that evidence only while the mutation-input hash remains unchanged.
Any Rust, test, manifest, configuration, example, migration, or rule change requires a new scoped
mutation run.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-004-typed-ai-provider-contracts.md`
- AAR: `docs/planning/knowledge/aar/AAR-004-typed-ai-provider-contracts.md`
- Architecture: `docs/architecture/ai.md`, `docs/architecture/agent.md`, and
  `docs/architecture/vision.md`.

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
