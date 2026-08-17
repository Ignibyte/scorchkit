---
title: Typed and versioned AI provider contracts — notes
pipeline_id: d9bf41e6-ed24-412e-84ef-846b4d1efcdc
---

# Typed and versioned AI provider contracts — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: authorize provider processes before effects; assert provider behavior through
  complete process contracts; distinguish exact contract failures; enforce task invariants in every
  provider implementation; and remove the raw prompt method called out in the architecture debt.
- Recon: only planning and analysis call `AiProvider::generate`; both own prompt construction and
  response parsing. Correlation and remediation expose raw prompt pairs without a provider-owned
  operation. Claude normalization has two owners. Existing engine attack-chain, scan-plan, and
  analysis types are serializable, and all host call sites already keep AI failure separate from
  deterministic scan success.
- Plan: add `ai::contracts` with `scorchkit.ai/v1` request/response envelopes and four typed tasks;
  replace `generate` with typed methods; give Codex and Claude the same rendering/decoding path;
  migrate planning and analysis; connect correlation and remediation through fallback-owning
  services; then prove provider equivalence with shared fixtures and existing host regressions.
- Operator confirmation: the owner directed SK-029 through SK-033 back to back and approved local
  commits. This confirms TICKET-004 planning and delivery. No push, PR, remote target, provider
  network API, or broad mutation run is authorized.

## Phase 2 — Design

- Architecture: add `ai::contracts` as the provider-neutral boundary. It defines
  `AI_CONTRACT_SCHEMA = "scorchkit.ai/v1"`, an `AiTask` discriminator, typed request DTOs for plan,
  analysis, correlation, and remediation, generic versioned request/response envelopes, typed
  provider metadata, and exact decode errors. Requests use compact finding, module, scan-summary,
  and project-context values rather than prompt strings. The contract renderer serializes one
  request envelope and names the required response envelope. `AiProvider` exposes four concrete
  async methods. `CliAiProvider` owns shared rendering/decoding and delegates only process argument
  construction and outer-envelope normalization by provider kind. `NoOpProvider` returns a typed
  disabled error from every operation.
- Workflow design: `ScanPlanner` constructs `PlanRequest` and consumes a typed `ScanPlan` before its
  existing registered-module validation. `AiAnalyst` constructs `AnalysisRequest`; summary,
  prioritize, and filter call `analyze`, while remediate calls the distinct typed `remediate`
  operation and maps it into the existing analysis wrapper. `AiCorrelator` merges typed provider
  chains with rule chains by name and returns rule output on disabled, unavailable, or invalid AI.
  `AiRemediator` returns typed provider guidance when valid and a labeled deterministic risk-ordered
  walk otherwise. Provider output remains interpretation and never mutates findings or evidence.
- Error and compatibility design: a response must contain the exact schema and task before payload
  deserialization succeeds. Missing, future, and cross-task envelopes are different typed errors.
  Codex raw stdout and Claude's outer JSON result are normalized once, then passed to the same
  decoder. Planning and analysis host behavior remains non-fatal to scan success. Existing pure
  deterministic correlation and remediation builders remain available, but raw provider prompt
  builders and the raw provider generation method are removed.
- File manifest: add `src/ai/contracts.rs` and `tests/ai_provider_contracts.rs`; update
  `src/ai/mod.rs`, `src/ai/provider.rs`, `src/ai/planner.rs`, `src/ai/analyst.rs`,
  `src/ai/correlator.rs`, `src/ai/remediation.rs`, `src/ai/prompts.rs`, `src/ai/response.rs`, and
  `src/ai/types.rs`; update AI, agent, and vision architecture docs, README, roadmap, changelog,
  public AI serde tests, and linked ticket artifacts. Do not change MCP result schemas, provider
  network behavior, engine policy, scanner findings, storage, or job execution.
- Regression test plan: serde round trips for every request and response envelope; exact schema/task
  decoder matrix; focus/payload mismatch rejection; full four-task recording-executor suites for
  Codex and Claude using the same typed fixtures; exact CLI argument and normalized metadata checks;
  disabled and unavailable provider errors; planner module allow-list filtering; analyst focus
  dispatch; correlation merge/dedup/fallback; remediation provider/deterministic fallback; existing
  autonomous runner, CLI, MCP, response parsing, and evidence-separation tests; fast gate during
  development and one DIFF gate for validation. Mutation reruns, if repair is needed, remain limited
  to exact repaired functions under the owner's standing direction.

## Phase 3 — Implement

- Files and behavior changed: added the provider-neutral `ai::contracts` boundary with versioned
  request/response envelopes, four typed tasks, compact request DTOs, typed metadata, and exact
  decode errors. Replaced the raw provider generation method with plan, analyze, correlate, and
  remediate methods. Codex and Claude now share contract rendering and decoding while retaining
  their bounded provider-specific process arguments. Migrated planner and analyst callers, wired
  provider augmentation into correlation and remediation, and preserved deterministic fallbacks.
  Removed the duplicate legacy Claude and raw analysis/plan parsers. Added public contract,
  provider-parity, cross-task rejection, fallback, dispatch, and evidence-separation tests. Updated
  the AI, agent, and vision architecture docs, README, and changelog.
- Design deviations: `src/ai/types.rs` required no schema change because its existing result types
  already satisfy the typed response boundary. Raw JSON extraction remains a small helper in
  `response.rs`, while all version and task validation moved to `contracts.rs`. The provider now
  checks configured binary availability before invoking its executor, making the existing
  unavailable state fail before effects. Planning additionally rejects a typed plan whose target
  does not equal the requested target; this tightens the intended task invariant without changing
  successful behavior.
- Development evidence: the focused AI unit and integration suites passed, strict all-target
  all-feature Clippy passed, and `bash bin/gate.sh --fast` passed 14 gates with no failures. The
  first fast run exposed only one rustfmt difference introduced by a late test assertion; formatting
  was corrected and the complete fast gate rerun passed. No mutation scan ran in fast mode.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Contract boundary | The built-in CLI adapter validated schema, task, plan target, and analysis focus, but a third-party `AiProvider` implementation could construct a mismatched public `AiProviderResponse` that planner, analyst, correlator, or remediator consumed directly. | high | Fixed. Added reusable envelope validation at every workflow consumption boundary, repeated request-bound plan-target and analysis-focus validation outside the built-in adapter, and added external-provider bypass regressions. Correlation and remediation treat invalid external envelopes as provider failure and return their deterministic fallback. |
| 2 | Prompt and parser abuse | Finding fields can contain instructions or JSON-like text, and provider output may be direct, fenced, or prefixed. | medium | Accepted with evidence. Request data is serialized as JSON under a typed `input`, the system contract labels every field untrusted and forbids effects, extraction is followed by exact schema/task/payload decoding, and terminal presentation escapes control characters. Scanner evidence is copied into reasoning input but never replaced by provider output. |
| 3 | Adapter parity and effects | Codex and Claude use different process transports, creating risk of semantic drift or an effect before host authorization. | high | Verified. Both adapters use the same renderer/decoder and shared four-task fixtures; only invocation and Claude outer-envelope normalization differ. Existing CLI, MCP, and autonomous-host call sites authorize `ExternalTool` before planner or analyst execution, and the built-in adapter remains crate-private. |
| 4 | Failure behavior | Disabled, unavailable, malformed, or cross-task AI output could accidentally suppress deterministic results. | high | Verified. Planning and analysis remain non-fatal at hosts. Correlation always computes rules first, and remediation builds the local risk walk on every unavailable or rejected provider path. Focused success/failure/disabled/wrong-envelope tests pass. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused AI tests passed 39/39; public provider contracts passed
  4/4; scan-plan contracts passed 12/12; strict all-target/all-feature Clippy passed. The normal
  `bash bin/gate.sh --diff` run passed every applicable test, documentation, dependency, secret,
  policy, coverage, Nextest, PostgreSQL, CLI, and MCP lane.
- Gate run and receipt: DIFF passed 19 gates with zero failures and three named web-only skips. Line
  coverage was 79.63%. The scoped mutation lane selected 84 mutations in 29 functions across eight
  files: 26 caught, 58 unviable, zero missed/timeouts, and 100% MSI. Nextest executed 1,432 cases;
  PostgreSQL ran 62 MCP, 11 storage, and 8 storage-integration cases; CLI/MCP contracts ran 21 CLI,
  2 code-scan, 62 MCP, and 12 scan-plan cases. The receipt was written in DIFF mode.
- Mutation delivery evidence: because the completed DIFF has zero survivors, there are no repaired
  functions to rerun. The raw inventory and outcomes are sealed as
  `.git/scorchkit-mutants-focused-ticket-004`, with a verifier that recomputes every count, list,
  score, inventory identity, and the exact mutation-input hash. The owner explicitly stopped repeat
  mutation scans and approved the local commit. The focused delivery gate may reuse this evidence
  only while mutation inputs are unchanged; any Rust/test mutation input change revokes it.
- Documented skips with reasons: gates 17–19 are the repository's named web-only skips because
  ScorchKit has no web UI, website dogfood renderer, or CSS asset pipeline. The four all-feature
  ignored cases and six Nextest skips are existing reasoned live-network tests, not delivery proof.

## Phase 5 — Complete

- Docs updated: AI, agent, and vision architecture; README; roadmap; changelog; Constitution §19;
  sealed mutation-baseline verifier and gate selftest; ticket/spec/notes; knowledge register; and
  this AAR.
- AAR submitted: `AAR-004-typed-ai-provider-contracts`, 2026-08-17, effectiveness 5.
- Archive: `bash bin/pipeline.sh pass complete` closes TICKET-004, removes it from the open queue,
  moves the spec/notes pair to `docs/planning/pipeline/completed`, and rewrites cross-links. Delivery
  then reruns `bash bin/gate.sh --focused-repair` against the validation database; gate 16 verifies
  the sealed zero-survivor DIFF evidence without launching cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first fast gate failed rustfmt on one assertion. | A focused provider test was added after the preceding format pass. | Ran the formatter and reran the complete fast gate green. | Format after the final test edit before phase exit. |
| 2 | External `AiProvider` implementations could bypass schema/task and request-bound checks. | Validation lived only inside the crate-private Codex/Claude adapter. | Revalidated every public response at workflow consumption boundaries and added wrong-envelope/focus regressions. | Treat public provider implementations as adversarial even when built-in adapters already validate. |
| 3 | The focused verifier could not represent a completed green baseline with zero survivors. | Its schema required a nonempty survivor repair and recheck, even when no repair existed. | Added a sealed-green-DIFF verifier that accepts only zero misses, recomputes raw outcomes, and binds unchanged mutation inputs. | Never rerun a green mutation inventory solely to prove that its empty survivor set is still empty. |
