---
title: Codex-first plugin and workflow skills — notes
pipeline_id: 18311993-f79a-4319-8eee-d8fb19da3ba9
---

# Codex-first plugin and workflow skills — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: authorize before effects; treat host instructions and project registration as
  context rather than grants; prove public execution modes at their real boundary; test process and
  protocol contracts semantically; use loopback for executing integration tests; preserve scanner
  evidence separately from provider interpretation; keep provider and host adapters outside domain
  contracts; and rerun mutation only for changed Rust functions when repairs require it.
- Recon: the server already exposes 30 local stdio tools with generated input schemas, JSON content,
  resources, prompts, fail-closed engagement checks, stateless durable jobs, and database-backed
  projects. `scan_job_start` is deliberately non-persistent and `project_scan` is the persisted
  path. Results remain JSON-in-text until SK-032. No Codex plugin exists in the repository; the only
  Codex skill is the development pipeline adapter.
- Plan: create `plugins/scorchkit` with one MCP descriptor and five phase skills; add a self-contained
  repository package checker to the existing metadata gate; validate with the official plugin and
  skill validators; exercise the existing duplex job and project MCP contracts on loopback; update
  architecture and operator docs; and deliver with a normal DIFF receipt.
- Operator confirmation: the owner directed SK-029 through SK-033 back to back and approved local
  per-ticket commits. This confirms TICKET-005 planning and delivery. No push, PR, plugin install,
  marketplace mutation, remote target, new effect, or broad mutation run is authorized.

## Phase 2 — Design

- Architecture: add a host-adapter package at `plugins/scorchkit`. Its manifest identifies
  ScorchKit `0.1.0` as an Ignibyte security plugin with interactive/read/write capabilities and
  points to `./skills/` and `./.mcp.json`. The MCP descriptor declares the installed `scorchkit`
  binary with `serve` over local stdio and names `DATABASE_URL` as an optional inherited variable;
  it does not set a working directory, allowing ScorchKit's normal workspace-local
  `scorchkit.toml` discovery, and stores no value or credential. No marketplace or app/UI manifest
  is included.
- MCP compatibility correction: extend `ProjectScanParams` with optional comma-separated `modules`
  and `skip` fields and apply them after `apply_profile`. This makes the server's documented
  `plan_scan` → `project_scan` sequence executable while retaining profile authorization and exact
  project target membership checks before scanning.
- Skill design: `prepare-security-engagement` owns project and target inventory but repeats that
  inventory is not authorization. `plan-security-engagement` uses target intelligence, module
  inventory, tool availability, and planning, then stops before execution. `run-security-engagement`
  uses the least-powerful sufficient profile, durable jobs for stateless work, and `project_scan`
  only when persisted project results are required. `report-security-findings` reads posture,
  findings, detailed evidence, and correlation before optional labeled AI analysis and never calls
  status mutation. `verify-security-remediation` captures the prior scan/finding baseline, rescans
  the same registered target only at user direction, compares evidence, and transitions to verified
  only when evidence supports the fix. Every skill stops when ScorchKit MCP is unavailable instead
  of improvising terminal commands.
- Contract design: each skill has only `name` and `description` frontmatter plus generated
  `agents/openai.yaml`. A repository-owned `bin/codex-plugin-contract.sh` validates JSON shape,
  exact skill inventory, frontmatter/folder identity, default prompts, required/forbidden tool
  ownership, safety invariants, no fenced command blocks, no raw CLI instructions, and no secret
  values. Its selftest copies the package to local temporary storage and proves altered MCP startup,
  missing skills, shell instructions, and unsafe reporting-state mutations fail. Gate 13 invokes
  the real package check so fast and delivery modes use the same contract without depending on the
  developer's installed Codex skills.
- File manifest: add `plugins/scorchkit/.codex-plugin/plugin.json`,
  `plugins/scorchkit/.mcp.json`, and `SKILL.md` plus `agents/openai.yaml` under each of the five skill
  directories; add `bin/codex-plugin-contract.sh`; update `bin/gate.sh`,
  `docs/architecture/agent.md`, `docs/architecture/mcp.md`, add
  `docs/guide/codex-plugin.md`, and update `README.md`, `CHANGELOG.md`, roadmap, and ticket/AAR
  artifacts; update `src/mcp/types.rs`, `src/mcp/tools.rs`, and focused `tests/mcp_tools.rs` coverage
  for project module selectors. Do not change Cargo manifests, storage schemas, migrations,
  policies, authorization, or MCP result types.
- Regression test plan: run the official plugin validator and skill quick validator against every
  packaged skill; run the package validator selftest and real contract; run the existing authorized
  loopback duplex MCP job test and the database-backed MCP project/finding suite; run the canonical
  fast gate; inspect the complete diff and adversarially test authorization wording, phase
  crossover, shell fallback, state mutation, secrets, manifest paths, and host-neutrality; then run
  one normal DIFF delivery gate scoped to the changed MCP functions. If it is green, seal that
  exact result and reuse it after archive only while mutation inputs remain identical. If a mutant
  survives, repair and rerun only its exact function. No broad or repeated mutation inventory is
  permitted.

## Phase 3 — Implement

- Files and behavior changed: added the repository-owned `plugins/scorchkit` package with a valid
  manifest, bounded local stdio MCP descriptor, and five phase-specific skills plus Codex UI
  metadata. Added `bin/codex-plugin-contract.sh` and wired its real and negative-fixture checks into
  metadata gate 13. Extended persisted project scans with optional include/skip module selectors,
  applied only after profile authorization, and returned the actual run/skipped module lists.
  Added database-backed selector, policy-denial, and transport-schema assertions. Updated operator,
  architecture, README, changelog, ticket, and AAR documentation.
- Focused evidence: the official plugin validator, all five official skill quick validators, the
  package contract selftest, the authorized duplex MCP transport test, all 63 database-backed MCP
  tool tests, and the canonical fast gate passed. The fast gate reported 14 passed, 0 failed, and 8
  deliberate fast-mode skips; it did not run mutation testing.
- Design deviations: recon proved the existing `plan_scan` output could recommend exact modules but
  `project_scan` could not accept them. The implementation therefore included the planned
  compatibility correction and, during self-review, added actual module outcome lists to the
  project-scan response so the execution and verification skills do not claim unavailable
  evidence.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Policy boundary | A registered project target must not become authorization for a persisted scan. | High | Verified `project_scan` resolves membership first and then enters `Engine::dast_context_for_target`; added a database-backed denial test proving a registered loopback target fails before I/O when no engagement exists. |
| 2 | Capability scope | Include selectors would broaden a profile if applied before `apply_profile`. | High | Verified profile filtering precedes include and exclude filtering; the focused test requests `cors` under `quick` and proves only the authorized `headers` module runs. |
| 3 | Workflow evidence | The execution workflow originally promised module outcomes absent from the immediate persisted-scan response. | Medium | Fixed by returning actual `modules_run` and runtime `modules_skipped` lists and asserting their JSON contract. Whole-scan failures remain errors rather than successful results. |
| 4 | Phase separation | The first static crossover expression rejected only wording shaped as “Call `<scan tool>`,” so equivalent “Use” wording could escape the validator. | Medium | Fixed by rejecting any scan-execution tool token in preparation/planning workflows and added a negative `Use project_scan` fixture. Reporting now rejects any status-tool reference in its workflow, independent of sentence shape. |
| 5 | Remediation truth | Absence after a skipped or profile-filtered reproducer could be misreported as verified. | High | The verification skill requires every reproducing module to appear in the completed set, a terminal follow-up scan, and unchanged stored finding identity/timestamps before status mutation. Missing, skipped, failed, and ambiguous outcomes remain unchanged. |
| 6 | Secret and startup boundary | Plugin metadata could embed credentials, change the working directory, or introduce an alternate command path. | High | Manifest/MCP validation permits only `scorchkit` + `serve`, named `DATABASE_URL` inheritance, no `env`, `cwd`, headers, marketplace, raw command workflow, or linked contract files. Negative fixtures prove alternate startup and raw-command fallback fail. |
| 7 | Host neutrality | A Codex package could leak into engine or crate dependencies. | Medium | Source/dependency inspection found no plugin or Codex package references in production crates; the package consumes only the existing MCP boundary. |

## Phase 4 — Validate

- Tests run (commands and outcomes): official plugin validation passed; all five official skill
  quick validations passed; package contract and its five negative-fixture classes passed; focused
  project-scan tests passed 3/3; the complete MCP suite passed 63/63; and the canonical gate passed
  all Rust, documentation, dependency, secret, shell, static-analysis, coverage, strict Nextest,
  PostgreSQL, CLI, and MCP contracts.
- Gate run and receipt: the normal DIFF gate passed 19 applicable lanes with zero failures and wrote
  the exact-worktree receipt. Line coverage was 79.54%. Nextest ran 1,433/1,433 cases with six
  reasoned live-network skips. DIFF mutation selected two mutations in
  `ScorchKitServer::do_project_scan`, caught both, and reported 100% MSI with zero missed,
  timeouts, or unviable cases. The raw result is sealed as
  `.git/scorchkit-mutants-focused-ticket-005` and verifies against mutation input
  `99fcdb045d3b2e4102c03f6a2d3172f8e0404e42a2e6ec1a8753eeebcb2c77cb`.
- Mutation-blind files: `src/mcp/types.rs` contains declarative request fields whose generated
  schema is asserted through a real duplex MCP client; `tests/mcp_tools.rs` is executable evidence.
- Documented skips with reasons: gates 17-19 are not applicable because ScorchKit has no browser UI,
  website dogfood render, or CSS asset pipeline. The six ignored cases require live third-party
  network access and retain their explicit reasons. No full or repeat mutation campaign ran.

## Phase 5 — Complete

- Docs updated: added the operator plugin guide; updated README, changelog, agent and MCP
  architecture, roadmap closed-work/evidence/debt ordering, ticket/spec, and durable knowledge
  index. Documentation identifies JSON-in-text and principal/annotation work as SK-032 rather than
  claiming it is already native structured MCP content.
- AAR submitted: `AAR-005-codex-first-plugin` is submitted at effectiveness 5 with two new
  prevention rules and two captured contract/test failures registered in the knowledge index.
- Archive: the pipeline-owned completion transition closed TICKET-005, rewrote its active links,
  moved the spec/notes pair, and left no active pipeline. The archived tree requires the approved
  focused-repair delivery proof before commit because archival changes the worktree receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The documented AI plan-to-persisted-scan path could not preserve recommended module scope. | `ProjectScanParams` exposed only project, target, and profile even though stateless scan tools already supported selectors. | Added optional `modules` and `skip`, applied after the profile filter, and covered persistence plus advertised schema. | Bind host workflow instructions to the concrete MCP request schema and an executing transport test. |
| 2 | The execution skill initially requested module outcome details that `project_scan` did not return directly. | Persistence stored module lists, but the immediate MCP response returned only counts and finding summary. | Return actual run/skipped lists and assert the response contract. | Review every skill output claim against the exact tool response, not only stored internal state. |
| 3 | Phase crossover validation depended on one imperative verb. | The first expression matched “Call” rather than the forbidden effect/tool itself. | Reject forbidden MCP tool tokens throughout each non-executing workflow and prove a differently worded negative fixture fails. | Static policy checks should recognize the protected semantic token independently of surrounding prose. |
