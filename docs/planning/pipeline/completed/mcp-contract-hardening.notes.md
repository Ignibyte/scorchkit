---
title: Typed MCP contracts and principal-aware tool boundaries — notes
pipeline_id: 3d9a79cb-9135-4523-80ed-d97895e77777
---

# Typed MCP contracts and principal-aware tool boundaries — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` keeps the engagement as the only
  authority; `PR-scorchkit-host-workflow-tool-contract-001` binds host claims to advertised schemas,
  immediate results, and an executing transport; `PR-scorchkit-semantic-token-policy-check-001`
  requires phase/effect classification independent of prose; `PR-scorchkit-exact-failure-source-001`
  requires authorization negatives to identify the selected denial; and
  `PR-scorchkit-green-baseline-reuse-001` prohibits reusing mutation evidence after relevant input
  changes.
- Recon changed the plan: locked `rmcp` 1.8 can generate structured output schemas, but its
  typed-JSON adapter serializes the new object into the compatibility text block. ScorchKit therefore
  needs a small local result adapter that preserves the exact prior text while adding the versioned
  structured envelope. Request `client_info` is self-asserted; it will be labeled as attribution,
  while the current local stdio process boundary supplies the principal kind. Every tool needs one
  central class contract so metadata, annotations, and result envelopes cannot drift independently.
- Operator confirmation: the owner directed SK-029 through SK-033 back to back and explicitly
  approved local commits. The owner also stopped repeat broad mutation scans after repair; SK-032
  will run one normal DIFF validation and only exact repaired-function follow-ups if required. No
  push, PR, remote target, remote transport, or broader effect is authorized.

## Phase 2 — Design

- Architecture: add `mcp::contract` as the transport adaptation layer. It owns a versioned
  object-root response envelope with success/error status, tool name, class, principal context,
  result or error, plus a custom `IntoCallToolResult` adapter. Successful content retains the exact
  pre-SK-032 text block while `structuredContent` carries the envelope; routed business failures
  retain caller-visible text, set `isError=true`, and carry the same structured envelope. A custom
  router-context extractor obtains the routed tool name and local request principal from rmcp's
  `RequestContext`; peer client name/version are labeled untrusted attribution. The extractor does
  not read or create engagement grants. One exhaustive `ToolContract` inventory owns the 30 names,
  read/local-state/external-effect class, strongest-behavior safety flags, and generated title. A
  router decorator fails startup/tests if the macro routes and inventory differ, then applies the
  shared output schema, full annotations, and custom class/version metadata to every route. All thin
  wrappers return only through the contract adapter; existing `do_*` methods remain unchanged.
- Class design: read tools only observe module/tool/job/project/finding/target/posture/progress
  state; local-state tools create/delete/update projects, targets, finding state, migrations,
  schedules, or cancellation state without starting new target work; external-effect tools may
  contact targets, launch provider/scanner processes, start/resume jobs, execute schedules, or scan
  local code with external tools. Composite tools take the strongest class. Destructive hints are
  conservative for any tool that can accept pentest/exploit work or delete/overwrite state;
  idempotence is true only when repeats cannot add another record or effect; open-world is true for
  target/provider/tool execution.
- Principal design: `kind=local_process` and a stable local subject identify the only supported
  transport boundary. Client implementation name/version are optional and `trusted=false`; a client
  calling itself an administrator remains untrusted attribution. Principal context is returned for
  traceability but never passed as an engagement or policy grant. Remote authenticated principal
  injection, missing-principal denial, and principal-to-engagement binding remain SK-037.
- Compatibility/error design: structured success stores the parsed JSON value when the legacy text
  is JSON and otherwise stores it as a string. Business errors escape terminal controls before both
  text and structured publication. Parameter-decoding failures remain rmcp protocol/tool argument
  errors because no safe typed call context exists until routing and decoding succeed.
- File manifest: add `src/mcp/contract.rs` and `tests/fixtures/mcp/tool-contract-v1.json`; update
  `src/mcp/mod.rs`, `src/mcp/server.rs`, `src/mcp/tools.rs`, `src/mcp/instructions.rs`,
  `tests/mcp_tools.rs`, the five Codex plugin skills where result-reading guidance applies,
  `docs/architecture/mcp.md`, `docs/architecture/agent.md`, `docs/guide/codex-plugin.md`, README,
  changelog, roadmap, ticket/spec/notes/AAR, and knowledge register. No dependency, migration,
  scanner, policy, storage, CLI, or provider changes are planned.
- Regression test plan: exact 30-name class/annotation fixture; shared output-schema snapshot and
  object-root assertion; router-inventory mismatch negatives; pure success/error adapter tests for
  JSON, plain text, control escaping, principal labeling, and legacy content; transport-independent
  contract-helper tests; duplex calls proving native structured success and no-engagement structured
  denial with a spoofed privileged client name; unchanged direct `do_*` serialization tests;
  representative read/state/effect calls; plugin contract; full MCP suite with PostgreSQL and
  loopback only; fast gate during implementation; one normal DIFF delivery gate, with only exact
  repaired-function mutation follow-ups if the baseline reports survivors.

## Phase 3 — Implement

- Files and behavior changed: added `src/mcp/contract.rs` with the versioned
  `scorchkit.mcp.tool-result/v1` envelope, local-process principal context, explicitly untrusted
  client attribution, exhaustive 30-tool behavior inventory, generated annotations and metadata,
  shared output schema, and a result adapter that preserves compatibility text. Routed MCP wrappers
  now pass their request context and adapt existing `do_*` results at the transport boundary. Added
  exact inventory/schema fixtures, unit and duplex integration coverage, spoofed-client denial
  coverage, plugin guidance/contract checks, and operator/architecture documentation.
- Design deviations: added `tests/fixtures/mcp/tool-output-schema-v1.json` beside the planned tool
  inventory fixture so the generated output schema is reviewed and pinned independently. Classified
  `correlate_findings` as read-only after source inspection confirmed that the existing
  implementation reads findings and computes rule correlations without persistence or provider
  execution. The planned direct router-call assertion was corrected to a direct result-adapter test
  plus a generated-router inventory/decorating test because rmcp intentionally keeps the peer
  constructor required by `ToolCallContext` private outside its crate; the duplex suite remains the
  real framed-routing proof. No business method, policy grant, storage schema, dependency, scanner,
  or provider behavior changed.
- Focused implementation evidence: `cargo check --all-targets --features mcp` passed; all 64 MCP
  integration tests passed with the local validation database; contract unit tests, wrapper lifecycle
  tests, duplex transport success, and spoofed attribution denial passed; the Codex plugin validator
  and negative selftest passed; strict all-target/all-feature Clippy passed; and the final fast gate
  passed all 14 applicable lanes with zero failures and no mutation run.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness and API-contract critic | The design said “direct router invocation,” but the test only decorated/listed routes; constructing a valid direct call would require rmcp's private `Peer::new`. | Low | Accepted. Corrected the requirement to the observable boundary, added a direct `IntoCallToolResult` success test that pins legacy text and native fields, retained direct generated-router inventory/mismatch coverage, and retained duplex framing for real request context. Focused test passed. |
| 2 | Security and abuse-case critic | Caller name/version are attacker-controlled attribution and could be mistaken for authorization if passed into engine policy. | High if present | Verified absent. `McpPrincipalContext::local` labels the values `trusted=false`; the context flows only into the response envelope, never `AppConfig`, `Engagement`, target scope, capability, or effect checks. The duplex client named `local-administrator` still receives the exact no-engagement denial. No change required. |
| 3 | Data-integrity and compatibility critic | Adding native output could double-serialize JSON, drop old text, or permit both success result and error simultaneously. | Medium if present | Verified absent. The adapter preserves the owned legacy text, parses only the separate semantic copy, and constructs exclusive success/error envelopes; schema and exact-content tests cover both boundaries. No change required. |
| 4 | Simplification and architecture critic | Moving class flags back into 30 wrapper attributes would remove the router decorator but duplicate the contract used by result envelopes. | Medium regression risk | Rejected. One exhaustive inventory is the smaller source of truth and fails closed when route count or names drift. Thin wrappers retain generated input schemas and unchanged `do_*` behavior. No change required. |

## Phase 4 — Validate

- Tests run (commands and outcomes): the focused contract suite passed 5/5; the full MCP integration
  suite passed 64/64 against the local validation database; strict all-target/all-feature Clippy
  passed; plugin validation and its negative selftest passed; all-feature tests, nextest, PostgreSQL
  integration, CLI/MCP contracts, coverage, dependency policy, secret scanning, ShellCheck, Semgrep,
  Rustdoc, formatting, and source-policy lanes passed. Only local loopback, duplex, process, and
  database fixtures ran; no public or third-party target was scanned.
- Mutation validation: the one approved DIFF batch completed 54 selected mutations in eight minutes:
  11 caught, two missed, 41 unviable. Both survivors were return-value substitutions in the pure
  `tool_title` helper. Added the exact `scan_job_start` → `Scan Job Start` assertion and ran only
  those two named mutations; both were caught. Sealed evidence at
  `.git/scorchkit-mutants-focused-ticket-006` preserves the broad raw outcomes, exact recheck, and
  pre-repair `src/mcp/contract.rs` snapshot. The verifier reconstructs 13/13 viable caught, zero
  misses, 100% MSI, and binds mutation input
  `d106fad814f71a18e9965f4399cb0af1b009e17adb4a361805af717d87df2044`.
- Gate run and receipt: `bash bin/gate.sh --focused-repair` passed 19 applicable lanes with zero
  failures, verified the focused seal without launching cargo-mutants, and wrote
  `.git/scorchkit-gate-receipt` for the exact validation worktree.
- Documented skips with reasons: gates 17–19 are not applicable because ScorchKit has no browser UI,
  website dogfood surface, or CSS asset pipeline. The full repository mutation campaign remains
  scheduled work by owner direction; no broad mutation rerun was performed after the repair.

## Phase 5 — Complete

- Docs updated: README, changelog, MCP and agent architecture, Codex plugin guide, server
  instructions, all five packaged workflow skills, roadmap closed-work/evidence/debt ordering,
  ticket/spec/notes, and the durable knowledge register now describe the shipped native result,
  behavior-class, annotation, principal, and compatibility boundaries. Remote authenticated
  principal binding remains explicitly deferred to SK-037; workspace extraction is next as SK-033.
- AAR submitted: `AAR-006-mcp-contract-hardening` is submitted at effectiveness 5 with three new
  prevention rules and two captured verification/test gaps registered in the knowledge index.
- Archive: the pipeline-owned completion transition closed TICKET-006, rewrote its active links,
  moved the spec/notes pair, and left no active pipeline. The archived worktree now requires the
  approved focused-repair delivery proof before the local commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Strict Clippy rejected eight new contract-layer expressions and one integration-test default. | The first implementation was checked with compilation and focused tests before the repository's stricter lint profile. | Replaced the panic-prone metadata conversion, derived the complete equality contract, removed unnecessary instance coupling/clones, corrected Rustdoc markup, and named the default type. | Run the strict all-target/all-feature lint command before the first fast gate for new transport adapters. |
| 2 | The first fast gate failed the schema snapshot and ShellCheck. | A lint-driven Rustdoc correction intentionally changed generated schema text, while literal Markdown backticks in a shell search triggered `SC2016`. | Updated the reviewed schema fixture and used escaped backticks in double-quoted shell patterns; reran only the affected snapshot and shell check before the fast gate. | Treat generated documentation as schema input and run the changed shell script through ShellCheck before the repository gate. |
| 3 | The first post-inspection fast gate failed only Rustfmt on the new direct-adapter assertion. | The focused test was run after the edit, but formatting was checked before rather than after that final patch. | Applied the repository formatter and reran the non-mutation fast gate: 14 passed, zero failed. | Format after the final source patch, immediately before the gate. |
| 4 | The DIFF mutation lane found two surviving substitutions in `tool_title`, leaving the viable score at 84.61%. | Router tests asserted annotations and schema but not the generated human-readable title. | Added one exact compound-name title assertion and reran only the two `tool_title` mutations; both were caught and cumulative focused evidence verifies 100% MSI. | Pin generated presentation metadata as well as semantic flags when one helper owns both. |
