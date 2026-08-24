---
title: Typed run preprocessors and lifecycle hooks — notes
pipeline_id: be2067dc-2f84-4c5e-ace6-eab4baf91f3b
---

# Typed run preprocessors and lifecycle hooks — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` keeps processor declarations and
  proposals from becoming authority; `PR-scorchkit-cancellation-whole-lifecycle-001` keeps adjacent
  processors inside scan cancellation; `PR-scorchkit-public-evidence-revalidation-001` and
  `PR-scorchkit-projection-validate-canonical-001` require redaction/validation at every public
  outcome boundary; `PR-scorchkit-durable-worker-foreground-separation-001` keeps notification
  delivery outside scan completion; `PR-scorchkit-transition-audit-reconstruction-001` requires
  independently meaningful processor outcomes; `PR-scorchkit-extension-persistence-boundary-001`
  keeps processors proposal-only; and `PR-scorchkit-bounded-validator-mutation-table-001` requires
  exact version, count, byte, time, identity, subset, and compound-boundary tests.
- Comparable work: TICKET-002 established cancellation around hooks and the shared owned executor;
  TICKET-010 established immutable scanner evidence plus labeled derived analysis; TICKET-015
  established append-meaningful dispositions; TICKET-021 established durable notification handoff;
  and TICKET-028 established versioned untrusted extension envelopes and bounded validation.
- Recon: current local hooks are DAST/code-only, use one global timeout/failure flag, chain arbitrary
  JSON, ignore pre/post-scan changes, and can destructively replace post-module findings. The event
  bus already distinguishes lossy broadcast from awaited durable sinks. `ScanResult` is the shared
  public result boundary but has no processor outcomes.
- Operator confirmation: the owner's standing 2026-08-23 direction is to continue the next roughly
  five roadmap tickets and use DIFF, never full, mutation validation. That confirms promotion of
  SK-051 and this plan's delivery mode.

## Phase 2 — Design

- Architecture: lower provider-neutral run-pipeline contracts validate versioned envelopes and
  proposals against host-built authority ceilings; config owns explicit local processors plus
  legacy adapters; root `HookRunner` owns deterministic bounded process execution; DAST/code runners
  apply only safe preprocessing narrowing, preserve original findings, collect outcomes in
  `ScanResult`, and publish typed events. Notification remains durable enqueue through the existing
  event sink with delivery outside scan completion.
- File manifest: add core/config run-pipeline modules; extend their library exports, `ScanResult`,
  `ScanEvent`, and `AppConfig`; rewrite the root hook adapter; add narrow DAST/code context authority
  helpers; integrate both existing hook-enabled runners; update exhaustive event consumers, result
  fixtures/projections, tests, and public/architecture/security/planning documentation.
- Regression test plan: exact contract/version/identity/schema/order/budget and authority-clamp truth
  tables; explicit/legacy configuration compatibility; typed request/response and required/optional
  adapter failures; cancellation/timeout/overflow cleanup; DAST/code module narrowing and immutable
  findings; bounded public outcomes; durable notification handoff and no foreground sender; fast
  development gate followed by DIFF-only validation and delivery.
- Operator confirmation: the owner's standing instruction to continue the next roughly five tickets
  with DIFF rather than full mutations confirms this design and file scope.

## Phase 3 — Implement

- Files and behavior changed: added provider-neutral run phase, processor contract, authority,
  typed input/proposal/response/outcome, validation, normalization, redaction, and hard-bound types
  in `scorchkit-core`; added complete explicit processor configuration and legacy compatibility
  validation in `scorchkit-config`; rewrote the root hook runner as a deterministic typed adapter;
  integrated preprocessing, immutable finding proposals, reporting, outcome collection, and event
  publication in the standard DAST and code runners; preserved outcomes across result serialization
  and merge; added the typed audit/webhook event boundary; and updated public architecture,
  configuration, security, README, and changelog documentation.
- Behavioral evidence: preprocessing target/module/capability/effect/credential proposals are
  clamped to host-built authority and incompatible modules are removed before execution; explicit
  responses must match their registered schema, identity, phase, proposal kind, source identities,
  and bounds; original findings survive legacy filter output unchanged; required failures abort and
  optional failures record only redacted degraded outcomes; DAST processor events reach the awaited
  durable sink while code retains its established best-effort event behavior.
- Test evidence: focused core/config/adapter/DAST/code tests passed; strict all-feature/all-target
  Clippy passed; `bash bin/gate.sh --fast` passed 14/14 applicable lanes with mutation explicitly
  skipped by fast mode.
- Design deviations: none. Legacy checkpoint and explicit phased DAST remain outside the existing
  hook-enabled path, as do infra/cloud families, matching the ticket's scope exclusion.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Secret boundary | Executor failures could echo raw stderr or executable paths into diagnostics. | High | Fixed: collapse execution/decoding failures to typed generic diagnostics, redact before error/event projection, and test optional plus required secret-bearing failures. |
| 2 | Authorization | Preprocessing narrowing filtered modules but later phases rebuilt the original capability/effect/credential ceiling. | High | Fixed: persist the accepted authority through enrichment/reporting; integration test proves a removed capability rejects the later processor without invocation. |
| 3 | Provenance | The enrichment outcome event was durably published before its source finding event. | Medium | Fixed: publish normalized source findings first and assert durable source-before-proposal order. |
| 4 | Notification | The new event had a webhook mapping but was absent from the configuration allowlist. | Medium | Fixed: add `pipeline_processor_outcome` to the exact supported-kind set and its count contract. |
| 5 | Proposal integrity | Finding proposals admitted self-relations, semantically empty shapes, and conflicting terminal proposals. | Medium | Fixed: add per-kind, cross-proposal, identity, annotation, and relation validation with truth-table tests. |
| 6 | Arithmetic boundary | Report severity-count validation used an unchecked sum. | Medium | Fixed: use checked addition and reject overflow; add an overflow regression. |
| 7 | Public projection | An accepted preprocessing outcome could retain the redundant policy target, including credential-bearing URL material. | Medium | Fixed: reject embedded web credentials, clear the target before outcome publication, and reject it during public normalization. |
| 8 | Failure semantics | Optional invalid proposals were labeled degraded, leaving the rejected disposition unreachable. | Medium | Fixed: classify execution failures as degraded and invalid typed/legacy proposals as rejected; assert both paths. |
| 9 | Legacy compatibility | An irrelevant legacy pre-scan JSON object was recorded as an applied proposal. | Low | Fixed: adapt output without a target or modules field to passthrough/no-change. |
| 10 | Validation coverage | Aggregate configuration boundaries lacked a direct matrix for total count, timeout endpoints, empty paths, and duplicate ID/order. | Low | Fixed: add exact accepted/rejected aggregate configuration tests. |
| 11 | Maintainability | Inspection repairs pushed one adapter method past the line limit and held test mutex guards longer than necessary. | Low | Fixed: extract the accepted-state update helper and drop guards immediately after snapshots; strict Clippy passes. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused core/config/adapter/DAST/code tests passed; strict
  all-feature/all-target Clippy passed; post-inspection `bash bin/gate.sh --fast` passed 14/14 lanes
  with mutation explicitly skipped; `bash bin/mutants.sh --inspect` inventoried 11,178 configured
  targets without compiling mutants.
- Gate run and receipt: the one completed `bash bin/gate.sh --diff` passed all 18 applicable
  non-mutation lanes and selected 374 changed-code mutants: 161 caught, 114 missed, 99 unviable,
  58.54% initial viable MSI. Raw outcomes are preserved under
  `.git/scorchkit-mutants-focused-ticket-029/initial`.
- Owner-approved focused repair: repair and recheck all and only those 114 named survivors in 28
  verifier-distinct functions across eight files, preserving pre-repair snapshots and using
  `bash bin/gate.sh --focused-repair`; do not repeat the broad DIFF or run FULL.
- Survivor outcome: the first exact-name pass caught 111/114 and isolated three residual boolean
  boundaries. Direct valid-arm assertions killed those three in a three-name follow-up. Sealed
  evidence reconstructs 275/275 viable outcomes at 100% MSI with 99 compiler-unviable mutations,
  mutation-input hash `9f2b8154ea2d804629f76faa58a513f5c5aa445d80ac10a900ba8e9ea3104f6a`,
  and evidence digest `9d99c058b6d5d71e87fa050f644283116dc57832d7b701b3952c4ad1390b382b`.
- Documented skips with reasons: browser, website-render, and CSS lanes are repository-defined
  inapplicable skips. The first DIFF attempt used stale container password metadata and stopped at
  ordinary tests before mutation; an authenticated PostgreSQL query established the retained
  disposable database password, and the completed run then passed every database-sensitive lane.

## Phase 5 — Complete

- Docs updated: README, SECURITY, changelog, run-pipeline/configuration/executor/runner/hook
  architecture, roadmap completion state, ticket evidence, and the reusable knowledge register.
- AAR submitted: `AAR-029-typed-run-pipeline`, submitted 2026-08-24 with effectiveness 4/5 and
  three failure patterns plus three prevention rules registered.
- Archive: TICKET-029 closes on 2026-08-24 and the spec/notes move through the repository pipeline's
  atomic archive transition. Delivery reruns the same focused-repair gate because archive changes
  the worktree; gate 16 verifies sealed evidence and launches no cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Narrowed authority did not survive the full lifecycle. | The initial integration recomputed phase authority from the scan context. | Carry one mutable sealed ceiling through all phases. | Test a preprocessing capability removal against a later processor and assert no invocation. |
| 2 | Failure text could contain processor-controlled bytes. | Adapter errors reused executor and decoder detail in public outcomes. | Replace untrusted details with generic typed categories and redact at the final boundary. | Keep secret-bearing failure fixtures for both optional and required modes. |
| 3 | Durable proposal provenance preceded its source record. | Outcome publication happened inside enrichment before the runner emitted findings. | Emit normalized findings before invoking/publishing enrichment. | Assert exact durable source-before-derived order. |
| 4 | The first validation attempt failed 14 database-sensitive tests before mutation. | The long-lived disposable container retained its initialized password while its current environment metadata advertised a different value. | Verify credentials with an authenticated query and rerun with the actual disposable database URL. | Treat readiness probes as reachability only; authenticate before starting a delivery gate. |
| 5 | The completed DIFF mutation lane found 114 survivors after all functional lanes passed. | Representative tests did not pin every exact constant, compound predicate, typed phase arm, and collection boundary in the new contract. | Preserve the completed inventory, add direct truth tables/integration assertions, and recheck only the 114 names. | Write exact max/one-over and independent compound-operand matrices before mutation validation. |
| 6 | Three names survived the first exact 114-name recheck. | Error-only fixtures did not prove the complementary valid arms for legacy deduplication, test-default authority, and credential-use consistency. | Added one direct valid assertion for each branch and caught all three in an exact three-name follow-up. | Every negated guard needs both its rejecting and accepting truth-table arms. |
| 7 | The first focused gate found two default-feature redundant clones after all-feature Clippy had passed. | The feature matrix made ownership analysis differ between the two Clippy configurations. | Replaced the test-only clones with moves, ran strict default and all-feature Clippy, and resealed the same exact three-mutant final-tree scope at 3/3 caught. | Run both default and all-feature strict Clippy before the final mutation-input seal. |
