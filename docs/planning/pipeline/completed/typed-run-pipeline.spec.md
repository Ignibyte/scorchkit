---
title: Typed run preprocessors and lifecycle hooks
pipeline_id: be2067dc-2f84-4c5e-ace6-eab4baf91f3b
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-029
ticket_doc: docs/planning/tickets/closed/TICKET-029-typed-run-pipeline.md
aar: docs/planning/knowledge/aar/AAR-029-typed-run-pipeline.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-029
created: 2026-08-23
---

# Typed run preprocessors and lifecycle hooks — spec

## Intent

Ship a provider-neutral typed run-pipeline contract and root-owned local processor adapter that
turn today's arbitrary lifecycle JSON into validated, bounded proposals and explicit outcomes.
Integrate it with the DAST and code runners, preserve original findings, expose pipeline outcomes in
normal scan results, and route notification through the existing durable event seam.

## Scope

- In: typed phase/contract/envelope/proposal/outcome records; explicit processor configuration and
  legacy hook adaptation; deterministic DAST/code integration; authority clamping; immutable
  scanner evidence; cancellation/resource budgets; durable notification events; public projections.
- Out: a parallel event system; ambient effects or storage handles; extension distribution; model
  execution; triage persistence; new hook support in infra/cloud; synchronous notification effects.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a processor registers for a lifecycle phase, ScorchKit shall require a versioned contract with unique identity, typed input/output schemas, declared capabilities, deterministic order, failure mode, and nonzero bounded input, output, and wall-time budgets. | Contract/schema snapshots plus invalid identity, duplicate order, phase/schema, capability, and exact-budget tests. |
| REQ-002 | When preprocessing proposes a target, module, capability, credential-use, or effect change, ScorchKit shall validate the complete proposal against a host-built authorization ceiling and shall reject any target change or authority expansion before module execution. | Exact target, module subset, capability subset, credential, and effect-clamp matrix with recording executor negatives. |
| REQ-003 | When post-module processing filters, deduplicates, enriches, correlates, or annotates findings, ScorchKit shall retain the original normalized scanner findings and record the proposal and its disposition separately with processor and source-finding identity. | Original-finding immutability, derived-record provenance, redaction, and stable ordering tests in DAST and code runners. |
| REQ-004 | When a required policy or integrity processor fails, ScorchKit shall fail closed; when an optional enrichment or reporting processor fails, ScorchKit shall retain a redacted degraded outcome and continue without applying its proposal. | Required/optional malformed output, nonzero exit, timeout, overflow, and later-processor ordering matrix. |
| REQ-005 | When cancellation, timeout, or output overflow occurs during a local processor, ScorchKit shall stop its owned process through the shared executor and shall not publish a successful processor or scan phase. | Cancellation and bounded process-tree fixtures plus terminal-event assertions. |
| REQ-006 | When notification work is requested, ScorchKit shall publish a typed redacted lifecycle event through the existing awaited durable-event seam and shall not execute remote notification work inside scan completion. | Recording durable sink, queue handoff, scan-independence, and no-direct-network source contracts. |
| REQ-007 | When legacy pre-scan, post-module, or post-scan scripts remain configured, ScorchKit shall adapt them into deterministic typed compatibility processors without treating arbitrary JSON as authority or deleting scanner evidence. | Legacy configuration/default fixtures and compatibility execution tests. |
| REQ-008 | When run-pipeline outcomes cross ScanResult, report, control, MCP, or durable job boundaries, ScorchKit shall expose bounded provider-neutral records with redacted diagnostics and no credential values, executable output, policy objects, or storage handles. | Serialization, public projection, report, control/MCP, job progress, and secret-redaction contracts. |
| REQ-009 | When mutation validation repairs TICKET-029, ScorchKit shall preserve the completed 374-mutant DIFF baseline and recheck all and only its 114 named survivors in 28 verifier-distinct functions across eight files. | Sealed initial outcomes, eight pre-repair snapshots, exact-name inventory/recheck, reconstructed MSI, and focused-repair receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Put lifecycle contracts in `scorchkit-core`; keep local-process execution and host policy assembly in the root crate. | Provider-neutral consumers need stable types without access to composition or effects. |
| 2 | Define the canonical phase order as intake validation, preprocessing, plan proposal, authorization, execution, normalization, enrichment, correlation, analysis attachment, reporting, and notification. | Later extensions/models/triage need one lifecycle vocabulary rather than new parallel hooks. |
| 3 | Model processor output as proposals plus dispositions; never permit in-place replacement of source findings. | Scanner evidence and derived decisions have different trust and provenance. |
| 4 | Build a bounded `RunAuthority` from the already policy-sealed host context and validate every preprocessing field against it. | Processor declarations and outputs cannot become grants. |
| 5 | Keep local processor execution sequential by `(phase, order, id)` and use the shared owned process executor with cancellation. | Determinism and whole-tree cleanup already have a proven seam. |
| 6 | Adapt legacy hook lists to fixed typed contracts; preserve invocation order but treat their output as untrusted proposals. | Existing configuration remains readable without preserving destructive evidence replacement. |
| 7 | Represent notification as durable event publication only; reject a local processor registered for the notification phase. | Remote notification delivery must stay outside foreground scan completion. |
| 8 | Add bounded pipeline outcomes to `ScanResult` and its existing projections rather than create separate storage or transport APIs. | One canonical result continues feeding report, control, MCP, and jobs. |
| 9 | Preserve the one completed DIFF inventory, repair its 114 survivors, and use the approved focused-repair path without repeating the broad selection. | This implements the owner's explicit direction to squash survivors only and avoid another long mutation run. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-029-typed-run-pipeline.md`
- AAR: `docs/planning/knowledge/aar/AAR-029-typed-run-pipeline.md`
- Architecture: `docs/architecture/hooks.md`, `docs/architecture/runner.md`,
  `docs/architecture/executor.md`, `docs/architecture/extensions.md`

## Design

### Architecture

1. `scorchkit-core` owns the serializable lifecycle vocabulary: phase, schema/version constants,
   processor contract, budgets, authority ceiling, typed inputs/proposals, disposition, and bounded
   public outcome. Validation has no access to CLI, MCP, storage, process, or agent providers.
2. `scorchkit-config` owns explicit local-processor configuration. Loading validates scalar bounds,
   known schema/phase combinations, unique IDs, and unique `(phase, order)` slots. Existing hook
   lists compile into fixed `legacy.*` processor contracts after explicit processors.
3. Root `HookRunner` becomes the local processor adapter. It sorts by `(phase, order, id)`, encodes a
   versioned request, invokes one canonical executable with an exact timeout and stream ceiling,
   decodes exactly one bounded response, validates it against the registered contract and host
   authority, redacts diagnostics, and returns outcome records. It never receives a store or raw
   engagement handle.
4. DAST and code orchestrators build phase inputs from already selected targets/modules/findings.
   Preprocessing may only narrow runnable modules and declared maxima. Post-module processors see
   immutable finding snapshots and return separately recorded disposition/annotation proposals;
   scanner findings continue unchanged. Reporting consumes only a bounded summary.
5. `ScanResult.pipeline_outcomes` carries validated safe outcomes. Dedicated typed lifecycle events
   publish each outcome through the existing event bus; DAST uses awaited durable publication so
   configured webhook sinks enqueue redacted notification work without performing delivery in the
   foreground. Code retains its existing non-durable event semantics because it has no durable job
   host.
6. Legacy pre-scan scripts receive a versioned compatibility envelope and may narrow modules;
   legacy post-module `findings` arrays are parsed into source-identity dispositions but cannot
   alter the original vector; legacy post-scan output is recorded as an annotation proposal.
   Empty output remains passthrough. Invalid output follows the configured required/optional mode.
7. All processor inputs, outputs, counts, strings, annotations, proposals, and outcome collections
   have independent ceilings. Notification-phase local executable registration fails validation and
   points operators to the durable webhook configuration.

### File manifest

- Add `crates/scorchkit-core/src/run_pipeline.rs`; export it from the core library and compatibility
  engine facade; extend `ScanResult` and `ScanEvent` with bounded typed pipeline records.
- Add `crates/scorchkit-config/src/run_pipeline.rs`; export it and extend `AppConfig`/`HookConfig`
  with explicit processors while preserving legacy deserialization defaults.
- Rewrite `src/engine/hook_runner.rs`; add narrow context helpers in `scan_context.rs` and
  `code_context.rs` to construct sealed authority ceilings and bounded invocations.
- Update `src/runner/orchestrator.rs` and `src/runner/code_orchestrator.rs` to apply preprocessing
  narrowing, preserve findings, collect outcomes, and publish typed lifecycle records.
- Update exhaustive event consumers in `src/engine/audit_log.rs`, `src/webhooks.rs`, and runner tests;
  update `ScanResult` fixtures and control/report serialization snapshots where the new defaulted
  field is observable.
- Update `docs/architecture/hooks.md`, `docs/architecture/runner.md`, configuration/reference docs,
  README/SECURITY/CHANGELOG/ROADMAP at completion, and add focused contract/integration tests.

### Regression plan

- Core truth tables: every phase wire name/order, schema pairing, identifier/text/list ceilings,
  unique order, nonzero/max budgets, authority target/module/capability/effect/credential clamps,
  finding-source identity, outcome disposition, redaction, and serialization round trips.
- Configuration: explicit processor defaults and exact boundaries, duplicate identity/order,
  invalid notification transport, legacy list compatibility, no configured-processor defaults, and
  secret-free `Debug`/error messages.
- Adapter: exact request bytes/schema, empty output, malformed/oversized output, contract mismatch,
  missing source finding, required/optional failure, deterministic chaining, cancellation, timeout,
  output overflow, and recording executor no-call checks after invalid registration.
- Runners: accepted module narrowing before execution; target/capability/effect expansion denial;
  original finding equality after filter/enrich proposals; stable outcome/event ordering; required
  abort vs optional degraded continuation; final cancellation; result/report/control JSON parity.
- Notifications: DAST typed outcomes reach an awaited recording durable sink, webhook event kind and
  redacted payload are bounded, and no local notification executable or synchronous network sender
  is reachable.
- Validation: focused Rust tests and `bash bin/gate.sh --fast` during implementation; preserve the
  one completed `bash bin/gate.sh --diff` inventory; recheck exactly its 114 survivors; then use
  `bash bin/gate.sh --focused-repair` for validation and post-archive delivery. Never repeat the
  broad selection or run the no-argument/full mutation gate.

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
