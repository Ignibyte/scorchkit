---
title: TICKET-029-typed-run-pipeline
status: done
ticket_number: 029
type: feature
created: 2026-08-23
closed: 2026-08-24
intake:
pipeline_spec: docs/planning/pipeline/completed/typed-run-pipeline.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-029
---

# Typed run preprocessors and lifecycle hooks

## Summary

Promote ScorchKit's existing event and local-hook seams into one versioned, provider-neutral run
pipeline. Typed processors may narrow a run plan or propose derived finding dispositions, but the
engine validates every envelope, clamps it to already-authorized inputs, preserves original scanner
findings, and records each accepted, rejected, degraded, or failed processor outcome.

## Why

SK-050 established an isolated extension contract, while today's lifecycle scripts still exchange
untyped JSON and may destructively replace a module's findings. SK-051 establishes the lifecycle,
proposal, ordering, failure, and provenance boundary before later model analysis, triage, and
conversation surfaces consume or produce derived security context.

## EARS Requirements

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

## Scope

- In: versioned phase, processor, proposal, authority-ceiling, disposition, and outcome contracts;
  explicit local processor configuration; legacy hook adapters; deterministic execution in the
  existing DAST and code runners; policy clamping; original-finding preservation; bounded outcome
  projection; durable notification handoff; documentation and compatibility tests.
- Out: a second event bus; ambient or direct network/filesystem/database access; extension package
  distribution; model inference; triage-state mutation; arbitrary scanner-evidence replacement;
  adding lifecycle scripts to scan families that do not currently support them; synchronous remote
  notification delivery.

## Locked decisions

- Core contracts remain provider neutral and below CLI, MCP, storage, agent, and local-process
  adapters. Root composition owns execution, authorization ceilings, and durable publication.
- Processor declarations and returned proposals are context, never grants. V1 target changes are
  rejected; module, capability, credential-use, and effect requests may only narrow sealed maxima.
- Original scanner findings are immutable pipeline inputs. A processor returns separately labeled
  proposals and outcomes; it never replaces or mutates scanner evidence in place.
- Local processors use only the existing policy-sealed `ToolExecutor`, one JSON envelope on stdin,
  and one bounded JSON envelope on stdout. No shell, ambient network, or storage handle is added.
- Required processors fail closed. Optional processors produce a redacted degraded outcome and
  their output is not applied. Notification remains an awaited durable enqueue followed by an
  independently owned worker.
- Legacy hooks remain accepted through fixed compatibility contracts and stable config order, but
  legacy post-module output becomes a recorded proposal instead of replacing scanner findings.
- Development uses `bash bin/gate.sh --fast`; the one completed DIFF inventory is retained and its
  114 survivors are the exact approved repair/recheck scope. Validation and post-archive delivery
  use `bash bin/gate.sh --focused-repair`; another broad, mode-less, or `--full` run is not
  authorized.

## Recon

- `HookRunner` currently chains arbitrary `serde_json::Value`; pre-scan output is ignored,
  post-module may replace the complete findings vector, and post-scan output is discarded.
- Only DAST and code orchestrators currently invoke local hooks. They already race hook futures with
  the scan cancellation token and run scripts through policy-sealed owned subprocesses.
- `EventBus` is bounded best-effort telemetry, while `publish_durable` awaits registered sinks before
  broadcast. The SK-043 webhook sink is the existing notification handoff and delivery remains out
  of band.
- `ScanResult` is the shared provider-neutral projection used by reports and higher-level hosts; it
  has no pipeline outcome field today.
- `EffectClass` and `Capability` are ordered/typed policy values, so a host-built ceiling can validate
  proposals without exposing an `Engagement` or opaque authorization decision to a processor.
- SK-050's manifest/protocol boundaries and SK-028's cancellation seam supply reusable version,
  byte-limit, process-ownership, and exact-boundary patterns.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/typed-run-pipeline.spec.md`
- Promoted from `docs/planning/intake/INTAKE-typed-run-pipeline.md`.

## Log

- 2026-08-23: opened.
- 2026-08-23: promoted the SK-051 candidate under the owner's standing direction to continue the
  next roughly five tickets with DIFF-only mutation validation.
- 2026-08-24: owner directed ScorchKit to squash survivors only and avoid repeating the long broad
  mutation process; approved focused repair is exactly the completed DIFF's 114 named survivors in
  28 verifier-distinct functions across eight files, sealed as
  `scorchkit-mutants-focused-ticket-029`.
