---
title: TICKET-031-finding-triage
status: done
ticket_number: 031
type: feature
created: 2026-08-24
closed: 2026-08-24
intake: docs/planning/intake/INTAKE-finding-triage.md
pipeline_spec: docs/planning/pipeline/completed/finding-triage.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-031
---

# Durable finding validation and triage lifecycle

## Summary

Add one provider-neutral append-only finding-validation and triage contract for human and system
decisions, correlation explanations, scoped time-bounded suppressions, accepted risk, fixes, and
regressions. The original scanner finding and evidence remain immutable, model recommendations
remain labeled analysis, and every public surface consumes the same canonical durable projection.

## Why

SK-035 established canonical findings and evidence, SK-040 established evidence-backed attack-path
transitions, and SK-052 established model recommendations without lifecycle authority. ScorchKit
still exposes a mutable compatibility status column, so it cannot reconstruct who decided what,
preserve disagreement, scope a suppression safely, or distinguish a verified fix from a later
regression. SK-053 closes that gap before any conversation or console frontend is added.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an authorized actor triages a finding, ScorchKit shall append one canonical transition containing the exact prior and next closed state, actor, reason, time, evidence references, and optional model-analysis reference without changing the original scanner finding or evidence. | Core state/identity tables, authorization-before-write tests, append/conflict tests, and scanner-record byte-invariance checks. |
| REQ-002 | When findings are deduplicated or correlated, ScorchKit shall append a canonical decision that retains every contributing finding, scanner, and evidence identity plus the normalized facets and a bounded redacted explanation. | Multi-scanner/source-runtime fixtures, ordering/identity/limit tables, and durable parity tests. |
| REQ-003 | When a suppression is created, ScorchKit shall require an exact project plus finding, rule, target, or rule-target scope, a reason, actor, creation time, and a future expiry or review time; only an unexpired exact match shall be active and no suppression shall remove the finding or evidence from canonical reads. | Scope/expiry/review/mismatch truth table, public visibility checks, and exact-boundary tests. |
| REQ-004 | When model analysis recommends a disposition, ScorchKit shall preserve the recommendation and provenance separately and shall reject any state transition that lacks an independently authorized actor command or cites analysis not belonging to the same finding. | Model/user disagreement, cross-finding reference, missing engagement/grant, and audit-order tests. |
| REQ-005 | When a fixed finding reappears under the same stable identity, or a prior disposition no longer matches materially changed evidence, ScorchKit shall append a deterministic regressed or needs-context transition instead of silently retaining the prior disposition. | Repeated-scan, changed-evidence, idempotency, and concurrent-ingest tests. |
| REQ-006 | When triage is read through control API, CLI, MCP, or reports, ScorchKit shall project the same current state, complete ordered history, correlation decisions, evidence links, and active-suppression verdict and shall fail the complete read on malformed or divergent durable child state. | Cross-surface snapshots, external schema fixture, PostgreSQL corruption matrix, and report projection tests. |
| REQ-007 | When existing finding status commands and stored legacy statuses are used, ScorchKit shall map them explicitly into the new transition vocabulary without deleting history or changing headless CLI/MCP compatibility. | Migration matrix and legacy CLI/MCP command/result fixtures. |

## Scope

- In: provider-neutral triage domain and identities; append-only transitions, correlation decisions,
  and suppression records; exact current-state projection; deterministic reappearance handling;
  PostgreSQL migration and canonical parity; control API command/query; CLI/MCP compatibility;
  report projections; tests and durable documentation.
- Out: deleting or rewriting detector output; global permanent ignores; model-owned dispositions;
  a frontend; team identity/RBAC; automatic network or scanner effects; arbitrary correlation from
  prose; push or PR.

## Locked decisions

- The canonical triage history is authoritative; a duplicated current state is only an indexed
  projection and must match the ordered history.
- Suppression changes visibility metadata only. Canonical findings and evidence always remain
  readable and countable.
- Human and deterministic system actors may append transitions. Model identities may be cited as
  provenance but never satisfy actor authorization.
- Rediscovery under a fixed stable identity creates `regressed`; a materially changed evidence set
  invalidates a prior disposition as `needs_context`.
- Existing `VulnStatus` values remain compatibility inputs with an explicit closed mapping.
- Triage commands are `local_state` effects and require the same exact engagement binding and
  policy enforcement as other control mutations.
- Validation uses one DIFF gate. A completed survivor inventory may receive exact-name repair and
  recheck only; no no-argument or FULL mutation campaign is part of this ticket.
- The owner approved repair and exact-name recheck of all and only the completed DIFF's 195
  survivors in 47 functions across seven files. The 598-mutant raw baseline remains preserved;
  another broad mutation run is explicitly out of scope.

## Recon

- Intake: `docs/planning/intake/INTAKE-finding-triage.md`.
- Reused seams: canonical `FindingRecordV2` and child validation, attack-path transition identity
  and storage patterns, model-analysis provenance, `ControlService`, local-state authorization,
  CLI/MCP control adapters, and canonical report redaction.
- The current `tracked_findings.status/status_note` update is mutable and unaudited. `VulnStatus`
  already accepts `wont_fix` and `accepted_risk`, but public control validation only proves that the
  string is recognized; there is no transition history, scoped suppression, model-reference check,
  or regression-on-rediscovery contract.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/finding-triage.spec.md`
- The owner directed overnight work through the next roughly five tickets and previously authorized
  local commits. This confirms plan/design transitions and local delivery only; it does not
  authorize a push, PR, remote target, or live model/service call.

## Log

- 2026-08-24: opened.
- 2026-08-24: intake promoted; plan locked to append-only history, exact suppression matching,
  deterministic rediscovery, canonical cross-surface parity, and compatibility over the existing
  mutable status commands.
- 2026-08-24: implementation completed for core/storage/migration/control/CLI/MCP/report projection,
  typed multi-target authorization, concurrent rediscovery, release upgrade, and durable docs;
  focused development validation is green and adversarial inspection is next.
- 2026-08-24: the completed DIFF selected 598 mutants: 357 caught, 195 missed, and 46 unviable
  (64.67% viable MSI). The owner stopped broad reruns and approved repair of exactly those 195
  survivor names followed by a focused recheck and local commit.
- 2026-08-24: survivor-only rechecks caught 164 of 195, then 28 of the remaining 31, then all three
  selector-guaranteed residuals. Sealed cumulative evidence verifies all 195 original survivors
  caught, 552/552 viable caught overall, 46 unviable, zero misses, and 100% MSI without another
  broad mutation run.
- 2026-08-24: the focused-repair delivery gate passed 19 applicable lanes with no failures, 85.55%
  line coverage, 2,189 strict Nextest cases, authenticated PostgreSQL, CLI/MCP contracts, and three
  named web-only skips; its mutation lane verified sealed evidence and ran no cargo-mutants.
