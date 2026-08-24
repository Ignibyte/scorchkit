---
aar: AAR-029-typed-run-pipeline
ticket: TICKET-029
pipeline: typed-run-pipeline
status: submitted
opened: 2026-08-23
submitted: 2026-08-24
effectiveness: 4 - strong
---

# AAR-029 — Typed run preprocessors and lifecycle hooks

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Processor contracts declare capabilities and proposals can name authority-bearing fields. | Yes; the host builds a sealed authority ceiling and validates every proposal before execution changes. |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Processors run immediately around module batches and scan completion. | Yes; every local processor remains inside the caller token and success is checked afterward. |
| `PR-scorchkit-public-evidence-revalidation-001` | Processor output and diagnostics cross into normal scan results. | Yes; output is bounded, typed, normalized, and redacted before projection. |
| `PR-scorchkit-transition-audit-reconstruction-001` | A processor disposition must explain what was proposed and accepted or rejected. | Yes; outcomes retain phase, processor identity, source identities, disposition, and safe diagnostic. |
| `PR-scorchkit-durable-worker-foreground-separation-001` | Notification is a lifecycle phase but remote delivery can outlive a scan. | Yes; the phase only publishes through the durable queue seam and never sends synchronously. |
| `PR-scorchkit-extension-persistence-boundary-001` | SK-050 extensions may later implement lifecycle processors. | Yes; the contract is proposal-only and exposes no storage, policy, engagement, or canonical path handle. |
| `PR-scorchkit-bounded-validator-mutation-table-001` | New contracts contain versions, counts, byte ceilings, ordering, and subset predicates. | Yes; the regression plan isolates every exact boundary and invalid arm. |
| `docs/architecture/hooks.md` | Current behavior chains raw JSON and replaces post-module findings. | Yes; compatibility adapters retain invocation while removing destructive evidence replacement. |

## What happened

- Added provider-neutral typed contracts for eleven lifecycle phases, explicit processor identity,
  schemas, deterministic order, failure mode, resource budgets, sealed authority, typed proposals,
  and bounded redacted outcomes.
- Added explicit local processor configuration plus deterministic legacy hook adapters, all routed
  through the existing owned and policy-sealed executor without exposing ambient authority.
- Integrated preprocessing, immutable finding proposals, reporting, and typed outcome events into
  the existing DAST and code runners. Accepted preprocessing narrows one carried authority ceiling;
  original scanner findings remain intact and source events precede derived outcomes.
- Adversarial inspection repaired eleven authorization, privacy, provenance, validation,
  compatibility, and maintainability findings.
- The one canonical DIFF selected 374 mutants. Its 114 survivors were repaired without repeating
  that broad run; sealed exact-name evidence accounts for 275/275 viable mutations caught at 100%
  MSI, with 99 unviable. The focused delivery gate passed all 19 applicable lanes at 84.80% line
  coverage and launched no cargo-mutants.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-lifecycle-authority-reconstruction-001` | A later processor phase rebuilt authority from the original scan context after preprocessing had narrowed it. | Reconstructing an earlier ceiling silently restores authority that a prior accepted phase removed. |
| `BF-scorchkit-derived-event-before-source-001` | Enrichment outcome publication preceded the source finding event it referenced. | Durable consumers can observe a derived record before its provenance exists. |
| `BF-scorchkit-postgres-init-env-auth-drift-001` | A reused PostgreSQL volume retained its initialized password while current container environment metadata advertised another value. | A readiness probe and current init variables prove reachability, not that delivery credentials authenticate. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-lifecycle-authority-reconstruction-001` | Enrichment and reporting could recover capabilities, effect, and credential ceilings removed during preprocessing. | Adversarial cross-phase authorization trace. |
| `BF-scorchkit-derived-event-before-source-001` | The durable sink received the processor outcome before the source finding. | Adversarial provenance-order inspection. |
| `BF-scorchkit-postgres-init-env-auth-drift-001` | The first DIFF attempt stopped in database-sensitive tests before mutation because the advertised password was stale. | Delivery-gate database preflight. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-lifecycle-authority-monotonic-001` | Carry one sealed mutable authority ceiling through a lifecycle; an accepted narrowing may constrain later phases, and no phase may reconstruct a broader ceiling from original context. | Authorization is monotonic across lifecycle transitions, not independently recalculated per hook. |
| `PR-scorchkit-source-before-derived-publication-001` | Durably publish and identify canonical source records before any processor outcome or derived proposal that references them. | Consumers must never observe provenance edges before their source nodes. |
| `PR-scorchkit-database-auth-preflight-001` | Before a long database-backed delivery gate, execute an authenticated query with the exact gate URL; do not infer credentials from readiness or container initialization metadata. | Reused persistent volumes can retain authentication state that differs from current initialization variables. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 4/5. Recalled policy-before-effects, whole-lifecycle cancellation, public revalidation,
immutable evidence, durable handoff, and exact-boundary mutation rules directly shaped the typed
proposal-only design. Inspection still found two high-impact gaps in secret-safe diagnostics and
cross-phase authority monotonicity plus nine medium-to-low contract gaps. All were repaired and
covered before delivery. The focused campaign then exposed clause-level observability gaps without
repeating the 374-mutant DIFF, and the final gate verified the sealed 275/275 viable result.
