---
aar: AAR-031-finding-triage
ticket: TICKET-031
pipeline: finding-triage
status: submitted
opened: 2026-08-24
submitted: 2026-08-24
effectiveness: 4 - strong
---

# AAR-031 — Durable finding validation and triage lifecycle

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-transition-audit-reconstruction-001` | Triage replaces a mutable status with decisions over time. | Yes — current state will be reconstructed from canonical ordered transitions. |
| `PR-scorchkit-durable-canonical-parity-001` | Triage has raw child JSON plus indexed duplicated fields. | Yes — every child and current-state projection must match before a public read. |
| `PR-scorchkit-projection-validate-canonical-001` | CLI, MCP, API, and reports share triage state. | Yes — invalid nested state fails the complete projection. |
| `PR-scorchkit-proof-evidence-own-provenance-001` | Correlation and disposition cite scanner evidence. | Yes — decisions retain exact same-finding evidence identities and cannot borrow proof implicitly. |
| `PR-scorchkit-correlation-work-budget-001` | Correlation decisions contain many identities and facets. | Yes — counts, text, and aggregate work receive separate ceilings. |
| `PR-scorchkit-attribution-not-authorization-001` and SK-052 | A model may recommend a disposition. | Yes — its identity is optional provenance and never an authorized actor. |
| `PR-scorchkit-public-typed-canonical-redaction-001` | Public triage structs can bypass constructors. | Yes — consumers must revalidate canonical redaction and ordering. |
| `PR-scorchkit-bounded-validator-mutation-table-001` | Closed states, scopes, times, and mappings create branch seams. | Yes — tests will pin every enum, exact limit, and independent predicate. |

## What happened

- Added a provider-neutral seven-state lifecycle with bounded canonical transitions, correlations,
  suppressions, actor attribution, model-analysis provenance, legacy compatibility, and exact
  deterministic identities while preserving scanner findings and evidence unchanged.
- Added append-only PostgreSQL storage, migration of every legacy status, complete child/raw/
  duplicated-column parity, transactional write ceilings, deterministic rediscovery, and one
  validated current-state projection reconstructed from history.
- Routed control API, CLI, MCP, and project-report consumers through the same authorization-before-
  write and fail-closed public projection, including typed runtime, source, artifact, network, and
  cloud target authorization.
- Adversarial inspection repaired selector-before-validation, mutable-latest-history,
  concurrency/lock-order, retry/determinism, caller-error, and compatibility defects before
  survivor-only mutation repair.

## Novel findings

| ID | Finding | Why it matters |
|---|---|---|
| `BF-scorchkit-unvalidated-suppression-selector-001` | A suppression query filtered on duplicated scope columns before validating their parity with the canonical raw record. | Corrupting a duplicate could hide the row from validation and make a complete public read fail open. |
| `BF-scorchkit-latest-state-history-revalidation-001` | Correlation readback tried to reconstruct an append-only decision's scanner/evidence context from mutable latest finding snapshots. | Valid historical decisions can become unreadable after later rediscovery unless their preserved inputs remain authoritative. |
| `BF-scorchkit-append-bound-lock-order-001` | Read sentinel bounds existed without equivalent first-over-limit write rejection, and multi-parent writes lacked one complete lock order. | A successful write could poison future reads or create deadlock risk even though each individual row was otherwise valid. |
| `BF-scorchkit-selector-invariant-mutation-gap-001` | Defensive duplicated-column checks guaranteed by the current SQL selector could not be falsified through ordinary database fixtures. | Unexercised fail-closed checks survive mutation and can silently regress if the selector or schema changes later. |

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-unvalidated-suppression-selector-001` | A malformed suppression vanished from the relevance query and the public projection succeeded. | Durable-parity adversarial inspection and PostgreSQL corruption matrix. |
| `BF-scorchkit-latest-state-history-revalidation-001` | Cross-scanner rediscovery could invalidate a previously valid correlation, while unrelated duplicate evidence could cause a false ownership failure. | Historical-integrity inspection. |
| `BF-scorchkit-append-bound-lock-order-001` | The first over-limit append was accepted and opposite-parent correlation writes could lock rows in conflicting order. | Concurrency and exact-bound review. |
| `BF-scorchkit-selector-invariant-mutation-gap-001` | Three OR-to-AND changes remained observationally equivalent through the production SQL selectors. | Completed exact survivor rechecks. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-validate-before-select-duplicate-001` | Validate a complete bounded canonical child ledger before duplicated columns decide relevance, filtering, or visibility. | A corrupt duplicate must never remove its own canonical row from validation scope. |
| `PR-scorchkit-history-not-latest-reconstruction-001` | Reconstruct append-only decisions from their preserved inputs and cited provenance, never from a mutable latest snapshot. | Current state cannot retroactively redefine valid historical truth. |
| `PR-scorchkit-append-bound-lock-order-001` | Give every bounded append-only child the same read and write ceiling, and document one global lock order across aggregate, project, and member rows. | Read bounds alone permit durable poisoning, while locally reasonable row locks can still deadlock. |
| `PR-scorchkit-selector-invariant-test-seam-001` | Keep selector-guaranteed defensive projection checks independently falsifiable through test-only row injection or an equivalent pure validation seam. | Defensive parity code needs direct evidence even when the current query makes corruption unreachable. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Recalled knowledge materially changed the design from an expanded mutable status field into a
bounded append-only history with same-finding provenance, consumer-side canonical validation, and
authorization separated from model attribution. Adversarial inspection still found ordering,
historical-reconstruction, write-bound, and lock-order gaps that representative functional tests
had not exposed. One completed 598-mutant DIFF preserved 195 survivors; exact survivor-only
rechecks caught all 195 without another broad run. The sealed evidence reconstructs 552/552 viable
mutations caught at 100% MSI with 46 unviable and zero misses.
