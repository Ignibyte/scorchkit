---
aar: AAR-025-quality-ratchet
ticket: TICKET-025
pipeline: quality-ratchet
status: submitted
opened: 2026-08-22
submitted: 2026-08-23
effectiveness: 4
---

# AAR-025 — Complete scheduled mutation inventory and quality ratchet

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `AAR-001-rustal-quality-workflow` | The scheduled campaign is the full inventory deferred by TICKET-001. | Yes; it requires one preserved broad result, fail-closed completion status, exact survivor rechecks, and a blind-file ledger. |
| `PR-scorchkit-gate-prerequisites-001` | A 9,772-case inventory is too costly to run behind a known-red prerequisite. | Yes; complete static and coverage readiness before campaign execution. |
| `BF-scorchkit-mutation-rescan-cost-001` / `PR-scorchkit-focused-mutation-repair-001` | SK-047 explicitly combines broad discovery with bounded repair. | Yes; perform one FULL baseline and thereafter run only the exact survivor set. |
| `AAR-007-workspace-crate-extraction` / `PR-scorchkit-workspace-gate-scope-001` | The inventory spans the extracted workspace. | Yes; assert every configured package source remains in scope and preserve the root facade only as composition. |
| `AAR-023-windows-process-owner` / `PR-scorchkit-target-inactive-mutation-files-001` | Linux cannot observe native-Windows implementations. | Yes; retain the two exact target-inactive file exclusions and reject any new exclusion. |
| `PR-scorchkit-validation-evidence-before-receipt-001` | Campaign documents and evidence summaries change the worktree. | Yes; finalize them before receipt-producing validation and rerun the same approved mode after archive. |

## What happened

- Planning promoted SK-047 as TICKET-025 and began the scheduled 9,772-case inventory in four local
  shards. Two shards completed; a third stopped after 138 outcomes; the fourth never started. The
  owner then stopped the remaining broad work and approved repair of only the 13 unique names seen.
- One completed exact 13-name baseline corrected the partial evidence: the cloud description
  candidate was already caught, while 12 names across TLS, rate limiting, and SSRF reproduced as
  misses. Direct boundary and truth-table tests repaired those seams without changing production
  behavior.
- The only post-repair mutation execution selected those exact 12 misses. It caught all 12 with no
  timeout, miss, or unviable outcome. Sealed evidence accounts for all 13 candidates at 100% focused
  MSI and preserves the stopped shards as incomplete, non-passing discovery evidence.

## Novel findings

- Plan recon measured 9,772 configured mutations across 298 source files, materially larger than
  the 6,095-case inventory recorded when workspace extraction completed.
- Partial mutation output is useful for candidate discovery but cannot determine an authoritative
  repair denominator: one of the 13 names labeled as a survivor by the stopped work was caught by
  the completed exact baseline.
- Shell validation using `awk` must carry invalid state into `END`; an unconditional final exit can
  erase an earlier failure and accept malformed scope files.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-partial-mutation-survivor-overstatement-001` | The stopped campaign's labels overstated the repair set because incomplete shard output had not completed a common baseline. | Exact 13-name pre-repair run. |
| `BF-scorchkit-awk-end-status-overwrite-001` | The first blank-line validator could overwrite an early failure from its `END` block. | Adversarial shell inspection and selftest. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-partial-mutation-candidate-reproduction-001` | Treat names from an incomplete mutation run as candidates; execute one completed exact pre-repair selection and let its misses define the repair/recheck set. | This avoids repairing or claiming a seam based on partial-run status while still bounding expensive work. |
| `PR-scorchkit-shell-validator-accumulate-state-001` | Stream validators with finalization blocks must accumulate invalid state and decide success once at the end, with empty, blank, duplicate, and valid fixtures. | Finalization logic can otherwise overwrite an earlier nonzero exit and silently widen an exact scope. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

The recalled focused-repair rule prevented a second broad campaign after the owner stopped the
first. Exact reproduction narrowed 13 partial-run candidates to 12 authoritative misses, and the
generic evidence contract proved their three-file transition and exact current-tree recheck. The
original full-campaign plan was too costly for the owner's desired outcome, but fail-closed evidence
labeling kept the incomplete work from becoming a false green claim.
