---
title: TICKET-025-quality-ratchet
status: done
ticket_number: 025
type: chore
focused_repair: approved
created: 2026-08-22
closed: 2026-08-23
intake: docs/planning/intake/INTAKE-quality-ratchet.md
pipeline_spec: docs/planning/pipeline/completed/quality-ratchet.spec.md
---

# Complete scheduled mutation inventory and quality ratchet

## Summary

Preserve the stopped repository-wide campaign as incomplete discovery evidence, evaluate the exact
13 survivor candidates observed before the owner stopped it, repair the 12 reproduced survivors,
and move on without another broad mutation run or an unsupported coverage-floor ratchet.

## Why

SK-027 deliberately deferred one broad inventory after its interrupted discovery run. TICKET-025
completed two of four shards and 138 outcomes from a third before the owner stopped it on
2026-08-23. Those artifacts exposed 13 unique survivors but did not produce a completed FULL result.
Finishing the remaining hours is not required to repair the observed seams or proceed to SK-048.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When TICKET-025 reports the stopped broad campaign, ScorchKit shall label its two completed shards and one partial shard as incomplete discovery evidence and shall never report them as a completed FULL result or delivery proof. | Raw artifact readback, ticket narrative, and absence of a merged FULL receipt. |
| REQ-002 | When the focused repair begins, ScorchKit shall select all and only the 13 unique survivor names observed before the stop and shall reject any inventory mismatch. | Exact-name inventory preflight and completed pre-repair outcomes. |
| REQ-003 | When mutation inputs change for the repair, ScorchKit shall preserve every prior input, prove the old-to-new transition, and recheck exactly the 12 names that the completed pre-repair run reproduced as misses without another broad run. | Transition snapshots, exact focused outcomes, and focused-evidence verifier. |
| REQ-004 | When a discovered survivor represents an observable contract, ScorchKit shall add a direct regression assertion that distinguishes the original behavior from its mutation. | Focused TLS, metadata, rate-limit, and SSRF tests. |
| REQ-005 | When this narrowed campaign is delivered, ScorchKit shall retain the 62% coverage and 95% mutation floors and shall add no exclusion, skip, retry, ignore, suppression, or baseline. | Configuration diff and quality-gate contracts. |
| REQ-006 | When TICKET-025 is delivered, ScorchKit shall pass every non-web delivery lane and shall bind its 13-candidate/12-repair focused evidence and final worktree in the receipt. | Green FOCUSED-REPAIR receipt, pipeline receipt check, and post-archive rerun. |

## Scope

- In: stopped-campaign disposition; exact 13-name baseline; source/test repair; exact 12-survivor
  recheck; focused evidence, gate, documentation, and receipt contracts.
- Out: remaining broad shards; merged FULL claims; coverage-floor changes; unrelated product
  behavior; remote or third-party scan targets; lower quality floors; broader exclusions, retries,
  skips, ignores, or suppressions.

## Locked decisions

- The owner's 2026-08-23 direction supersedes the broad-campaign portion of the 2026-08-22 plan:
  stop after the preserved partial evidence, repair all and only the 13 observed survivors, then
  proceed to SK-048.
- Run Cargo commands sequentially. Cargo-mutants may use bounded internal workers, and every worker
  must build on local scratch with the validation PostgreSQL database.
- Run one completed 13-name baseline before repair and one exact 12-name recheck after repair. The
  incomplete broad shards remain discovery-only and are never reported green.
- Keep the 95% viable MSI and 62% coverage minimums unchanged.

## Recon

- `bash bin/mutants.sh --inspect` reports 9,772 configured mutations across 298 source files; the
  inventory stays inside workspace source roots, excludes the composition binary, and includes the
  policy kernel.
- The host has 24 logical CPUs and 827 GiB free on `/mnt/buildtmp`, so bounded parallel mutation
  workers can use the repository-owned local-scratch isolation without competing Cargo commands.
- The last exact-tree DIFF before this ticket measured 84.59% line coverage and 100% MSI for its
  seven viable changed-code mutations. Because the owner stopped the broad campaign, TICKET-025
  retains the existing 62% coverage and 95% mutation floors instead of inferring a new floor.
- Shards `0/4` and `1/4` completed 4,886 unique mutations and found seven survivors. Shard `2/4`
  stopped after 138 outcomes and had found six more; shard `3/4` never started. The exact 13 unique
  names across four source files are the approved candidate scope. The completed exact-name baseline
  caught the cloud-description candidate and reproduced 12 misses across the other three files;
  those 12 are the authoritative repair scope.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/quality-ratchet.spec.md`
- Focused evidence: `.git/scorchkit-mutants-focused-ticket-025`; the initial exact run caught one
  of 13 candidates and reproduced 12 misses, while the exact final recheck caught all 12. The
  generic verifier reports 13/13 viable caught at 100% focused MSI.

## Log

- 2026-08-22: opened.
- 2026-08-22: promoted from `INTAKE-quality-ratchet`; owner direction covers ordered SK-047 and its
  conditional exact survivor repair, while the completed FULL result will define the locked scope.
- 2026-08-23: owner stopped the incomplete FULL campaign, approved repair of the exact 13 observed
  survivors only, and directed work to proceed to the next ticket afterward.
- 2026-08-23: completed the exact candidate baseline and survivor-only recheck; no remaining broad
  shard or second full campaign was run.
