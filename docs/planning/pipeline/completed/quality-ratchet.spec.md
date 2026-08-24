---
title: Complete scheduled mutation inventory and quality ratchet
pipeline_id: 1508637c-d626-43cd-ab4a-3d27ef8b5bba
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-025
ticket_doc: docs/planning/tickets/closed/TICKET-025-quality-ratchet.md
aar: docs/planning/knowledge/aar/AAR-025-quality-ratchet.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-025
created: 2026-08-22
---

# Complete scheduled mutation inventory and quality ratchet — spec

## Intent

Preserve the stopped repository-wide campaign as incomplete discovery evidence, evaluate the exact
13 survivor candidates observed before the owner stopped it, repair the 12 reproduced survivors,
and move to binary release work without another broad mutation run or an unmeasured quality-floor
change.

## Scope

- In: preservation of the two completed shards and one partial shard as non-passing discovery
  evidence; an exact 13-name pre-repair run; source/test repair; exact 12-name recheck; focused
  evidence sealing; documentation.
- Out: the remaining broad shards, a merged FULL claim, the planned campaign helper, the 80%
  coverage ratchet, unrelated product changes, new effect classes, remote targets, lower floors,
  broader mutation exclusions, retries, skips, ignores, or suppressions.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When TICKET-025 reports the stopped broad campaign, ScorchKit shall label its two completed shards and one partial shard as incomplete discovery evidence and shall never report them as a completed FULL result or delivery proof. | Raw artifact readback, ticket narrative, and absence of a merged FULL receipt. |
| REQ-002 | When the focused repair begins, ScorchKit shall select all and only the 13 unique survivor names observed before the stop and shall reject any inventory mismatch. | Exact-name inventory preflight and completed pre-repair outcomes. |
| REQ-003 | When mutation inputs change for the repair, ScorchKit shall preserve every prior input, prove the old-to-new transition, and recheck exactly the 12 names that the completed pre-repair run reproduced as misses without another broad run. | Transition snapshots, exact focused outcomes, and focused-evidence verifier. |
| REQ-004 | When a discovered survivor represents an observable contract, ScorchKit shall add a direct regression assertion that distinguishes the original behavior from its mutation. | Focused TLS, metadata, rate-limit, and SSRF tests. |
| REQ-005 | When this narrowed campaign is delivered, ScorchKit shall retain the 62% coverage and 95% mutation floors and shall add no exclusion, skip, retry, ignore, suppression, or baseline. | Configuration diff and quality-gate contracts. |
| REQ-006 | When TICKET-025 is delivered, ScorchKit shall pass every non-web delivery lane and shall bind its 13-candidate/12-repair focused evidence and final worktree in the receipt. | Green FOCUSED-REPAIR receipt, pipeline receipt check, and post-archive rerun. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Stop the broad campaign after the owner's 2026-08-23 direction and do not run shards `2/4` or `3/4` again. | The remaining hours do not improve proof for the 13 already observed seams. |
| 2 | Treat the exact 13 unique observed names as the owner-approved candidate scope and the completed exact-name baseline's 12 misses as the repair scope. | The fresh baseline caught the cloud-description candidate and reproduced the other 12, so evidence rather than a partial-run label defines the repair set. |
| 3 | Run the 13 candidates once before repair and the 12 reproduced misses once after repair; run no other mutation selection. | This proves the original gaps and their repairs without representing incomplete broad evidence as passing. |
| 4 | Run Cargo commands sequentially; use only cargo-mutants' bounded workers on local scratch for concurrency. | This preserves the repository build contract. |
| 5 | Keep the 62% coverage and 95% mutation floors unchanged. | The stopped campaign cannot support a repository-wide ratchet. |
| 6 | Add no exclusion, retry, ignore, skip, suppression, or synthetic outcome. | Quality debt is repaired at observable source/test seams and raw evidence remains authoritative. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-025-quality-ratchet.md`
- AAR: `docs/planning/knowledge/aar/AAR-025-quality-ratchet.md`
- Intake: `docs/planning/intake/INTAKE-quality-ratchet.md`
- Architecture: `CONSTITUTION.md` sections 0, 3, 15, and 19; `docs/planning/ROADMAP.md`

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

## Design

### Focused repair architecture

1. Preserve `.git/scorchkit-mutants-full-ticket-025` and
   `.git/scorchkit-mutants-full-work-002-of-004` as stopped, non-passing discovery artifacts.
2. `bin/mutants.sh --recheck` inventories and executes the exact 13 names and rejects a missing,
   extra, duplicate, blank, traversal-bearing, or stale name before execution.
3. The pre-repair exact-name run becomes the completed `initial/` focused baseline. It caught the
   cloud-description candidate and reproduced 12 misses; it is not described as a FULL or DIFF
   result.
4. Snapshot every mutation input changed by the repair, add direct behavioral assertions, and run
   the same exact-name selection once on the final tree.
5. The generic verifier proves the initial survivor set equals the final caught/timeout set, proves
   the input transition, enforces at least 95% MSI, and rejects the incomplete broad artifacts as a
   delivery source.
6. The final current-tree focused-repair gate runs every non-mutation delivery lane, verifies the
   sealed exact-scope evidence without cargo-mutants, and binds its digest and exact tree.

### Safety and effect review

- The campaign adds no ScorchKit runtime effect. Its subprocess and filesystem actions remain local
  developer/CI tooling: cargo-mutants, the existing validation PostgreSQL database, ephemeral local
  scratch, and a validated evidence directory immediately beneath `.git`.
- Evidence paths reject symlinks, traversal, unexpected Git-directory locations, stale source
  hashes, mixed cargo-mutants versions, incomplete shards, overlaps, gaps, and edited raw results.
- No scanner, remote target, credential, TLS, timeout, output-limit, or secret-redaction behavior is
  weakened or exercised against a non-loopback target.

### Planned file manifest

- Extend `bin/mutants.sh` with exact-name recheck mode and safe caller-selected evidence output;
  keep DIFF, FULL, INSPECT, SELFTEST, and SHARD contracts compatible.
- Extend `tests/quality_gate_contract.rs` to pin exact-name selection, unchanged exclusions, and the
  unchanged 95% MSI floor.
- Repair only `src/engine/tls_probe.rs`, `src/scanner/ratelimit.rs`, and `src/scanner/ssrf.rs`, plus
  direct tests in those files. `src/recon/cloud.rs` needs no change because the exact baseline caught
  its candidate.
- Update `docs/guide/development.md`, `CONSTITUTION.md`, `docs/planning/ROADMAP.md`, `CHANGELOG.md`,
  ticket/pipeline/AAR artifacts, and the knowledge register with the stopped-campaign disposition,
  exact repair evidence, and operator instructions.

### Regression plan

- Shell/self-test: reject missing, extra, duplicate, blank, traversal-bearing, or stale exact names.
- Initial evidence: one completed exact-name run accounts for all 13 observed candidates before
  source or test repair: one caught and 12 missed.
- Development: focused TLS, metadata, rate-limit, and SSRF tests, exact lint, and the fast gate.
- Repair evidence: one current-tree exact 12-name recheck, transition snapshots, and generic focused
  verification with zero survivors and at least 95% MSI.
- Validation/delivery: database-backed `bash bin/gate.sh --focused-repair` before completion and
  again after archive; confirm the unchanged 62% coverage and 95% mutation floors, named web-only
  skips, pipeline receipt match, exact evidence digest, and clean `git diff --check`.
