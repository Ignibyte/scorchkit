---
title: INTAKE-quality-ratchet
status: promoted
created: 2026-08-17
ticket: TICKET-025
pipeline_spec: docs/planning/pipeline/active/quality-ratchet.spec.md
---

# Quality ratchet and scheduled full mutation evidence

## Problem or opportunity

The repository has focused mutation evidence for completed repairs and one interrupted discovery
inventory, but the scheduled complete mutation baseline and measured coverage ratchet remain open.
Repeating a broad mutation scan after each repair would waste hours without improving repair proof.

## Proposed outcome

The original proposal was one completed, preserved full mutation inventory followed by focused
repairs. On 2026-08-23 the repository owner stopped the remaining broad shards, approved repair of
the exact observed candidates only, and directed the pipeline to SK-048. TICKET-025 therefore
preserves the stopped work as incomplete discovery evidence, closes the exact reproduced survivor
set, and leaves both quality floors unchanged.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the scheduled full mutation campaign runs, ScorchKit shall execute the complete inventory in planned local-scratch shards and preserve a recognized completed result. | Merged raw outcomes and verifier output. |
| REQ-002 | When the full inventory reports survivors, ScorchKit shall create named focused repair scopes and shall not rerun the full inventory after each repair. | Survivor-to-ticket ledger and focused outcomes. |
| REQ-003 | When mutation results are published, ScorchKit shall reconstruct the viable score, misses, timeouts, unviable outcomes, and blind files from raw evidence. | Independent verifier tests. |
| REQ-004 | When coverage or mutation floors increase, ScorchKit shall set them no higher than the measured green baseline and shall not add exclusions or skips to obtain it. | Gate selftests and reviewed configuration diff. |

## Scope notes

- Delivered: two complete shards and one partial shard preserved as non-passing discovery evidence;
  a completed exact 13-candidate baseline; direct repair of its 12 misses; one exact 12-name
  recheck; focused evidence and delivery contracts.
- Canceled by owner direction: the remaining broad shards, a merged FULL claim, and an 80 percent
  coverage ratchet. Lower floors, wider exclusions, retries, and silent skips remained out of scope.
