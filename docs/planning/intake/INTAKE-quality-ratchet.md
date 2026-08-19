---
title: INTAKE-quality-ratchet
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Quality ratchet and scheduled full mutation evidence

## Problem or opportunity

The repository has focused mutation evidence for completed repairs and one interrupted discovery
inventory, but the scheduled complete mutation baseline and measured coverage ratchet remain open.
Repeating a broad mutation scan after each repair would waste hours without improving repair proof.

## Proposed outcome

ScorchKit will have one completed, preserved full mutation inventory, focused tickets for any named
survivors, a reviewed blind-file ledger, and coverage/mutation floors raised only from completed
green evidence.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the scheduled full mutation campaign runs, ScorchKit shall execute the complete inventory in planned local-scratch shards and preserve a recognized completed result. | Merged raw outcomes and verifier output. |
| REQ-002 | When the full inventory reports survivors, ScorchKit shall create named focused repair scopes and shall not rerun the full inventory after each repair. | Survivor-to-ticket ledger and focused outcomes. |
| REQ-003 | When mutation results are published, ScorchKit shall reconstruct the viable score, misses, timeouts, unviable outcomes, and blind files from raw evidence. | Independent verifier tests. |
| REQ-004 | When coverage or mutation floors increase, ScorchKit shall set them no higher than the measured green baseline and shall not add exclusions or skips to obtain it. | Gate selftests and reviewed configuration diff. |

## Scope notes

- In: scheduled full mutation evidence, survivor repair ledger, blind-file review, measured coverage
  ratchet toward 80 percent, gate contracts.
- Out: full rescans after every mutation fix, lower floors, wider exclusions, retries or silent skips.
