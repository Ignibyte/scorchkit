---
name: scorchkit-pipeline
description: Drive ScorchKit changes through its repository-owned intake, ticket, plan, design, implementation, adversarial inspection, validation, completion, and delivery workflow. Use for feature, bug, refactor, security-hardening, dependency, documentation, or release work in the ScorchKit repository when a change should be implemented or prepared for delivery. Do not use for read-only questions, status reports, or diagnostics that make no project changes.
---

# ScorchKit pipeline

Keep workflow state in repository files and use `bin/pipeline.sh` for deterministic transitions.
Treat `CONSTITUTION.md` as binding and `AGENTS.md`, `SECURITY.md`, and
`docs/planning/ROADMAP.md` as required project context.

## Start or resume

1. Read the four documents above.
2. Run `bash bin/pipeline.sh doctor` and `bash bin/pipeline.sh status`.
3. Read active bulletins, search `docs/planning/knowledge/INDEX.md`, comparable completed pipeline
   notes, and relevant architecture docs. Summarize what changed the approach.
4. If an active pipeline exists, resume it. Never create a second active pipeline.
5. For an idea that is not ready to implement, run `bash bin/pipeline.sh intake SLUG TITLE...` and
   stop. For ready work, run `bash bin/pipeline.sh create SLUG TYPE TITLE...`.

## Run the phases

Edit the linked ticket, spec, notes, and AAR with concrete evidence before passing each phase.

1. Plan: make EARS requirements observable and scoped, seed the AAR recall log, record operator
   confirmation, then run `bash bin/pipeline.sh pass plan`.
2. Design: run `bash bin/pipeline.sh start design`; record architecture, file manifest,
   compatibility, security boundaries, and regression tests; obtain operator confirmation; pass
   design.
3. Implement: start implementation, make only confirmed changes, record deviations, and pass it.
4. Inspect: start inspection. Use independent correctness, security, data-integrity, and
   simplification critics when available; otherwise perform those labeled passes yourself. Record
   every finding and disposition, fix accepted findings, then pass inspection.
5. Validate: start validation; write and run relevant tests, then run `bash bin/gate.sh --diff`.
   An active ticket that satisfies the focused-repair amendment in `CONSTITUTION.md` §19 instead
   runs `bash bin/gate.sh --focused-repair`. The same mode may finish post-archive delivery for that
   closed ticket. If delivery exposes a source defect, preserve the prior input, prove the transition
   is limited to the repaired files, and mutate only the repaired functions. Record commands,
   outcomes, and receipt mode. Pass validation only while its receipt and bound evidence match the
   worktree.
6. Complete: start completion; update durable docs and changelog, submit the AAR (`status:
   submitted`, date, effectiveness), update the notes, and run `bash bin/pipeline.sh pass complete`.
   This archives the pair and closes the ticket.
7. Delivery: rerun the same approved receipt-producing gate because archival invalidates the
   validation receipt. Confirm `bash bin/pipeline.sh receipt`. Commit or open a PR only when the user
   authorized it.

Use `bash bin/pipeline.sh start PHASE` and `bash bin/pipeline.sh pass PHASE` for transitions. Do not
hand-edit phase status or move active artifacts manually.

## Integrity rules

- Run Cargo commands sequentially. Do not kill a running Cargo command.
- Never lower a floor, add a baseline, broaden an exclusion, suppress a diagnostic, delete a test,
  or introduce a silent skip to obtain green.
- Treat the quality tool's exit status and generated receipt as evidence; prose is not evidence.
- Keep scanner effects inside `SECURITY.md` authorization boundaries.
- Capture new reusable lessons in both the current AAR and knowledge register.
- Leave the pipeline active when blocked; report the exact missing evidence or authority.

For status or repair, run `bash bin/pipeline.sh check`, `doctor`, `status`, or `receipt` and fix the
reported invariant rather than bypassing the script.
