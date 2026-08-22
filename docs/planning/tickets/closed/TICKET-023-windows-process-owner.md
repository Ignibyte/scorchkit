---
title: TICKET-023-windows-process-owner
status: done
ticket_number: 023
type: feature
created: 2026-08-22
closed: 2026-08-22
intake:
  - docs/planning/intake/INTAKE-windows-process-owner.md
pipeline_spec: docs/planning/pipeline/completed/windows-process-owner.spec.md
---

# Add Windows Job Object process ownership

## Summary

Enable Windows builds by giving every ScorchKit-owned external process a Windows Job Object with
kill-on-close semantics. The one-shot tool executor and long-lived Interactsh session create the
child suspended, establish descendant ownership, and resume it only after ownership succeeds while
preserving the existing Unix process-group implementation.

## Why

The external-process boundary already promises bounded whole-tree cleanup, but ScorchKit currently
rejects every non-Unix build because Windows lacks an equivalent owner. SK-045 is the next roadmap
item and closes that platform gap without weakening timeout, output, cancellation, policy, or
serialized result contracts.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the bounded tool executor or Interactsh launches a process on Windows, ScorchKit shall create it suspended, assign it and inheriting descendants to an owned kill-on-close Job Object, and resume it only after ownership succeeds. | Windows pre-resume marker test, process-tree fixture, and implementation inspection. |
| REQ-002 | When a Windows-owned process succeeds, exits nonzero, times out, is cancelled, exceeds an output or artifact limit, is explicitly stopped, or loses its owner, ScorchKit shall terminate and release its descendants within two seconds. | Windows lifecycle matrix using a child-and-descendant fixture and bounded process-state assertions. |
| REQ-003 | When Windows Job Object ownership cannot be established, ScorchKit shall return a typed infrastructure failure before the suspended process performs scanner work. | Forced ownership-setup failure with an absent side-effect marker. |
| REQ-004 | When the same bounded invocation runs on Windows or Unix, ScorchKit shall preserve executable resolution, stdin, stdout, stderr, exit-policy, timeout, output-limit, artifact-limit, and `ToolOutput` serialization behavior. | Cross-platform executor contract fixtures and existing Unix lifecycle suite. |
| REQ-005 | When the supported workspace is built and tested in CI, ScorchKit shall compile on Windows and execute the Windows process-owner lifecycle suite. | Required `windows-latest` workspace Clippy/test job plus local Windows-target compilation. |

## Scope

- In: a platform-owned child abstraction in `scorchkit-tools`; Windows suspended spawn and Job
  Object ownership; one-shot and Interactsh lifecycle integration; forced ownership-failure and
  descendant-cleanup tests; Windows workspace CI; supported-host documentation.
- Out: Windows-specific scanners or UI; weaker cleanup, timeout, output, artifact, policy, or audit
  semantics; changes to process result schemas; replacement of the proven Unix process-group
  backend; support for non-Unix, non-Windows targets.

## Locked decisions

- Keep Unix process-group creation and its bounded exited-child race handling unchanged.
- Use a Windows-target-only safe Rust process wrapper; ScorchKit source remains `unsafe`-free.
- On Windows, apply direct-child kill-on-drop and Job Object kill-on-close before spawn; resume the
  suspended child only after Job Object assignment succeeds.
- Treat a Job Object setup error as an infrastructure failure and never fall back to direct-child
  ownership.
- Keep the two-second descendant cleanup contract and every public/serialized tool result stable.
- Add a native Windows CI lane; ordinary validation remains the canonical DIFF gate, not FULL or
  focused repair.
- The owner's request to finish the next three roadmap tickets confirms this bounded plan and
  design.

## Recon

- The current owner is an RAII Unix process-group guard in `scorchkit-tools`; its non-Unix branch
  can kill only the direct child, and the root crate deliberately rejects non-Unix compilation.
- `SystemToolExecutor` and `InteractshSession` are the two process lifecycles that must share the
  platform owner. Both already use Tokio piped I/O and direct-child kill-on-drop.
- `PR-scorchkit-bounded-process-exit-race-001` requires termination errors to remain observable and
  bounds only a proven exited-child Unix race.
- `PR-scorchkit-cancellation-whole-lifecycle-001` requires owner drop to cover active subprocess
  effects before success can be published.
- The selected Windows wrapper uses `CREATE_SUSPENDED`, `AssignProcessToJobObject`, a
  kill-on-close Job Object, and explicit resume behind a safe dependency API. This closes the
  descendant-escape window without adding local unsafe code.
- Current CI executes only Ubuntu jobs, so source compatibility alone cannot prove the Windows
  lifecycle contract.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/windows-process-owner.spec.md`

## Log

- 2026-08-22: opened.
- 2026-08-22: promoted `INTAKE-windows-process-owner.md` as SK-045 and recorded the owner's
  next-three delivery request as plan and design confirmation.
