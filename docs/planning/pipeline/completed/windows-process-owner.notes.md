---
title: Add Windows Job Object process ownership — notes
pipeline_id: a81bce64-b43b-4a12-a121-6be485404508
---

# Add Windows Job Object process ownership — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-bounded-process-exit-race-001`: preserve the Unix termination classifier and
    return genuine live-owner errors rather than hiding or waiting indefinitely on them.
  - `PR-scorchkit-cancellation-whole-lifecycle-001`: cancellation and future drop must tear down
    the process effect before a caller can publish success.
  - `PR-scorchkit-policy-before-effects-001`: this ticket changes ownership after the existing
    policy-sealed invocation boundary; it does not create a new scanner or authorization path.
  - `PR-scorchkit-supported-host-semantic-assertions-003`: cross-host tests must assert process and
    filesystem semantics instead of platform-specific display details.
  - `rustal-quality-workflow.notes.md`: direct-child cleanup was a high-severity gap; one-shot and
    Interactsh paths must retain the same whole-tree owner across every terminal lifecycle.
  - `shared-job-executor.notes.md`: active process futures are cancelled by drop, so the Windows
    owner itself must be RAII and must cover adjacent long-lived process paths.
  - `docs/architecture/{runner,executor,tools,workspace}.md`: `scorchkit-tools` is the single owner
    of bounded process invocation, output, cancellation, and platform ownership.
- Recon evidence:
  - The current `OwnedProcessGroup` configures `process_group(0)` and owns a Unix PGID; its
    non-Unix branch is a no-op and `stop_owned_process` kills only the direct child.
  - The root crate has an explicit non-Unix compile error, and every current CI job uses Ubuntu.
  - Both `SystemToolExecutor` and `InteractshSession` directly spawn Tokio children and then attach
    the Unix guard, so both must move to the same platform-owned child seam.
  - The selected safe Windows wrapper creates the child with `CREATE_SUSPENDED`, assigns it to an
    owned Job Object, resumes it after assignment, terminates the Job Object on stop, and supports
    kill-on-close through an RAII handle.
  - Normal coordination must wait on the direct child rather than all Job members so a successful
    parent with a surviving descendant can be cleaned up and still reported as success.
- Operator confirmation: the owner's request to take and finish the next three roadmap tickets
  confirms SK-045's bounded plan and design. Windows-specific scanner behavior, weaker cleanup,
  and a broad FULL gate remain out of scope.

## Phase 2 — Design

- Architecture:
  - Add an `OwnedProcess` in `scorchkit-tools`. On Unix it contains the existing Tokio child and
    `OwnedProcessGroup`; on Windows it contains a safe wrapped Tokio child whose outer Job Object
    owner has kill-on-close and whose direct child also has kill-on-drop.
  - A single `spawn_owned_process` accepts the fully configured Tokio command. Unix configures a
    new process group before spawn. Windows applies kill-on-drop and Job Object wrappers; the Job
    wrapper sets `CREATE_SUSPENDED`, assigns ownership, and resumes only after success.
  - Normal I/O uses `OwnedProcess::wait`, which observes only the direct child on both platforms.
    `stop_owned_process` signals the Unix process group or Windows Job Object, waits for the direct
    child, and on Windows also awaits the Job completion event under the two-second bound.
  - Missing stdout/stderr, read/write failure, timeout, output/artifact overflow, nonzero exit,
    explicit stop, and future/owner drop all retain the same RAII owner. Ownership setup errors map
    to the existing typed `ToolFailed` infrastructure status before any suspended child runs.
  - `SystemToolExecutor` and `InteractshSession` consume only the provider-neutral owner. Scanner,
    policy, invocation, evidence, and serialized result types do not gain Windows-specific fields.
- File manifest:
  - Add a Windows-target-only safe process-wrapper dependency in
    `crates/scorchkit-tools/Cargo.toml` and update `Cargo.lock`.
  - Refactor `crates/scorchkit-tools/src/lib.rs` around `OwnedProcess`, platform spawn/wait/stop,
    injected pre-resume failure coverage, and Windows lifecycle fixtures while preserving Unix
    owner code and tests.
  - Update `src/runner/subprocess.rs` compatibility exports and `src/engine/oob.rs` to use the same
    owned child for long-lived sessions and Windows explicit-stop/drop tests.
  - Remove only the obsolete Windows compile block in `src/lib.rs`; retain an error for unsupported
    non-Unix/non-Windows targets.
  - Add native Windows workspace Clippy/test coverage to `.github/workflows/ci.yml` and pin that
    lane in `tests/quality_gate_contract.rs`.
  - Update `SECURITY.md`, `README.md`, `CHANGELOG.md`, current architecture, getting-started,
    tutorial, roadmap, and pipeline artifacts from the Unix-only boundary to Linux/macOS/Windows
    parity. Historical closed tickets and sealed security reports remain unchanged.
- Regression test plan:
  - Preserve and rerun every existing Unix group termination, exit-race, timeout, output, artifact,
    OOB stop/drop, and shared-executor cancellation test.
  - On Windows, use the current test executable as a local child/descendant fixture and query only
    local process state. Cover successful parent exit, nonzero exit, timeout, output overflow,
    artifact overflow, direct explicit stop, and dropped execution future; each descendant must
    disappear within two seconds.
  - Inject a setup failure after suspended spawn but before Job Object assignment/resume; assert a
    typed infrastructure error and that the child never creates its side-effect marker.
  - Assert Windows stdin/stdout/stderr and accepted-exit behavior through `SystemToolExecutor` and
    run the complete workspace test suite on `windows-latest`.
  - Cross-compile/check the Windows target locally where available, run focused package/root tests,
    then `bash bin/gate.sh --fast`. Validation and post-archive delivery each run the ordinary
    database-backed `bash bin/gate.sh --diff`.

## Phase 3 — Implement

- Files and behavior changed:
  - Added the Windows-target-only `process-wrap` dependency with `job-object`, `kill-on-drop`, and
    Tokio support. `scorchkit-tools::OwnedProcess` now owns the existing Unix group or a Windows
    wrapped child; Windows spawn is suspended, assigned to the Job Object, and resumed only after
    ownership succeeds.
  - Routed `SystemToolExecutor` and `InteractshSession` through the same owned spawn/stop seam.
    Normal completion waits for the direct child, then terminates and reaps the complete owned tree,
    preserving successful-parent semantics when a descendant remains alive.
  - Added Windows fixtures for stdin/stdout/stderr and accepted exits; success, nonzero, timeout,
    output overflow, artifact overflow, future drop, explicit stop, Interactsh stop/drop, and forced
    pre-resume ownership failure. Every descendant assertion has a two-second bound.
  - Replaced the root Windows compile rejection with an unsupported-platform rejection, added a
    native `windows-latest` workspace Clippy/test job and its repository contract test, and updated
    current support/security/architecture/operator documentation.
  - Cleaned existing Windows-only unused/no-op compilation branches exposed by workspace Clippy.
    Unix permission and same-filesystem checks are unchanged; Windows paths now at least verify
    existence, and snapshot promotion compares canonical volume prefixes.
- Design deviations:
  - None in the ownership design. Local validation cross-compiles the complete workspace because
    the build host is Linux; the configured native Windows CI job owns executable Job Object proof.
- Development evidence:
  - `cargo test -p scorchkit-tools --all-features`: 31 passed.
  - `cargo test --lib engine::oob --all-features`: 18 passed.
  - `cargo clippy --workspace --all-targets --all-features --target
    x86_64-pc-windows-gnu -- -D warnings`: green.
  - `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --fast`: 14 passed,
    0 failed, 8 mode-defined skips.
  - The first FAST run exposed platform-specific Clippy signatures and a spelling-lane collision
    with the Windows task-list output-format flag. The source was split by platform and the flag
    assembled without a false-positive token; the full FAST gate then passed.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | API/security | The compatibility `OwnedProcessGroup` and `configure_owned_process_group` still existed as empty/no-op public hidden types on Windows, leaving a misleading direct-spawn seam beside the fail-closed owner. | medium | Fixed: both legacy group APIs now exist only on Unix; Windows exposes only `spawn_owned_process`, which cannot return an unowned child. |
| 2 | Reliability | The timeout fixture started its five-second lifecycle only after awaiting execution, so an overloaded native runner could time out before the nested descendant published its PID and produce a fixture failure instead of cleanup evidence. | medium | Fixed: the test polls the PID concurrently with execution, rejects premature completion, then awaits the configured timeout and cleanup. Fixture acquisition is bounded separately from the two-second exit assertion. |
| 3 | Test integrity | Libtest's own Windows child-process preamble could consume a tiny 64-byte stdout budget before the output fixture spawned and recorded its descendant. | medium | Fixed: the output-overflow test reserves 4 KiB for harness output; the fixture records the descendant before deliberately producing unbounded output. |
| 4 | Dependency | A Windows process dependency could accidentally enter the Unix build graph or introduce repository `unsafe` source. | high | Verified absent: `process-wrap` is target-scoped, the Linux dependency tree excludes it, Cargo deny/audit are green, and repository source remains `unsafe`-free. |
| 5 | Lifecycle/security | Waiting through the outer Job wrapper during normal execution would block on descendants and turn a successful parent with a lingering child into a timeout. | high | Verified absent: normal wait intentionally reaches the wrapped direct Tokio child; only cleanup terminates the Job and awaits the outer completion port. Success-with-descendant has a dedicated Windows fixture. |
| 6 | Test integrity | The first DIFF mutation run enumerated native-Windows bodies in a Linux executable and treated every target-inactive rewrite as a survivor, obscuring the host-active score. | high | Fixed: native-Windows process and filesystem bodies live in two target-only modules with exact file exclusions documented in `.cargo/mutants.toml`; Windows cross-Clippy and the required native CI runtime lane retain their proof, while every host-active library file remains in mutation scope. |
| 7 | Mutation quality | Unix stdin and direct-child identity accessors had only indirect coverage, and the explicit `OwnedProcess::drop` body was behaviorally redundant with the inner group guard's drop. | medium | Fixed: a direct pipe/PID contract kills `None`, zero, and one substitutions; the redundant explicit drop was removed, the group field was ordered before the direct child to preserve descendant-first implicit destruction, and a direct owner-drop descendant test pins that ordering. |

- Repair verification:
  - Windows-target workspace Clippy remained green with all features and targets.
  - Linux `scorchkit-tools` (31 tests) and OOB (18 tests) lifecycle suites remained green.
  - `bash bin/mutants.sh --inspect` found 9,783 configured mutants across 298 workspace source
    files and confirmed the composition binary exclusion and policy-kernel inclusion.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo clippy --workspace --all-targets --all-features --target
    x86_64-pc-windows-gnu -- -D warnings`: green after the mutation-focused extraction.
  - `cargo test -p scorchkit-tools --all-features`: 33 passed, including direct pipe/PID and
    implicit-drop descendant lifecycle contracts.
  - `bash bin/mutants.sh --inspect`: 9,766 configured mutants across 298 source files; composition
    binary excluded and policy kernel included.
  - `bash bin/gate.sh --fast`: 14 passed, 0 failed, 8 mode-defined skips after the focused repair.
- Gate run and receipt:
  - The first `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff`
    passed 18 lanes and failed only mutation at 36.36%: 12 caught, 21 missed, 9 unviable. The
    misses identified five Windows filesystem branches, inactive Windows process bodies, direct
    Unix accessor assertions, and one equivalent explicit-drop body. Coverage, 1,929 strict tests,
    100 PostgreSQL tests, and CLI/MCP contracts were green in that diagnostic run.
  - After the focused source/test repair, the same DIFF command passed 19 lanes with 0 failures and
    3 web-only skips. Line coverage was 84.58%; mutation was 100% with 16 caught, 0 missed, and 9
    unviable; strict Nextest passed 1,931 tests with 10 reasoned skips; PostgreSQL passed 77 MCP,
    12 storage, and 11 storage-integration tests; CLI/MCP contracts passed.
  - Receipt: version 2 DIFF receipt for worktree
    `bf2c40e2038e8865cc905f8bfdc92eca4ad82fbfa170f99d7ab7b32126562edd`. These validation-note
    edits intentionally require the ordinary DIFF gate to issue a fresh exact-worktree receipt
    before `pass validate`.
- Documented skips with reasons:
  - Gates 17–19 are the repository's explicit web-only skips because ScorchKit has no web UI or
    asset pipeline.
  - Native Windows Job Object execution is unavailable on this Linux host. The complete workspace
    cross-Clippy build is green for `x86_64-pc-windows-gnu`; the required `windows-latest` CI job
    executes the lifecycle suite on the next pushed branch. No push is part of this local delivery.

## Phase 5 — Complete

- Docs updated: README, security policy, changelog, host and process architecture, getting-started
  guide, tutorial, roadmap, ticket, CI contract, mutation policy, validation evidence, and operator
  contracts consistently describe Linux/macOS process groups and Windows kill-on-close Job
  Objects behind the same bounded owner.
- AAR submitted: `AAR-023-windows-process-owner` on 2026-08-22 with effectiveness 5/5; three
  reusable prevention rules and three failure patterns are registered in the knowledge index.
- Archive: pending the repository-owned completion transition and post-archive exact-tree DIFF
  receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first FAST attempts exposed Windows-target Clippy failures and a spelling false positive in a Windows command-line flag. | Unix-only helper signatures and imports had accumulated inactive Windows branches, while the spelling lane matched a tool flag token without understanding command semantics. | Split helpers by platform, removed unused Windows branches, and assembled the reviewed flag without adding a broad spelling exception. | Cross-compile every target with workspace/all-target/all-feature Clippy and keep static exceptions narrower than the affected source expression. |
| 2 | The first DIFF gate reported 36.36% MSI with 21 survivors concentrated in native-Windows bodies that a Linux executable cannot observe. | Host-exclusive implementations remained in files selected by the Linux mutation run, so cargo-mutants rewrote source that was compiled out by `cfg(windows)`. | Extracted process and filesystem implementations into two exact target-only modules and excluded only those paths; native Windows Clippy and the required Windows CI runtime lane retain proof, while all host-active library files remain selected. | Use `PR-scorchkit-target-inactive-mutation-files-001` and assert the exact exclusion list in the quality-gate contract. |
| 3 | Unix pipe/PID mutations survived, and an explicit outer `Drop` was equivalent to the inner process-group guard's cleanup. | Accessors were covered only indirectly, and duplicate cleanup ownership hid the meaningful Rust field-destruction contract. | Added direct pipe/identity tests, removed the redundant outer `Drop`, declared the group owner before the child, and added a drop-time descendant fixture. | Use `PR-scorchkit-owned-process-accessor-contract-001` and `PR-scorchkit-descendant-owner-drop-order-001`. |
