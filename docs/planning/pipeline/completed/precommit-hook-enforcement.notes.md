---
title: Restore executable pre-commit receipt enforcement — notes
pipeline_id: fb1c97e3-8c91-464e-afc3-198ce35ebecb
---

# Restore executable pre-commit receipt enforcement — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `CONSTITUTION.md` §§0, 3, 15, and 19; `SECURITY.md`; roadmap delivery rules;
  `PR-scorchkit-gate-worktree-scope-001`; `PR-scorchkit-test-shell-fixtures-001`;
  `PR-scorchkit-ticket-diff-baseline-001`; `PR-scorchkit-focused-mutation-repair-001`; TICKET-001
  receipt and hook rationale; TICKET-008 delivery observation.
- Recon: the index records `.githooks/pre-commit` as `100644`; the native server checkout records
  `0644`; the SMB client reports synthetic `0700`; `doctor` checks only `core.hooksPath`; the current
  hook selftest calls the hook through Bash rather than through Git.
- Operator confirmation: on 2026-08-19 the owner directed removal of the obsolete Codex CLI and to
  start the next ticket. The delivery-hook defect already reported at the TICKET-008 commit is being
  handled as the narrow prerequisite before SK-035.

## Phase 2 — Design

- Architecture: add one side-effect-free hook-readiness function to `bin/pipeline.sh`. It resolves
  the configured hook path, requires the canonical `.githooks` path, requires a regular tracked
  `.githooks/pre-commit` entry with index mode `100755`, and requires the current checkout to expose
  it as executable. `doctor` renders the function's specific reason and fails closed. Receipt
  creation and verification remain owned by `bin/gate-state.sh` and are unchanged.
- Git invocation proof: extend `.githooks/pre-commit --selftest` after its receipt-integrity cases.
  The fixture installs the real hook and gate-state helper under its temporary repository, wires
  `core.hooksPath`, stages a change against a stale receipt, and calls `git commit`. The negative arm
  accepts only a nonzero commit whose captured output contains ScorchKit's `COMMIT BLOCKED` message;
  the positive arm writes a current receipt and requires the next real commit to succeed.
- Pipeline diagnostic proof: extend `bin/pipeline.sh selftest` with a temporary Git repository that
  proves `doctor` rejects an untracked hook, rejects index mode `100644`, and accepts mode `100755`
  only when the worktree file is executable. This exercises the public diagnostic rather than a
  textual implementation check.
- File manifest: `.githooks/pre-commit` (tracked mode plus Git-level integration fixture),
  `bin/pipeline.sh` (readiness check, doctor wiring, selftest cases), TICKET-009's ticket/spec/notes,
  `AAR-009`, the knowledge index if inspection yields a reusable rule, and `CHANGELOG.md` at
  completion. No Rust source, Rust tests, manifests, migrations, scanner code, or receipt helper
  changes are planned.
- Regression test plan: `shellcheck -x bin/pipeline.sh .githooks/pre-commit`;
  `bash .githooks/pre-commit --selftest`; `bash bin/pipeline.sh selftest`;
  `bash bin/pipeline.sh doctor`; `bash bin/gate.sh --fast`; native-server index/stat/readiness checks;
  then `bash bin/gate.sh --diff` for the exact-tree delivery receipt. The full gate and
  repository-wide mutation scan remain excluded. Because no mutation-relevant input changes, the
  DIFF mutation lane is expected to select no Rust mutation scope.
- Rollback: revert the hook mode and the two shell-script changes together. There is no persistent
  data or schema migration.
- Operator confirmation: on 2026-08-19 the owner directed ScorchKit to move onto the next ticket
  after reviewing the design and the trusted-model architecture. This advances TICKET-009 into its
  confirmed implementation scope.

## Phase 3 — Implement

- Files and behavior changed: `.githooks/pre-commit` is tracked as mode `100755` and its selftest
  now installs the real hook and receipt helper in a disposable repository, stages a change, calls
  `git commit`, and requires ScorchKit's stale-receipt denial. `bin/pipeline.sh` now distinguishes a
  configured hook from a ready hook by checking the exact hooks path, regular-file shape, one
  tracked index entry, index mode `100755`, and current checkout execute permission. Its public
  selftest covers missing, untracked, non-executable-index, non-executable-checkout, and ready states.
- Focused outcomes: ShellCheck passed for both changed scripts; the hook selftest proved direct
  receipt behavior and real Git invocation; the pipeline selftest passed all new negative and
  positive doctor cases; the mounted checkout reports `commit hook: ready`.
- Native checkout: `/srv/stacks/scorchkit` reports index mode `100755`, filesystem mode `0755`, and
  `commit hook: ready`. Its complete doctor command remains red only because the non-interactive SSH
  environment does not put Cargo on `PATH`; hook readiness itself passed.
- Design deviations: none. Receipt format, hashing, gate modes, Rust inputs, scanner behavior, and
  authorization policy are unchanged.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | The Git-level fixture supplied `SCORCHKIT_PROJECT_ROOT`, receipt, and helper paths, so it could hide a defect in the hook's normal repository and helper discovery. | medium | Fixed: removed all three overrides. The copied hook now resolves the fixture root, canonical helper, and default receipt path exactly as production does; the real Git commit denial still passes. |
| 2 | Security | The readiness check must not accept a symlink, a similarly named untracked file, multiple conflicted index stages, mode `100644`, or a checkout that cannot execute the hook. | high | Verified: regular-file and symlink checks, exact single-entry count, exact `100755` mode, and checkout `-x` are independently enforced; selftests cover each observable failure class. |
| 3 | Data integrity | The macOS SMB view reports synthetic execute bits that disagree with both the native server and the portable Git index. | high | Fixed by design: the index mode is authoritative for future checkouts and current checkout executability is a separate condition. Native server and mounted-client readbacks both pass. |
| 4 | Simplification | Replacing the old hooks-path diagnostic removed its repair command even though the new check had one owner and could preserve it cheaply. | low | Fixed: the exact-path failure again instructs the operator to run `git config core.hooksPath .githooks`; no parallel readiness implementation was added. |
| 5 | Receipt boundary | The versioned receipt binds content rather than staged index metadata, matching the existing rule that staging does not change a receipt. | informational | Accepted: this ticket does not change receipt semantics. The pipeline requires readiness checks and exact index/native readback before delivery; the hook remains an integrity discipline rather than a sandbox against deliberate `--no-verify` or index plumbing. |
| 6 | Dependency security | The live advisory database began rejecting transitive `h2` 0.4.15 during validation for `RUSTSEC-2026-0258`. | low | Fixed: `Cargo.lock` alone advances `h2` to the first compatible patched release, 0.4.16. No manifest or application-source dependency changed; all-feature tests, cargo-audit, and cargo-deny pass on the resulting graph. |
| 7 | Delivery correctness | A current receipt verified successfully, but normal Git invocation still exited 1 because the hook's final `[ "$1" = "--verify-only" ] && echo ...` conditional supplied the script's exit status. The integration fixture covered only stale-receipt rejection, so it could not detect this false rejection. | high | Fixed: successful verification now reaches explicit `exit 0`, and the same real-Git fixture must reject the stale receipt and accept a freshly written current receipt. |
| 8 | Host portability | The real executable-path test required a resolved `sh` path to end in `/sh`, but Ubuntu resolves `/bin/sh` to `/usr/bin/dash`. | medium | Fixed: retain the behavior contract by requiring an absolute existing file and a missing-tool negative, without assuming the target filename of a valid system symlink. |
| 9 | Shell portability | The focused-evidence verifier declared but did not initialize optional follow-up paths; Bash 5.2 with `set -u` rejected the no-follow-up branch before its selftest could run. | medium | Fixed: initialize both optional paths to empty strings and retain the existing guarded follow-up behavior. |
| 10 | Mutation result integrity | cargo-mutants successfully selected no mutants for the test-only Rust diff and emitted no output directory, but the runner required `outcomes.json` before recognizing the completed empty result. | medium | Fixed: only DIFF status 0 with an absent outcomes file becomes explicit empty evidence. Full, failed, and malformed results remain rejected, and a selftest proves all four branches. |
| 11 | Parallel lifecycle test | The active-ownership cleanup test waited two seconds for a broader persisted running state, so parallel load could exhaust the budget before it observed the ownership token the test actually asserts. | medium | Fixed: observe the active token directly and use a ten-second orthogonal harness budget; the exact test and parallel 1,041-test root-library lane pass. |
| 12 | Process fixture readiness | The PID helper parsed immediately after the shell created its output file, allowing a read between truncate and write to parse an empty string. | medium | Fixed: accept readiness only after trimmed content parses as a positive PID; the exact descendant cleanup test and parallel root-library lane pass. |

## Phase 4 — Validate

- Tests run (commands and outcomes): `shellcheck -x bin/pipeline.sh .githooks/pre-commit`
  passed; `bash .githooks/pre-commit --selftest` passed the direct receipt cases and the real Git
  stale-commit denial; `bash bin/pipeline.sh selftest` passed all pipeline lifecycle fixtures and
  the new hook-readiness matrix; `git diff --check` passed. Mounted-checkout doctor reports
  `commit hook: ready`; the native checkout reports index mode `100755`, filesystem mode `0755`,
  and the same ready diagnostic.
- Gate history: a development `bash bin/gate.sh --fast` attempt reached the
  workspace test lane, then its `scorchkit_tools` test executable remained asleep before entering
  the Rust runtime. After more than two hours at zero CPU, the owner explicitly directed termination
  and continuation. Only the exact frozen test child received `SIGTERM`; Cargo and the gate unwound
  normally. The attempt finished red because the terminated test lane had no verdict and because
  the live advisory database newly rejected locked `h2` 0.4.15 under `RUSTSEC-2026-0258`. This run
  is diagnostic evidence only, not validation evidence.
- Validation-only repair: update the single transitive `h2` lockfile entry to compatible patched
  release 0.4.16 without changing dependency manifests or application source, then rerun the FAST
  gate from a fresh target directory. This is a gate-unblocking security repair discovered after
  implementation; it does not expand scanner behavior or mutation scope.
- Clean FAST gate: `CARGO_TARGET_DIR=/tmp/scorchkit-t9-fast.RtuL0V` with the validation database
  completed green: 14 passed, 0 failed, and 8 mode/not-applicable skips. The all-feature suite,
  including all 21 `scorchkit-tools` tests, completed normally; cargo-audit and cargo-deny both
  accepted `h2` 0.4.16. Coverage, mutation, strict Nextest, PostgreSQL, and CLI/MCP contracts were
  skipped only because FAST mode does not run delivery-tier lanes.
- First clean DIFF attempt: 18 lanes passed, including 1,469 strict Nextest cases, PostgreSQL,
  coverage, and CLI/MCP contracts. The mutation lane failed before inventory or execution because
  its two-worker scratch guard required 48 GiB while only 13.3 GiB was free. No mutation was
  launched. The obsolete 51 GiB `/tmp/scorchkit-target-501` compiler cache that contained the
  terminated executable was deleted after its process chain exited; it held generated artifacts
  only and is recoverable by rebuilding. Local scratch then reported 64.2 GiB free for the final
  exact-tree DIFF rerun.
- Database readiness: local PostgreSQL accepts the existing
  `scorchkit_codex_validation_001` validation database. No database credential was added to the
  repository.
- Final validation: the exact-tree `bash bin/gate.sh --diff` rerun completed green with 19 passed,
  0 failed, and the three repository-defined web-only skips. The mutation lane passed after
  selecting no changed Rust lines; it did not launch cargo-mutants. Strict Nextest ran 1,469 tests,
  PostgreSQL integration ran 84 tests, and the CLI/MCP contract lane passed. The resulting DIFF
  receipt matched the worktree and was accepted by the pipeline's Validate transition.
- Documented skips with reasons: gates 17–19 are not applicable because ScorchKit has no web UI,
  website renderer, or CSS asset pipeline. The full gate and repository-wide mutation inventory
  remain out of scope under REQ-005 and the owner's focused-validation direction.

### Post-archive delivery repair

- The authorized `git commit` invoked the canonical hook and returned 1 with no denial message.
  Direct tracing proved receipt verification succeeded; the normal no-argument path then inherited
  the false status of its trailing `--verify-only` comparison.
- The initial hook repair changed `.githooks/pre-commit` plus this ticket's durable evidence. Later
  supported-host validation required one test-only Rust assertion and narrow shell portability
  repairs; no production Rust, manifest, migration, or scanner behavior changed.
- Regression proof now includes both real-Git outcomes: a stale receipt is blocked with the canonical
  message, while a current exact-tree receipt permits the commit.
- Moving validation to the new server NVMe also exercised the supported Linux host. Its first FAST
  run exposed one macOS-specific executable-name assertion and one uninitialized optional Bash
  value. Both received narrow portability repairs; no scanner effect or production Rust behavior
  changed.
- The server toolchain was aligned with the known-green local environment: Rust 1.96.0 and
  ShellCheck 0.11.0. The repaired server FAST rerun passed all 14 applicable lanes with zero
  failures and eight defined FAST-mode skips. Its Cargo target and temporary analysis paths were
  backed by `/mnt/fast`; no mutation lane runs in FAST mode.
- The first server DIFF run passed all 18 applicable non-mutation lanes. Gate 16 then exposed that a
  successful cargo-mutants empty selection creates no outcomes file: the changed Rust line is
  test-only, cargo-mutants reported `No mutants to filter` with status 0, and the runner incorrectly
  rejected the absent file.
- `bin/mutants.sh` now creates explicit zero-mutant evidence only for DIFF status 0 with no outcomes
  file. Its new selftest rejects the full, failed, and malformed counterparts. The focused real
  DIFF selection passed at 100% with 0 caught and 0 missed and launched no mutant compilation.
  Final delivery still uses the ordinary DIFF gate; a full or repository-wide mutation run remains
  forbidden by REQ-005 and the owner's direction.
- Repeated all-feature validation then reproduced two existing test races under parallel load: the
  job cleanup test exhausted an indirect two-second running-state wait, and the descendant fixture
  parsed a PID file between creation and content write. Both now observe their exact readiness
  contracts. Their exact tests and the parallel root-library lane passed with 1,041 tests green and
  four defined ignores.

## Phase 5 — Complete

- Docs updated: the changelog, ticket, pipeline evidence, AAR, and reusable knowledge index describe
  the executable-hook contract, diagnostic failure classes, real Git invocation proof, narrow
  advisory-driven lockfile repair, successful empty-DIFF mutation evidence, and supported-host
  readiness test hardening.
- AAR submitted: `AAR-009-precommit-hook-enforcement` records the inert-hook defect, inspection
  findings, validation interruption, prevention rule, and 5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-009 are ready for the pipeline-controlled archive. The
  archive changes the worktree, so delivery reruns the same DIFF gate. Its only changed Rust line is
  test-only; mutation selection therefore records an explicit empty result and launches no mutant
  compilation.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Git skipped the receipt hook while doctor reported it wired. | The hook was tracked as `100644`, and doctor checked only `core.hooksPath`. | Track mode `100755`; require canonical regular-file, index-mode, and checkout-execute readiness. | `BF-scorchkit-hook-wired-not-ready-001`; `PR-scorchkit-git-hook-execution-contract-001`. |
| 2 | The first Git fixture could bypass normal path discovery. | Test-only environment variables selected the root, receipt, and helper. | Remove overrides and run the copied hook at canonical fixture paths. | Test Git hooks through Git with production path resolution. |
| 3 | Git rejected a valid receipt without a denial message. | The hook had no explicit success exit, so its trailing false display conditional became the process status; the fixture tested only rejection. | Exit zero after successful verification and add the positive real-commit arm. | Every enforcement integration must prove both rejection and acceptance through the production entry point. |
| 4 | A successful empty DIFF mutation selection failed delivery. | cargo-mutants emits no outcomes file when no mutation-eligible production line intersects the diff, while the runner assumed every successful run creates one. | Normalize only DIFF status 0 with absent outcomes into explicit empty evidence and selftest the rejected counterparts. | `BF-scorchkit-empty-diff-mutation-artifacts-004`; `PR-scorchkit-empty-diff-mutation-evidence-004`. |
| 5 | Two tests failed only under the server's parallel all-feature lane. | They treated an indirect state or file existence as readiness instead of the exact ownership token or complete PID content. | Observe the asserted token directly with a bounded budget; require parseable positive PID content. | `BF-scorchkit-parallel-readiness-races-005`; `PR-scorchkit-exact-readiness-observation-005`. |
