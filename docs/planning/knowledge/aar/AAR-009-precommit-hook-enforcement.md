---
aar: AAR-009-precommit-hook-enforcement
ticket: TICKET-009
pipeline: precommit-hook-enforcement
status: submitted
opened: 2026-08-19
submitted: 2026-08-19
effectiveness: 5
---

# AAR-009 — Restore executable pre-commit receipt enforcement

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `CONSTITUTION.md` §§0, 3, 15, and 19 | Mandatory delivery workflow and owner's focused-mutation constraint. | yes — limits this repair to the enforcement boundary and forbids an unnecessary broad scan. |
| `PR-scorchkit-gate-worktree-scope-001` | The worktree and Git metadata can have different scope and semantics. | yes — led to checking index mode separately from SMB-presented filesystem mode. |
| `PR-scorchkit-test-shell-fixtures-001` | Existing tests intentionally invoke scripts through Bash when execute permission is not their contract. | yes — showed why those tests could not prove Git hook discoverability. |
| `PR-scorchkit-ticket-diff-baseline-001` | The next ticket needs a trustworthy canonical delivery boundary. | yes — made this defect a prerequisite instead of carrying it into SK-035. |
| `PR-scorchkit-focused-mutation-repair-001` | Do not repeat broad mutation inventories after focused changes. | yes — this shell-only ticket is limited to focused checks and the DIFF gate. |
| TICKET-001 and AAR-001 | Original receipt and pre-commit enforcement design. | yes — preserves receipt semantics while repairing activation and diagnostics. |
| TICKET-008 delivery | Git warned that `.githooks/pre-commit` was ignored because it was not executable. | yes — supplied the concrete failing native-checkout case. |

## What happened

- TICKET-008's commit exposed that Git had skipped `.githooks/pre-commit`: the index and native
  server checkout recorded a non-executable hook even though pipeline diagnostics reported it
  wired.
- The hook is now tracked as `100755`; the native server checkout reports `0755`; and the pipeline
  doctor distinguishes the configured hook path from a regular, tracked, executable canonical hook.
- The hook selftest now installs the real hook and receipt helper in a disposable repository and
  requires Git itself to reject a commit with a stale receipt and accept one with a current receipt.
- Focused ShellCheck, hook, pipeline, mounted-checkout, and native-checkout checks passed without
  changing Rust mutation inputs or launching a broad mutation inventory.

## Novel findings

- The SMB client presented synthetic mode `0700` while the same server file and Git index were
  `0644` and `100644`. Filesystem executability on that client could not represent checkout
  portability; the Git index had to be checked separately.
- `core.hooksPath=.githooks` proves only configuration. A missing, untracked, non-executable, or
  symlinked canonical hook can still leave enforcement inert.
- A Git-level fixture that injects project-root and helper paths can hide defects in the normal hook
  discovery path. Inspection removed those overrides so the test exercises production resolution.
- A rejection-only enforcement fixture can remain green while the hook rejects every operation.
  Delivery exposed that successful verification inherited a false trailing conditional as the hook
  process status; the integration now proves both rejection and acceptance through Git.
- Supported-host tests must assert executable properties rather than the final filename behind a
  system symlink: Ubuntu resolves `sh` to `dash`. Optional shell locals read under `set -u` must be
  initialized even when their branch is normally absent.
- cargo-mutants exits successfully and creates no outcomes file when a DIFF contains Rust changes
  but no mutation-eligible production line. Empty-selection evidence must be synthesized only from
  that exact successful DIFF state; otherwise missing or malformed evidence remains a failure.
- Parallel tests must wait for the exact readiness condition they assert. A broad lifecycle state
  with a two-second budget did not prove active ownership, and PID-file existence did not prove the
  shell had finished writing parseable content.
- A frozen test executable can prevent a gate from reaching its summary while external advisory
  state continues to change. After the owner-directed termination, the gate exposed a newly
  published `h2` advisory; a clean build proved the loader freeze was stale-process state rather
  than a failing `scorchkit-tools` test.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-hook-wired-not-ready-001` | Pipeline diagnostics called the hook wired when only `core.hooksPath` matched; the canonical hook was tracked and checked out without execute permission, so Git skipped it. | TICKET-008 commit warning, native `stat`, Git index inspection, and TICKET-009 recon. |
| `BF-scorchkit-hook-valid-receipt-rejected-002` | The hook verified a current receipt but returned status 1 because its trailing display conditional was false during normal Git invocation. | Authorized TICKET-009 delivery commit and direct hook trace. |
| `BF-scorchkit-linux-portability-validation-003` | Linux FAST validation rejected a valid `sh` symlink target name and an unset optional evidence path that macOS did not expose. | Server-side TICKET-009 FAST gate on Rust 1.96.0 and Bash 5.2. |
| `BF-scorchkit-empty-diff-mutation-artifacts-004` | A successful cargo-mutants empty DIFF selection emitted no outcomes file, and the runner rejected it before recording explicit zero-mutant evidence. | Server-side TICKET-009 DIFF gate and focused `bin/mutants.sh --diff` reproduction. |
| `BF-scorchkit-parallel-readiness-races-005` | Existing lifecycle and process-fixture tests used indirect or incomplete readiness signals, failing under server parallel load while passing alone. | Repeated server all-feature root-library runs; exact-test reproductions passed in isolation. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-git-hook-execution-contract-001` | Prove a repository hook through Git using its canonical checkout paths, and diagnose configured path, tracked mode, and checkout executability as separate readiness conditions. | Direct Bash invocation and a matching hooks-path setting did not prove Git could discover or execute the enforcement hook. |
| `PR-scorchkit-enforcement-two-arm-proof-002` | Every enforcement integration shall prove both a rejected invalid case and an accepted valid case through the production entry point. | A stale-receipt-only fixture passed while the hook rejected current receipts too. |
| `PR-scorchkit-supported-host-semantic-assertions-003` | Cross-host tests shall assert executable and filesystem semantics, not a platform-specific symlink target name, and shell optionals read under `set -u` shall be initialized. | Ubuntu's `sh` resolves to `dash`, and Bash 5.2 rejects declared-but-unset locals. |
| `PR-scorchkit-empty-diff-mutation-evidence-004` | Normalize missing mutation outcomes only when cargo-mutants returned status 0 in DIFF mode; persist an explicit empty result and reject full, failed, or malformed counterparts. | A test-only Rust diff produced a valid empty selection but no cargo-mutants output directory. |
| `PR-scorchkit-exact-readiness-observation-005` | In parallel async and process fixtures, wait on the exact asserted condition with an orthogonal bounded budget; a readiness file is ready only when its content is complete and valid. | A lifecycle-state proxy timed out before ownership observation, and an existing but empty PID file was parsed. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5/5. Recalled receipt, worktree-scope, shell-fixture, diff-baseline, and focused-mutation rules kept
the repair narrow while exposing the distinction between hook configuration and executable hook
readiness. Delivery itself found the missing positive hook contract; server FAST then exposed two
portable-test gaps, one successful-empty mutation evidence gap, and two parallel readiness races.
The two-arm hook fixture, repaired Linux tests, and focused empty-DIFF proof are green, production
Rust and scanner effects are unchanged, and the final ordinary DIFF receipt remains the delivery
authority.
