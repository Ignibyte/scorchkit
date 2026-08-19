---
title: TICKET-009-precommit-hook-enforcement
status: done
ticket_number: 009
type: bug
created: 2026-08-19
closed: 2026-08-19
intake:
pipeline_spec: docs/planning/pipeline/completed/precommit-hook-enforcement.spec.md
---

# Restore executable pre-commit receipt enforcement

## Summary

Restore Git-enforced delivery receipts by tracking the ScorchKit pre-commit hook as executable,
making pipeline diagnostics reject an inert hook, and testing the hook through a real Git commit.

## Why

TICKET-008 exposed that `.githooks/pre-commit` was tracked as mode `100644`. The server therefore
treated it as non-executable and Git skipped it during commit even though `pipeline.sh doctor`
reported `commit hook: wired`. The receipt verifier itself passed, but the repository's final
enforcement boundary was not active. This must be repaired before the next product ticket relies on
the same delivery gate.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ScorchKit's canonical pre-commit hook is checked out on a native filesystem, ScorchKit shall preserve an executable Git index mode so Git can invoke it. | `git ls-files -s .githooks/pre-commit`; native server `stat`; Git hook integration selftest. |
| REQ-002 | When `pipeline.sh doctor` inspects a repository whose hook path is configured but whose canonical pre-commit hook is missing, untracked, or non-executable in the index, ScorchKit shall fail instead of reporting the hook as wired. | Pipeline selftest fixtures for valid and invalid hook states. |
| REQ-003 | When Git attempts a commit, ScorchKit shall invoke the canonical hook, block an absent or stale delivery receipt, and allow a current delivery receipt. | Two-arm temporary-repository commit integration test through Git, not a direct script call. |
| REQ-004 | When the hook is invoked directly for receipt verification, ScorchKit shall retain the existing valid, stale, tampered-mode, and symlink-retarget behavior. | Existing pre-commit receipt selftest plus regression assertions. |
| REQ-005 | When this delivery repair is validated, ScorchKit shall use focused shell and pipeline tests plus the normal DIFF gate and shall not launch a repository-wide mutation scan. | Validation notes and exact-tree DIFF receipt. |

## Scope

- In: tracked mode of `.githooks/pre-commit`; hook readiness diagnostics; actual Git-invocation
  regression coverage; pipeline and quality documentation required by this ticket.
- Out: receipt fingerprint semantics; gate mode policy; scanner behavior; production Rust application
  code; global Codex configuration; SK-035 evidence model work.
- Validation-only dependency repair: if the live advisory database rejects the locked transitive
  dependency graph, update only the affected lockfile entry to the first patched compatible release
  and prove the resulting graph through the ordinary FAST and DIFF gates. Do not change dependency
  manifests, application source, or mutation scope under this exception.

## Locked decisions

- Git's tracked mode is authoritative for portable checkout behavior; filesystem mode is an
  additional runtime check where available.
- A configured `core.hooksPath` alone is not proof that the expected hook can run.
- The regression must invoke Git's hook machinery; calling the hook with `bash` is retained but is
  not sufficient proof of enforcement.
- This ticket authorizes no production Rust behavior change or broad mutation inventory. A
  supported-host test assertion may change only to preserve the same executable-path contract.

## Recon

- `git ls-files -s .githooks/pre-commit` records mode `100644` at the ticket baseline.
- On `/srv/stacks/scorchkit`, `stat` reports mode `0644`, and Git skipped the hook during the
  TICKET-008 commit.
- On the SMB-mounted macOS path, synthetic mode `0700` masks the index defect; diagnostics must
  therefore inspect the index rather than trusting only `test -x`.
- `pipeline.sh doctor` currently verifies only that `core.hooksPath` equals `.githooks`.
- `.githooks/pre-commit --selftest` exercises the script through `bash` and does not prove Git will
  invoke it.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/precommit-hook-enforcement.spec.md`

## Log

- 2026-08-19: opened.
- 2026-08-19: owner directed removal of the obsolete Codex CLI and commencement of the next ticket;
  the delivery-hook failure discovered at the prior commit was accepted as the prerequisite repair.
- 2026-08-19: after the validation child remained frozen before Rust startup for more than two
  hours, the owner explicitly directed termination and continuation. The unwound gate then exposed
  `RUSTSEC-2026-0258` against locked `h2` 0.4.15, authorizing the narrow validation-only lockfile
  repair recorded in this ticket.
- 2026-08-19: clean FAST and exact-tree DIFF validation passed. DIFF reported 19 applicable lanes
  green and selected no changed Rust lines, so no mutation campaign was launched.
- 2026-08-19: the authorized delivery commit exposed that the hook's successful normal invocation
  inherited status 1 from its final `--verify-only` conditional. Added an explicit successful exit
  and a positive real-Git commit arm. Focused hook and pipeline checks passed; the final DIFF remains
  the delivery boundary.
- 2026-08-19: server-side FAST validation on the new NVMe exposed and repaired a Linux executable
  symlink assertion and an optional-value `set -u` failure. The Rust edit changes only a test
  assertion; DIFF mutation selection remains the required proof and no full inventory is authorized.
- 2026-08-19: after aligning the server to the known-green Rust 1.96.0 and ShellCheck 0.11.0,
  server-side FAST passed 14 lanes with no failures and the eight defined FAST-mode skips. Build
  output and temporary analysis paths resolved to the dedicated `/mnt/fast` NVMe.
- 2026-08-19: the server DIFF gate passed every non-mutation lane but exposed an empty-selection
  handling defect: cargo-mutants returned success for the test-only Rust diff and correctly created
  no outcomes file, while `bin/mutants.sh` treated the absent file as failure. The runner now
  normalizes only a successful empty DIFF result into explicit zero-mutant evidence; failed, full,
  and malformed results remain rejected. Its selftest and the actual focused DIFF selection passed
  at 100% with 0 caught, 0 missed, and no mutant compilation.
- 2026-08-19: repeated server validation exposed two parallel-only readiness races in existing
  tests. The job cleanup test now observes the ownership token it actually verifies with a bounded
  parallel-load budget, and the process fixture waits for a complete parseable PID rather than file
  existence alone. Both exact tests and the 1,041-test root library lane passed after repair.
