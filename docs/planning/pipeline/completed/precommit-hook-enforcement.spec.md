---
title: Restore executable pre-commit receipt enforcement
pipeline_id: fb1c97e3-8c91-464e-afc3-198ce35ebecb
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-009
ticket_doc: docs/planning/tickets/closed/TICKET-009-precommit-hook-enforcement.md
aar: docs/planning/knowledge/aar/AAR-009-precommit-hook-enforcement.md
created: 2026-08-19
---

# Restore executable pre-commit receipt enforcement — spec

## Intent

Ship a portable, fail-closed pre-commit enforcement boundary before further application-security
features are implemented. The tracked hook must be executable after checkout, diagnostics must
distinguish configuration from readiness, and an integration fixture must demonstrate that Git
blocks a commit whose delivery receipt is absent or stale.

## Scope

- In: canonical hook mode; reusable hook-readiness check; `doctor` failure behavior; Git-level hook
  invocation test; focused workflow documentation and delivery evidence.
- Out: changes to receipt content or approved gate modes; production Rust behavior; scanner
  selection; model routing; SK-035 evidence schemas.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When ScorchKit's canonical pre-commit hook is checked out on a native filesystem, ScorchKit shall preserve an executable Git index mode so Git can invoke it. | `git ls-files -s .githooks/pre-commit`; native server `stat`; Git hook integration selftest. |
| REQ-002 | When `pipeline.sh doctor` inspects a repository whose hook path is configured but whose canonical pre-commit hook is missing, untracked, or non-executable in the index, ScorchKit shall fail instead of reporting the hook as wired. | Pipeline selftest fixtures for valid and invalid hook states. |
| REQ-003 | When Git attempts a commit, ScorchKit shall invoke the canonical hook, block an absent or stale delivery receipt, and allow a current delivery receipt. | Two-arm temporary-repository commit integration test through Git, not a direct script call. |
| REQ-004 | When the hook is invoked directly for receipt verification, ScorchKit shall retain the existing valid, stale, tampered-mode, and symlink-retarget behavior. | Existing pre-commit receipt selftest plus regression assertions. |
| REQ-005 | When this delivery repair is validated, ScorchKit shall use focused shell and pipeline tests plus the normal DIFF gate and shall not launch a repository-wide mutation scan. | Validation notes and exact-tree DIFF receipt. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Treat Git index mode `100755` as the portable source of truth. | The SMB client presents synthetic execute bits that do not predict a native checkout. |
| 2 | Retain direct Bash invocation for portable selftests, but add stale-receipt rejection and current-receipt acceptance through real Git commits. | Script correctness, Git hook discoverability, and the success exit contract are separate behaviors. |
| 3 | Make `doctor` fail closed for an inert canonical hook. | A success diagnostic must prove readiness, not configuration alone. |
| 4 | Do not alter receipt semantics or application code. | The defect is isolated to delivery enforcement and should remain a small prerequisite. |
| 5 | Use DIFF validation only; do not run the full gate or a broad mutation campaign. | The only Rust change permitted during delivery repair is a supported-host test assertion; the owner has reserved broad scans for a later campaign. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-009-precommit-hook-enforcement.md`
- AAR: `docs/planning/knowledge/aar/AAR-009-precommit-hook-enforcement.md`
- Architecture: `.githooks/pre-commit`, `bin/pipeline.sh`, `bin/gate.sh`, and
  `bin/gate-state.sh` form the existing delivery-enforcement boundary.

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
