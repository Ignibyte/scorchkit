---
aar: AAR-023-windows-process-owner
ticket: TICKET-023
pipeline: windows-process-owner
status: submitted
opened: 2026-08-22
submitted: 2026-08-22
effectiveness: 5 - strong
---

# AAR-023 — Add Windows Job Object process ownership

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-bounded-process-exit-race-001` | Windows adds a second whole-tree termination backend. | Yes — the design preserves the proven Unix classifier and requires bounded, observable Windows cleanup errors. |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Process futures are cancelled by drop. | Yes — Job Object kill-on-close is part of the owned child rather than an optional cleanup call. |
| `PR-scorchkit-policy-before-effects-001` | Enabling a new host could create a parallel process path. | Yes — both Windows lifecycles remain behind the existing policy-sealed executor/Interactsh boundaries. |
| `PR-scorchkit-supported-host-semantic-assertions-003` | The new CI lane must prove behavior across unlike process APIs. | Yes — tests assert descendants and side effects, not platform-specific text or paths. |
| `rustal-quality-workflow.notes.md` | The original direct-child-only cleanup defect affected one-shot and long-lived tools. | Yes — SK-045 covers both owners and every terminal lifecycle. |
| `shared-job-executor.notes.md` | Caller cancellation drops active effect futures. | Yes — the Windows owner is RAII and cannot depend only on an awaited cleanup branch. |

## What happened

- Added one provider-neutral owned-process seam in `scorchkit-tools` and routed the one-shot tool
  executor and long-lived Interactsh session through it. Unix retains process-group ownership;
  Windows creates the child suspended, establishes kill-on-close Job Object ownership, and resumes
  only after assignment succeeds.
- Preserved direct-child observation during normal execution, then bounded whole-tree termination
  and reaping across success, nonzero exit, timeout, output or artifact overflow, explicit stop,
  future cancellation, and owner drop. Ownership setup failure remains a typed infrastructure
  error and cannot fall back to direct-child-only execution.
- Enabled Linux, macOS, and Windows as the supported host set, added a required native
  `windows-latest` workspace Clippy/test lane, and cross-compiled the full workspace locally without
  adding platform details to scanner, policy, evidence, or serialized result contracts.
- Adversarial inspection removed the misleading Windows no-op compatibility seam and hardened
  lifecycle fixtures. The first DIFF mutation run then exposed target-inactive Windows bodies plus
  Unix accessor and redundant-drop gaps; the repair split exact target-only modules and added
  direct semantic contracts.
- The final exact-tree DIFF gate passed all 19 applicable lanes at 84.58% line coverage and 100%
  MSI: 16 mutations caught, 0 missed, and 9 unviable. Strict Nextest passed 1,931 cases, all 100
  PostgreSQL tests passed, and CLI/MCP contracts were green.

## Novel findings

- A Windows group wrapper's normal `wait` may await every Job member. ScorchKit must observe the
  direct child during execution, then terminate and reap the complete Job before interpreting the
  parent result so a successful parent cannot become a timeout merely because it left descendants.
- A Linux DIFF inventory can enumerate `cfg(windows)` function bodies even though the Linux test
  executable cannot observe those rewrites. Host-exclusive implementations need exact target-only
  module boundaries so a narrow exclusion does not hide host-active source.
- An owned process's stdin, stdout, stderr, and direct-child identity are security-relevant
  lifecycle seams even when end-to-end output tests happen to exercise them indirectly. Direct
  accessor contracts make replacement and constant mutations observable.
- Rust field destruction order is part of the implicit cleanup contract when one field owns a
  descendant tree and another owns the direct child. The whole-tree owner must drop first, and a
  descendant fixture must prove that ordering instead of relying on a redundant outer `Drop` body.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-linux-mutation-windows-target-001` | Linux mutation execution treated target-inactive Windows process and filesystem rewrites as survivors, reducing the first reported MSI to 36.36% even though native compilation was green. | First canonical DIFF mutation inventory. |
| `BF-scorchkit-owned-process-accessor-mutation-001` | Indirect lifecycle coverage did not distinguish removed stdin/stdout/stderr accessors or substituted direct-child identities. | First canonical DIFF mutation inventory. |
| `BF-scorchkit-redundant-owned-process-drop-001` | An explicit outer `Drop` repeated the inner process-group guard's behavior, producing an equivalent mutation and obscuring which owner guaranteed descendant-first cleanup. | Mutation repair and ownership review. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-target-inactive-mutation-files-001` | Put host-exclusive process and filesystem bodies in exact target-only modules; exclude only those files from an unlike-host mutation run while native CI compiles and executes them. | Prevents impossible host-inactive rewrites from corrupting MSI without removing host-active source from mutation scope. |
| `PR-scorchkit-owned-process-accessor-contract-001` | Directly assert every owned-child pipe accessor and the direct-child identity used by wait and cleanup. | Indirect end-to-end tests may pass after an accessor or identity seam is removed or replaced. |
| `PR-scorchkit-descendant-owner-drop-order-001` | Destroy the whole-tree owner before the direct-child fallback and pin declaration-order cleanup with a semantic descendant-exit test. | Implicit field destruction order is executable lifecycle behavior and prevents descendants escaping when the outer future is dropped. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled policy-before-effects, whole-lifecycle cancellation, bounded process-race, and
cross-host semantic rules fixed the architecture before implementation: both process paths use one
owner, Windows work cannot resume before Job assignment, and cleanup remains bounded and
observable. Inspection found seven concrete API, lifecycle, dependency, and fixture issues. The
first DIFF result then exposed a measurement boundary and direct Unix contract gaps; exact
target-only modules, accessor tests, and descendant-order proof raised the current-tree mutation
result from 36.36% to 100% without weakening scope, timeouts, output limits, redaction, policy, or
the 95% MSI floor.
