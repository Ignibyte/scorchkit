---
aar: AAR-017-codex-appsec-workflows
ticket: TICKET-017
pipeline: codex-appsec-workflows
status: submitted
opened: 2026-08-21
submitted: 2026-08-21
effectiveness: 5 - strong
---

# AAR-017 — Codex-first application-security workflows and tiered scan profiles

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Profile compilation could be mistaken for authorization. | Yes; every planned effect retains its exact execution-time grant requirements. |
| `PR-scorchkit-host-workflow-tool-contract-001` | The new Codex coordinator changes the public plugin inventory. | Yes; the design includes positive/negative skill-contract validation. |
| `PR-scorchkit-semantic-token-policy-check-001` | Prose-only validation could miss an effectful fallback. | Yes; validator checks exact semantic workflow tokens and forbidden paths. |
| `PR-scorchkit-proof-evidence-own-provenance-001` | Codex Security semantic review is intentionally combined with scanner evidence. | Yes; host analysis stays labeled and cannot become canonical evidence. |
| TICKET-015 focused selection | Repair verification needed a narrow default. | Yes; exact supported selectors are planned before any explicit broad fallback. |
| Official Codex plugin and Security guidance | The host needs both workflow reasoning and controlled engine tools. | Yes; a skill coordinates Codex Security plus MCP while the engine remains vendor-neutral. |

## What happened

- The ticket shipped provider-neutral application context, change-set, and workflow-plan contracts,
  two read-only MCP tools, and a sixth Codex plugin skill that coordinates host analysis with
  ScorchKit effects without merging their authority or evidence.
- Exact-tree security review found no reportable vulnerability. It did expose a macOS filesystem
  classifier defect, which was repaired before delivery.
- Delivery validation exposed two isolated-checkout fixture assumptions and an ambient Cargo target
  that made mutation workers share generated artifacts. The runner now gives each worker a relative
  target directory on the Offload disk.
- The preserved 177-case mutation baseline found 28 clause and boundary gaps. Exact focused repair
  caught all 28 without repeating the broad inventory, yielding 152/152 viable outcomes caught.

## Novel findings

- Clearing `CARGO_TARGET_DIR` is not sufficient isolation when a global Cargo configuration supplies
  an absolute target directory. Mutation workers need an explicit relative target.
- Security-bound fixtures in copied worktrees must derive both the requested path and engagement
  scope from the runtime checkout. Compile-time repository paths cannot supply either side.
- Representative workflow tests do not prove exact alias, limit, gap, identity, and requirement
  behavior. Those boundaries need direct truth-table assertions.
- A focused selector that the engine cannot enforce must remain a typed gap. It must never trigger
  an implicit full-root substitute.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-ambient-cargo-target-worker-sharing-001` | A global absolute Cargo target made isolated mutation workers share generated build artifacts. | Process inspection during DIFF mutation validation. |
| `BF-scorchkit-compile-runtime-scope-mismatch-001` | Tests mixed a compile-time repository path with runtime engagement scope inside copied worktrees. | Cargo-mutants isolated baseline. |
| `BF-scorchkit-workflow-boundary-mutation-gap-001` | Representative workflow tests missed exact parser, limit, gap, identity, and requirement branches. | Preserved 177-case DIFF mutation baseline. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-mutation-relative-worker-target-001` | Override ambient Cargo settings with a relative target directory inside every isolated mutation worker. | Absolute global targets defeat worker isolation and can contaminate later canonical builds. |
| `PR-scorchkit-isolated-runtime-scope-fixture-001` | Derive request paths, authorization scope, and expected canonical roots from the runtime checkout in isolated-worktree tests. | Compile-time paths can escape or misdescribe a copied test root. |
| `PR-scorchkit-workflow-boundary-truth-table-001` | Assert every workflow alias, exact limit, gap predicate, stable identity, and engine requirement directly. | Downstream plan-shape checks do not observe clause-level contract changes. |
| `PR-scorchkit-workflow-gap-no-broad-substitution-001` | Preserve unsupported exact selectors as typed gaps and require a separate explicit choice before broader execution. | A focused verification request must not silently widen into a repository scan. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 5/5. Recalled policy, provenance, plugin-contract, and focused-verification rules changed the
design before implementation by excluding an opaque composite executor, separating host analysis
from scanner evidence, and forbidding broad fallback. Exact-tree inspection found and repaired the
filesystem classifier defect. The focused mutation campaign then exposed 28 direct boundary gaps
and caught every repaired survivor without another broad scan. The pre-completion focused-repair
gate passed all 19 applicable lanes with no failures and verified the sealed 152/152 viable result.
