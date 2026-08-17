---
aar: AAR-007-workspace-crate-extraction
ticket: TICKET-007
pipeline: workspace-crate-extraction
status: submitted
opened: 2026-08-17
submitted: 2026-08-17
effectiveness: 5
---

# AAR-007 — Behavior-preserving workspace crate extraction

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Family contexts have crate-private constructors and carry authorization decisions. | Yes — prevented a package move that would widen context construction authority. |
| `PR-scorchkit-executor-contract-001` | The shared scheduler and subprocess layer are already provider-neutral. | Yes — selected them for direct implementation extraction. |
| `PR-scorchkit-doc-examples-contract-001` | Root paths must remain compatible while type ownership changes. | Yes — added public-path and type-identity verification. |
| `PR-scorchkit-public-mode-dependency-contract-001` | All four family modes depend on common result and execution contracts. | Yes — kept family vocabulary explicit and feature-aware. |
| `PR-scorchkit-ticket-diff-baseline-001` | SK-032 ended at clean commit `e860608`. | Yes — gives SK-033 an exact mutation/delivery boundary. |
| `PR-scorchkit-focused-mutation-repair-001` | The owner stopped repeat broad mutation runs. | Yes — inventory showed the nominal DIFF had inflated to 841 mutations, so execution stayed within the 11 repaired functions. |
| `PR-scorchkit-effect-contract-single-source-001` | MCP metadata was centralized immediately before extraction. | Yes — the MCP package will own one inventory rather than copying it. |

## What happened

ScorchKit became a 14-package Cargo workspace: 13 internal packages now own stable policy, domain,
configuration, execution, process, family, storage-model, MCP, CLI, and agent contracts, while the
root package remains the composition and compatibility facade. Exact dependency edges, lockstep
versions, representative type identities, family descriptors, and private compatibility seams are
enforced by the architecture suite.

Inspection found that package movement had outgrown the root-only quality commands and that glob
re-exports widened several formerly private integration helpers. The gate and CI now cover the
whole workspace, and the facade exposes an explicit compatibility list while package-to-package
adapters remain hidden. CLI help, MCP schema text, public paths, features, and wire fixtures remain
unchanged.

The focused delivery gate passed 19 applicable lanes with 79.99% line coverage, 1,443 strict
Nextest cases, PostgreSQL and CLI/MCP contracts, and sealed mutation evidence for the 11 repaired
functions. The function scope selected 90 mutations: 83 were caught, seven were unviable, and none
were missed or timed out. The inventory-only Git DIFF selected 841 mutations because moved code
appears new; that broad campaign was not executed.

## Novel findings

- Package extraction changes the scope of the quality system as well as the Cargo graph. Root-only
  commands can report green while new package tests, documentation, and mutants are absent.
- Glob re-exports are unsafe at a compatibility boundary because package-public integration helpers
  can silently become root-public.
- Generated CLI and schema metadata can depend on the owning package even when Rust type identity
  and serialized fields do not change.
- Mutation selection must distinguish behavioral edits from source movement. A named function
  inventory can preserve useful evidence without disguising a move-inflated DIFF as focused work.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-workspace-gate-root-only-001` | Root-only quality commands excluded extracted package tests, documentation, coverage, static analysis, and mutation inventory. | Adversarial inspection of the gate and CI workflow. |
| `BF-scorchkit-facade-glob-visibility-001` | Glob re-exports widened formerly crate-private policy, lifecycle, process, and MCP helpers. | Public API and security-boundary inspection. |
| `BF-scorchkit-package-derived-metadata-drift-001` | Moving types changed Clap help and generated MCP schema text through package-local metadata and Rustdoc. | Existing CLI and schema fixtures. |
| `BF-scorchkit-code-move-diff-inflation-001` | A behavior-preserving move made the nominal DIFF select 841 mutations in 268 functions. | Inventory-only cargo-mutants selection. |
| `BF-scorchkit-nextest-empty-workspace-suites-001` | Workspace-wide Nextest treated six known contract-only library harnesses as unexpected empty suites. | First focused delivery gate. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-workspace-gate-scope-001` | When code moves into packages, make tests, linting, Rustdoc, coverage, static analysis, dependency checks, and mutation inventory workspace-wide in the same ticket. | A package boundary is not real if delivery proof still sees only the root. |
| `PR-scorchkit-facade-visibility-preservation-001` | Use explicit compatibility re-exports and negative visibility contracts when extraction crosses a private seam. | Package-public integration adapters must not silently become public root API. |
| `PR-scorchkit-package-metadata-lockstep-001` | Pin internal package versions to the root and make published CLI/schema metadata explicit when derive behavior depends on package ownership. | Moving a type must not change the product version, help text, or wire schema. |
| `PR-scorchkit-move-aware-mutation-scope-001` | Inventory a move-heavy DIFF before execution; if it becomes broad, run only the owner-approved repaired functions and seal both the input hash and exact function inventory. | Source movement should not trigger an accidental full campaign or produce unauditable focused evidence. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5/5. The plan preserved behavior while establishing enforceable package ownership. Inspection found
and fixed quality-scope, visibility, metadata, and Nextest integration defects before delivery.
