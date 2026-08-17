# ScorchKit knowledge register

Search this file before plan and implementation, then read the linked AAR, completed pipeline notes,
or architecture document. Capture reusable knowledge here and in the current AAR.

## ID conventions

- `PR-scorchkit-<slug>-NNN`: prevention rule.
- `BF-scorchkit-<slug>-NNN`: bug or failure pattern.
- `AD-scorchkit-<slug>-NNN`: architecture decision.

## Standing rules

| ID | Rule | Source |
|---|---|---|
| `PR-scorchkit-policy-before-effects-001` | Authorize targets and effect classes before creating network clients or subprocesses. | `SECURITY.md` |
| `PR-scorchkit-gate-sequential-cargo-001` | Run Cargo gates sequentially; let cargo-mutants manage only its own bounded workers. | `CONSTITUTION.md` §0 |
| `PR-scorchkit-mutation-local-scratch-001` | Keep mutation build trees and detailed output off the HDD/SMB worktree. | `bin/mutants.sh` |
| `PR-scorchkit-loopback-integration-001` | Integration tests that execute scans use loopback mocks and assert successful effects; a timeout is never an accepted test outcome. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-global-set-lock-001` | Tests and production operations defined over a database-wide due set serialize acquisition and prove concurrent callers do not duplicate work. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-gate-prerequisites-001` | Do not run expensive dependent delivery gates after a static prerequisite fails, and do not mutate a coverage-red build. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-observable-seams-001` | Extract policy decisions into pure asserted seams, but remove behavior-free delegates and retain one tested owner. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-executor-contract-001` | Route bounded external tools through one injectable context executor and assert every registry entry executes its declared invocation. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-derived-network-policy-001` | Authorize derived hostnames before DNS, every answer before use, and give protocol clients an authorized concrete connection when they would otherwise resolve again. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-doc-examples-contract-001` | Compile standalone examples against the public API whenever extension contexts, constructors, or registration seams change. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-provider-transport-quarantine-001` | Keep provider modules private, test-only, and unregistered until their authentication and service transports use ScorchKit policy. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-cli-options-observable-001` | Prove accepted profile and output options through scanner selection or artifact behavior, not parser-only tests. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-gate-worktree-scope-001` | Enumerate tracked and unignored worktree files before recursive formatters or linters can descend into `.git`. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-process-env-test-lock-001` | Serialize every library test that mutates process-wide environment variables through one crate-wide mutex. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-orthogonal-test-budget-001` | Give a fixture a bounded execution budget independent of the behavior under test unless deadline behavior is the assertion. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-test-shell-fixtures-001` | Run newly written shell fixtures through an explicit trusted shell instead of relying on temporary-file execute permissions. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-mutation-completion-evidence-001` | Publish mutation score and blind-file claims only after cargo-mutants returns a recognized completed status. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-mutation-effect-observation-001` | Call effect-owning async commands in tests and observe their errors, state changes, or artifacts instead of relying only on helper tests. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-process-output-contract-001` | Test CLI and report output through the built process with asymmetric fixtures and exact semantic assertions. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-presentation-predicate-001` | Give repeated quiet and cardinality decisions one shared predicate owner with a complete truth table. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-canonical-blind-ledger-001` | Review the completed mutation run's exact blind-file list and give every path a direct evidence disposition. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-focused-mutation-repair-001` | Preserve one broad survivor inventory, repair its named seams, and rerun only those functions; schedule a new full inventory separately. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-focused-evidence-binding-001` | Bind focused mutation outcomes to mutation-relevant inputs and bind their digest to the exact delivery receipt; reconstruct score and survivor identity from raw outcomes. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-archive-link-integrity-001` | Rewrite ticket/spec cross-links to their closed/completed destinations as part of the archive transition. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-bounded-process-exit-race-001` | Bound only a confirmed exited-child process-group permission race; return other live-child termination failures without an indefinite wait. | `AAR-001-rustal-quality-workflow` |
| `PR-scorchkit-cancellation-whole-lifecycle-001` | Race cancellation across central work and adjacent async effects, then check it before publishing success. | `AAR-002-shared-job-executor` |
| `PR-scorchkit-public-mode-dependency-contract-001` | Assert producer/consumer ordering through every public execution mode that owns a phase partition. | `AAR-002-shared-job-executor` |
| `PR-scorchkit-ticket-diff-baseline-001` | Establish a canonical Git/receipt boundary before starting the next ticket that relies on diff mutation. | `AAR-002-shared-job-executor` |
| `PR-scorchkit-store-invariants-falsification-001` | Enforce creation, replacement, transition, and lineage invariants inside every public store implementation and test direct callers against the shared contract. | `AAR-003-scan-job-lifecycle` |
| `PR-scorchkit-exact-failure-source-001` | When fail-closed branches share a status, assert the selected error or state rather than failure status alone. | `AAR-003-scan-job-lifecycle` |
| `PR-scorchkit-focused-evidence-generic-001` | Discover approved focused evidence from ticket metadata and verify its raw outcomes, timeouts, input transitions, and receipt-bound digest without ticket-number branches. | `AAR-003-scan-job-lifecycle` |
| `PR-scorchkit-clippy-before-mutation-seal-001` | Run strict all-target Clippy after mutation assertions and before sealing the current-tree mutation hash. | `AAR-003-scan-job-lifecycle` |
| `PR-scorchkit-provider-consumption-validation-001` | Revalidate public provider envelopes and request-bound invariants where workflows consume them, regardless of adapter validation. | `AAR-004-typed-ai-provider-contracts` |
| `PR-scorchkit-green-baseline-reuse-001` | Reuse a completed green DIFF/FULL mutation result only when raw outcomes prove zero misses and the exact mutation-input hash is unchanged. | `AAR-004-typed-ai-provider-contracts` |
| `PR-scorchkit-host-workflow-tool-contract-001` | Bind every host-workflow input and output claim to the advertised MCP schema, immediate tool result, and an executing transport test. | `AAR-005-codex-first-plugin` |
| `PR-scorchkit-semantic-token-policy-check-001` | Enforce static phase boundaries on protected tool/effect tokens independently of surrounding prose, and prove alternate wording fails. | `AAR-005-codex-first-plugin` |
| `PR-scorchkit-attribution-not-authorization-001` | Keep transport principal and self-asserted client attribution separate from engagement grants; label trust explicitly and prove a privileged-looking client name cannot authorize an effect. | `AAR-006-mcp-contract-hardening` |
| `PR-scorchkit-effect-contract-single-source-001` | Let one exhaustive inventory own every tool's strongest behavior class, annotations, and response provenance, and fail router construction when names or counts drift. | `AAR-006-mcp-contract-hardening` |
| `PR-scorchkit-generated-metadata-exactness-001` | Pin generated titles and other presentation metadata with exact representative assertions in addition to semantic schema/flag tests. | `AAR-006-mcp-contract-hardening` |

## Register

| ID | Kind | Source |
|---|---|---|
| `BF-scorchkit-scheduler-n-squared-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-websocket-second-resolution-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-test-environment-race-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-orthogonal-test-timeout-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-mutants-temp-script-spawn-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-mutants-incomplete-score-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-mutation-effect-erasure-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-report-output-symmetry-001` | bug | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-mutation-rescan-cost-001` | process failure | `AAR-001-rustal-quality-workflow` |
| `BF-scorchkit-exited-child-killpg-race-001` | bug | `AAR-001-rustal-quality-workflow` |
| `AD-scorchkit-focused-repair-receipt-001` | architecture decision | `CONSTITUTION.md` §19 |
| `BF-scorchkit-borrowed-future-inference-001` | build failure | `AAR-002-shared-job-executor` |
| `BF-scorchkit-cancellation-lifecycle-gap-001` | bug | `AAR-002-shared-job-executor` |
| `BF-scorchkit-success-before-final-conversion-001` | integrity bug | `AAR-002-shared-job-executor` |
| `BF-scorchkit-public-mode-proof-gap-001` | test gap | `AAR-002-shared-job-executor` |
| `BF-scorchkit-accumulated-diff-mutation-scope-001` | process failure | `AAR-002-shared-job-executor` |
| `AD-scorchkit-boxed-borrowed-jobs-001` | architecture decision | `AAR-002-shared-job-executor` |
| `BF-scorchkit-job-owner-drop-001` | lifecycle bug | `AAR-003-scan-job-lifecycle` |
| `BF-scorchkit-concurrent-cancel-same-state-001` | concurrency bug | `AAR-003-scan-job-lifecycle` |
| `BF-scorchkit-resume-fork-001` | integrity bug | `AAR-003-scan-job-lifecycle` |
| `BF-scorchkit-ambiguous-failure-source-001` | test gap | `AAR-003-scan-job-lifecycle` |
| `BF-scorchkit-focused-evidence-ticket-coupling-001` | process failure | `AAR-003-scan-job-lifecycle` |
| `BF-scorchkit-provider-envelope-bypass-001` | contract bug | `AAR-004-typed-ai-provider-contracts` |
| `BF-scorchkit-empty-survivor-proof-gap-001` | process failure | `AAR-004-typed-ai-provider-contracts` |
| `BF-scorchkit-project-scan-contract-gap-001` | contract bug | `AAR-005-codex-first-plugin` |
| `BF-scorchkit-plugin-phase-verb-bypass-001` | test gap | `AAR-005-codex-first-plugin` |
| `BF-scorchkit-rmcp-private-router-context-001` | verification-plan gap | `AAR-006-mcp-contract-hardening` |
| `BF-scorchkit-generated-tool-title-gap-001` | test gap | `AAR-006-mcp-contract-hardening` |
