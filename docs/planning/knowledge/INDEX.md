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
| `PR-scorchkit-git-hook-execution-contract-001` | Prove a repository hook through Git using its canonical checkout paths, and diagnose configured path, tracked mode, and checkout executability as separate readiness conditions. | `AAR-009-precommit-hook-enforcement` |
| `PR-scorchkit-enforcement-two-arm-proof-002` | Every enforcement integration shall prove both a rejected invalid case and an accepted valid case through the production entry point. | `AAR-009-precommit-hook-enforcement` |
| `PR-scorchkit-supported-host-semantic-assertions-003` | Cross-host tests shall assert executable and filesystem semantics, not a platform-specific symlink target name, and shell optionals read under `set -u` shall be initialized. | `AAR-009-precommit-hook-enforcement` |
| `PR-scorchkit-empty-diff-mutation-evidence-004` | Normalize missing mutation outcomes only for a successful DIFF selection, persist explicit empty evidence, and reject full, failed, or malformed counterparts. | `AAR-009-precommit-hook-enforcement` |
| `PR-scorchkit-exact-readiness-observation-005` | In parallel async and process fixtures, wait on the exact asserted condition with a bounded orthogonal budget; readiness files require complete valid content. | `AAR-009-precommit-hook-enforcement` |
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
| `PR-scorchkit-workspace-gate-scope-001` | When code moves into packages, make tests, linting, Rustdoc, coverage, static analysis, dependency checks, and mutation inventory workspace-wide in the same ticket. | `AAR-007-workspace-crate-extraction` |
| `PR-scorchkit-facade-visibility-preservation-001` | Use explicit compatibility re-exports and negative visibility contracts when extraction crosses a private seam. | `AAR-007-workspace-crate-extraction` |
| `PR-scorchkit-package-metadata-lockstep-001` | Pin internal package versions to the root and make published CLI/schema metadata explicit when derive behavior depends on package ownership. | `AAR-007-workspace-crate-extraction` |
| `PR-scorchkit-move-aware-mutation-scope-001` | Inventory a move-heavy DIFF before execution; if it becomes broad, run only the owner-approved repaired functions and seal both the input hash and exact function inventory. | `AAR-007-workspace-crate-extraction` |
| `PR-scorchkit-default-catalog-explicit-compatibility-001` | Keep implicit host and profile catalogs application-only; require exact IDs or a named compatibility surface for retained non-core adapters. | `AAR-008-appsec-registry-adapters` |
| `PR-scorchkit-adapter-execution-descriptor-parity-001` | Assert every adapter descriptor's output, effect, provenance, and artifact claims against its concrete invocation and parser. | `AAR-008-appsec-registry-adapters` |
| `PR-scorchkit-credential-use-separate-grant-001` | Require a separate exact credential-use grant before an external adapter can inherit or receive credentials, even when its scan and subprocess effects are already allowed. | `AAR-008-appsec-registry-adapters` |
| `PR-scorchkit-parser-outcome-integrity-001` | Distinguish no records, valid findings, malformed records, and scanner-reported failure; never convert partial output into a clean result. | `AAR-008-appsec-registry-adapters` |
| `PR-scorchkit-scoped-tool-artifacts-001` | Give each external-tool run scoped owned artifacts and make descriptor ownership match cleanup behavior. | `AAR-008-appsec-registry-adapters` |
| `PR-scorchkit-canonical-evidence-identity-001` | Recursively canonicalize unordered structured evidence and length-prefix every identity component before hashing. | `AAR-010-appsec-evidence-v2` |
| `PR-scorchkit-identity-schema-label-parity-001` | Version and persist record schemas and identity algorithms separately, with exact storage round-trip assertions for both labels. | `AAR-010-appsec-evidence-v2` |
| `PR-scorchkit-public-evidence-revalidation-001` | Reapply redaction and normalization whenever public compatibility evidence crosses serialization, finding, report, or persistence boundaries. | `AAR-010-appsec-evidence-v2` |
| `PR-scorchkit-finding-observation-transaction-001` | Serialize equivalent finding identities and append distinct evidence/analysis inside one transaction guarded by the identity lock. | `AAR-010-appsec-evidence-v2` |
| `PR-scorchkit-mutation-branch-directness-001` | Kill a repaired mutation with an assertion on the immediate branch contract before relying on downstream round trips. | `AAR-010-appsec-evidence-v2` |
| `PR-scorchkit-untrusted-finding-channel-redaction-001` | Normalize and redact every untrusted description, evidence value, flow message, and tool diagnostic at construction and each durable/public projection. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-analyzer-applicability-artifact-detection-001` | Derive applicability from bounded source/artifact discovery plus exact adapter capabilities; missing root manifests and empty declarations are not proof of coverage. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-scan-coverage-projection-parity-001` | Project canonical module outcomes and degraded status through CLI, MCP, JSON, reports, and SARIF. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-passive-analyzer-config-isolation-001` | Isolate passive analyzers with ScorchKit-owned configuration, state, environment, and outputs and disable target plugin/config discovery. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-verified-artifact-single-read-001` | Make file-consuming scanners use an owned copy of the same bounded bytes whose identity and schema were verified. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-module-mutation-evidence-001` | Preserve module-level cargo-mutants records and use `<module>` only for nonempty scope accounting. | `AAR-011-deep-sast-adapters` |
| `PR-scorchkit-offline-scan-refresh-separation-001` | Keep provider refresh outside scan execution; scans consume only explicit validated snapshots. | `AAR-012-application-supply-chain` |
| `PR-scorchkit-single-verified-sbom-001` | Generate one SBOM, validate and hash its bounded bytes once, and give consumers owned copies of those exact bytes. | `AAR-012-application-supply-chain` |
| `PR-scorchkit-cache-stage-ownership-001` | Give staged cache state an armed cleanup owner and transfer ownership only after verified atomic promotion. | `AAR-012-application-supply-chain` |
| `PR-scorchkit-aggregate-effect-budget-001` | Bound both each external object and the complete operation's object count and cumulative bytes. | `AAR-012-application-supply-chain` |
| `PR-scorchkit-source-artifact-coverage-separation-001` | Preserve declared source dependencies and shipped artifact contents as distinct coverage classes and correlate only supplied valid identities. | `AAR-012-application-supply-chain` |
| `PR-scorchkit-generated-dast-plan-001` | Compile external scanner plans only from already-authorized targets, local verified inputs, personas, phases, and bounded limits; arbitrary plans are context, not authority. | `AAR-013-authenticated-dast` |
| `PR-scorchkit-secretless-tool-version-probe-001` | Prove an executable and required version through a structurally secret-free environment before injecting credentials or scan-specific settings. | `AAR-013-authenticated-dast` |
| `PR-scorchkit-authenticated-dast-two-stage-proof-001` | Prove authenticated state before discovery and from final scanner evidence; missing or lost proof is a typed coverage gap. | `AAR-013-authenticated-dast` |
| `PR-scorchkit-operation-coverage-method-route-001` | Claim schema-operation coverage only from bounded traffic that matches both HTTP method and normalized route template. | `AAR-013-authenticated-dast` |
| `PR-scorchkit-artifact-entry-all-types-001` | Count every non-root filesystem entry against recursive artifact limits, follow only real directories, and sum only regular-file bytes. | `AAR-013-authenticated-dast` |
| `PR-scorchkit-authorize-validate-consume-one-handle-001` | Bind local-input authorization, validation, and byte consumption to one no-follow file handle and recheck its identity. | `AAR-014-trusted-nuclei` |
| `PR-scorchkit-adapter-terminal-state-authority-001` | Derive module and scan terminal state from typed adapter assessments and assert status plus lifecycle events in every runner mode. | `AAR-014-trusted-nuclei` |
| `PR-scorchkit-preprocess-budget-composition-001` | Reserve fixed workspace cost and accumulate all trusted input bytes and entries before creating artifacts or a subprocess. | `AAR-014-trusted-nuclei` |
| `PR-scorchkit-compound-guard-boundaries-001` | Assert each independent predicate and exact boundary; use typed flag unions when bitwise alternatives are behaviorally equivalent. | `AAR-014-trusted-nuclei` |
| `PR-scorchkit-proof-evidence-own-provenance-001` | Evaluate proof conditions from each evidence record's own provenance and combine records only after explicit comparability checks. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-transition-audit-reconstruction-001` | Persist every state-changing outcome, coverage decision, condition, evidence reference, and time, and rebuild transition identity on read. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-correlation-work-budget-001` | Bound input count, nested detail size, pair evaluations, and output count independently in many-to-many correlation. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-durable-canonical-parity-001` | Compare canonical raw JSON with every duplicated identity, schema, time, and projection column at durable API boundaries. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-correlation-facet-strength-001` | Classify correlation facets by evidentiary strength; generic method or weakness matches cannot prove reachability alone. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-projection-validate-canonical-001` | Validate nested records, ordering, identities, state, and coverage before every public projection. | `AAR-015-source-runtime-correlation` |
| `PR-scorchkit-declared-evidence-must-match-001` | Require every completed scenario to prove each declared evidence class with typed matching records at executor and durable boundaries. | `AAR-016-application-pentest` |
| `PR-scorchkit-native-response-byte-ceiling-001` | Consume decoded target responses through one hard byte-ceiling primitive; direct whole-body scanner reads are forbidden. | `AAR-016-application-pentest` |
| `PR-scorchkit-runtime-evidence-link-compatibility-001` | Attach manual runtime evidence only when project, canonical origin, route, and parameter match inside one transaction. | `AAR-016-application-pentest` |
| `PR-scorchkit-mutation-relative-worker-target-001` | Override ambient Cargo settings with a relative target directory inside every isolated mutation worker. | `AAR-017-codex-appsec-workflows` |
| `PR-scorchkit-isolated-runtime-scope-fixture-001` | Derive request paths, authorization scope, and expected canonical roots from the runtime checkout in isolated-worktree tests. | `AAR-017-codex-appsec-workflows` |
| `PR-scorchkit-workflow-boundary-truth-table-001` | Assert every workflow alias, exact limit, gap predicate, stable identity, and engine requirement directly. | `AAR-017-codex-appsec-workflows` |
| `PR-scorchkit-workflow-gap-no-broad-substitution-001` | Preserve unsupported exact selectors as typed gaps and require a separate explicit choice before broader execution. | `AAR-017-codex-appsec-workflows` |

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
| `BF-scorchkit-workspace-gate-root-only-001` | verification gap | `AAR-007-workspace-crate-extraction` |
| `BF-scorchkit-facade-glob-visibility-001` | public API bug | `AAR-007-workspace-crate-extraction` |
| `BF-scorchkit-package-derived-metadata-drift-001` | compatibility bug | `AAR-007-workspace-crate-extraction` |
| `BF-scorchkit-code-move-diff-inflation-001` | process failure | `AAR-007-workspace-crate-extraction` |
| `BF-scorchkit-nextest-empty-workspace-suites-001` | verification-plan gap | `AAR-007-workspace-crate-extraction` |
| `BF-scorchkit-adapter-output-contract-drift-001` | contract bug | `AAR-008-appsec-registry-adapters` |
| `BF-scorchkit-explicit-profile-bypass-001` | authorization bug | `AAR-008-appsec-registry-adapters` |
| `BF-scorchkit-ambient-credential-adapter-001` | authorization bug | `AAR-008-appsec-registry-adapters` |
| `BF-scorchkit-parser-no-findings-conflation-001` | evidence-integrity bug | `AAR-008-appsec-registry-adapters` |
| `BF-scorchkit-shared-tool-tempdir-001` | artifact-isolation bug | `AAR-008-appsec-registry-adapters` |
| `BF-scorchkit-hook-wired-not-ready-001` | delivery-integrity bug | `AAR-009-precommit-hook-enforcement` |
| `BF-scorchkit-hook-valid-receipt-rejected-002` | delivery-integrity bug | `AAR-009-precommit-hook-enforcement` |
| `BF-scorchkit-linux-portability-validation-003` | portability bug | `AAR-009-precommit-hook-enforcement` |
| `BF-scorchkit-empty-diff-mutation-artifacts-004` | verification bug | `AAR-009-precommit-hook-enforcement` |
| `BF-scorchkit-parallel-readiness-races-005` | test reliability bug | `AAR-009-precommit-hook-enforcement` |
| `BF-scorchkit-evidence-map-identity-nondeterminism-001` | evidence-integrity bug | `AAR-010-appsec-evidence-v2` |
| `BF-scorchkit-identity-schema-label-drift-001` | persistence-contract bug | `AAR-010-appsec-evidence-v2` |
| `BF-scorchkit-correlation-delimiter-collision-001` | identity-integrity bug | `AAR-010-appsec-evidence-v2` |
| `BF-scorchkit-public-evidence-redaction-bypass-001` | secret-handling bug | `AAR-010-appsec-evidence-v2` |
| `BF-scorchkit-mutation-incidental-normalization-001` | test-gap bug | `AAR-010-appsec-evidence-v2` |
| `BF-scorchkit-finding-channel-redaction-gaps-001` | secret-handling bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-manifest-only-analyzer-applicability-001` | coverage-integrity bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-unsupported-language-clean-coverage-001` | coverage-integrity bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-failed-scan-success-projection-001` | evidence-integrity bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-passive-analyzer-target-config-001` | process-isolation bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-parser-empty-failure-conflation-001` | evidence-integrity bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-pinned-rule-reopen-race-001` | provenance-integrity bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-module-mutation-function-null-001` | verification bug | `AAR-011-deep-sast-adapters` |
| `BF-scorchkit-refresh-stage-orphan-001` | cache-lifecycle bug | `AAR-012-application-supply-chain` |
| `BF-scorchkit-aggregate-provider-limit-gap-001` | effect-budget bug | `AAR-012-application-supply-chain` |
| `BF-scorchkit-tool-report-file-unbounded-001` | process-output bug | `AAR-012-application-supply-chain` |
| `BF-scorchkit-empty-artifact-profile-success-001` | coverage-integrity bug | `AAR-012-application-supply-chain` |
| `BF-scorchkit-zap-port-zero-001` | process-isolation bug | `AAR-013-authenticated-dast` |
| `BF-scorchkit-version-probe-secret-leak-001` | credential-boundary bug | `AAR-013-authenticated-dast` |
| `BF-scorchkit-url-only-operation-coverage-001` | coverage-integrity bug | `AAR-013-authenticated-dast` |
| `BF-scorchkit-graphql-import-variant-001` | schema-boundary bug | `AAR-013-authenticated-dast` |
| `BF-scorchkit-artifact-entry-undercount-001` | resource-budget bug | `AAR-013-authenticated-dast` |
| `BF-scorchkit-trusted-input-reopen-race-001` | provenance-integrity bug | `AAR-014-trusted-nuclei` |
| `BF-scorchkit-adapter-incomplete-status-elevation-001` | coverage-integrity bug | `AAR-014-trusted-nuclei` |
| `BF-scorchkit-preprocess-aggregate-budget-gap-001` | resource-budget bug | `AAR-014-trusted-nuclei` |
| `BF-scorchkit-address-authorization-artifact-order-001` | authorization-order bug | `AAR-014-trusted-nuclei` |
| `BF-scorchkit-compound-guard-mutation-gap-001` | test-gap bug | `AAR-014-trusted-nuclei` |
| `BF-scorchkit-evidence-provenance-splice-001` | evidence-integrity bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-transition-audit-erasure-001` | audit-integrity bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-correlation-cross-product-budget-001` | resource-budget bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-durable-raw-column-divergence-001` | persistence-integrity bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-method-only-correlation-001` | correlation-integrity bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-report-before-validation-001` | projection-integrity bug | `AAR-015-source-runtime-correlation` |
| `BF-scorchkit-status-only-persona-certification-001` | evidence-integrity bug | `AAR-016-application-pentest` |
| `BF-scorchkit-native-response-unbounded-001` | resource-budget bug | `AAR-016-application-pentest` |
| `BF-scorchkit-application-scan-split-transaction-001` | persistence-integrity bug | `AAR-016-application-pentest` |
| `BF-scorchkit-ambient-cargo-target-worker-sharing-001` | build-isolation bug | `AAR-017-codex-appsec-workflows` |
| `BF-scorchkit-compile-runtime-scope-mismatch-001` | test-isolation bug | `AAR-017-codex-appsec-workflows` |
| `BF-scorchkit-workflow-boundary-mutation-gap-001` | test-gap bug | `AAR-017-codex-appsec-workflows` |
