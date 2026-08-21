---
title: Codex-first application-security workflows and tiered scan profiles — notes
pipeline_id: 59f9a729-0811-49ee-9bdd-ab9f0a41e280
---

# Codex-first application-security workflows and tiered scan profiles — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `PR-scorchkit-policy-before-effects-001` and
    `PR-scorchkit-credential-use-separate-grant-001`: context and plans never replace exact
    target/capability/effect authorization, and persona labels never expose credentials.
  - `PR-scorchkit-host-workflow-tool-contract-001`: plugin prose is an executable public contract;
    positive and negative validators must cover tool ownership and phase crossovers.
  - `PR-scorchkit-semantic-token-policy-check-001`: workflow validators must inspect semantic
    operation tokens, not merely search for convenient prose fragments.
  - `PR-scorchkit-default-catalog-explicit-compatibility-001`: every implicit profile remains
    application-only; compatibility network, enterprise, and cloud families require explicit use.
  - `PR-scorchkit-generated-dast-plan-001` and `PR-scorchkit-policy-before-effects-001`: host plans
    are context; executable plans are compiled from closed types and remain separately authorized.
  - `PR-scorchkit-proof-evidence-own-provenance-001`: Codex Security output and other host analysis
    cannot inherit scanner-evidence status through a workflow result.
  - `PR-scorchkit-mutation-branch-directness-001`: profile, scope, and gap branches need direct
    truth-table assertions before mutation validation.
  - `PR-scorchkit-scan-coverage-projection-parity-001`: context and workflow gaps must survive MCP
    serialization and plugin interpretation without being converted into clean coverage.
- Recon evidence:
  - The existing plugin has five phase skills and a validator that fixes the exact inventory. It
    has no application-profile coordinator and currently requires operational skills to use only
    ScorchKit MCP.
  - The local MCP server exposes 37 tools, including source scanning, supply chain, application
    DAST, correlation, application-pentest planning/execution, and manual evidence import.
  - TICKET-015 already returns stable inert focused selectors, but no workflow consumes them.
  - Code context discovery already provides bounded no-follow language and manifest inventory
    behind `CodeScan`/`Passive` policy authorization. Persona labels are configuration keys and
    project targets are durable inventory, not grants.
  - The existing deterministic source and supply-chain tools accept a root, not an exact changed
    path set. Commit/PR planning must preserve this as a typed gap instead of widening execution.
  - Official Codex plugin documentation supports skills that coordinate tools already available to
    the model while MCP defines controlled operations. Official Codex Security change-review
    documentation scopes a review to one Git change set and distinguishes it from a repository scan.
- Operator confirmation: the owner directed work to continue through the next roadmap ticket,
  authorized automatic commits for green tickets, prohibited repeated full/repository mutation
  scans, and did not authorize a push.

## Phase 2 — Design

- Architecture:
  - Added `docs/architecture/appsec-workflows.md` with the inert context/plan boundary, provider
    ownership, monotonic profile table, explicit broad-step labels, focused-verification behavior,
    MCP/plugin contract, and evidence/authorization separation.
  - `application_context` performs only the existing policy-gated bounded local code discovery and
    optional project inventory read. `plan_appsec_workflow` rebuilds that context and compiles an
    inert plan; it does not cache caller state or execute a named step.
  - Commit and pull-request semantic steps require distinct immutable hexadecimal base/head IDs and
    a canonical changed-path set. Root scanners remain visibly broad because their public contract
    cannot enforce an exact changed-file selection.
  - Codex Security supplies labeled semantic diff/repository review at the host layer. ScorchKit
    MCP owns deterministic effects and evidence. Neither output is silently promoted into the
    other's provenance layer.
  - Focused selections are preferred. Exact selectors that cannot be enforced through a current
    public tool are gaps, not permission to substitute a broader module or scan.
- File manifest:
  - `crates/scorchkit-core/src/{appsec_workflow,lib}.rs` and core tests: versioned context,
    change-set, declared input, profile, step, gap, status, owner, scope, requirement, focused
    selection, canonicalization, and stable identity contracts.
  - `crates/scorchkit-mcp/src/{types,contract,instructions}.rs`, `src/mcp/{tools,instructions}.rs`,
    MCP fixtures and tests: bounded context/profile/focused inputs, two read-only tools, exact
    inventory/annotation/router/schema parity, structured results, registered targets, persona
    labels, and effect inventory without credentials.
  - `plugins/scorchkit/.codex-plugin/plugin.json`,
    `plugins/scorchkit/skills/run-application-security-workflow/**`, and
    `bin/codex-plugin-contract.sh`: sixth coordinator skill, UI metadata, correct Codex Security
    scan-class mapping, MCP-only deterministic effects, semantic/scanner separation, focused-first
    behavior, and negative fallback contracts.
  - `docs/architecture/appsec-workflows.md`, `docs/guide/codex-plugin.md`, MCP guidance, README,
    changelog, roadmap, intake, ticket, notes, and AAR: durable architecture, operator workflow,
    delivery evidence, and roadmap closure.
- Regression test plan:
  - Context matrix: absent/invalid/noncanonical roots; symlink and out-of-root paths; exact entry and
    byte limits; duplicate/order normalization; source-language/manifest inventory; route and
    artifact declarations; persona labels; registered-target URL credential/query redaction;
    configured capability/effect inventory; stable and field-sensitive identities.
  - Change-set matrix: missing one side, equal revisions, nonhex/mixed-case/oversized revisions,
    absolute/traversal/empty/control paths, duplicates, exact count/length boundaries, permutation
    stability, and engine-unverified provenance.
  - Profile truth table: exact kinds/order/owner/scope/tool/broadness/requirements for all five
    profiles; strict monotonic expansion; no compatibility family; no credential/exploit effect;
    missing project/target/artifact/route gaps; no grant manufactured by profile selection.
  - Focused matrix: identity mismatch, duplicate selectors, supported exact rows, unsupported rule,
    template, request/persona, and test rows, stable ordering/identity, and no implicit broad
    fallback.
  - MCP matrix: exact 39-tool inventory, read-only annotations, schema generation, direct and routed
    structured success/error, stateless/project contexts, bounded no-follow discovery, database
    target inventory, persona labels without secret references, and output parity.
  - Plugin matrix: exact six-skill inventory; required application context/plan calls; commit/PR
    diff scan, release standard repository scan, deep repeated repository scan; MCP-only engine
    effects; no raw command, unsupported-scope fallback, analysis promotion, automatic broad rescan,
    or authorization inference.
  - Validation runs focused unit/contract tests and `--fast` during development, then one `--diff`
    delivery run. No full or repository-wide mutation inventory is allowed.

## Phase 3 — Implement

- Files and behavior changed:
  - Added provider-neutral, versioned application context, immutable change-set, profile, step,
    status, gap, provenance, focused-selection, and stable identity contracts in
    `scorchkit-core`. Every workflow is inert, closed, ordered, and explicit about broad work and
    later authorization requirements.
  - Added read-only `application_context` and `plan_appsec_workflow` MCP tools. Context discovery
    uses the existing policy-gated, bounded code walk; project targets and persona labels remain
    credential-free inventory; planner calls execute no named step.
  - Added the sixth Codex plugin skill, mapping exact change reviews to Codex Security diff scans,
    release repository review to a standard repository scan, and deep review to its explicit deep
    scan. Deterministic effects remain ScorchKit MCP operations and host analysis never becomes
    scanner evidence.
  - Extended the executable plugin contract, MCP tool/schema fixture, root and crate tests,
    architecture, MCP/operator documentation, README, and changelog.
  - Hardened the existing mutation scratch selector to classify the mounted filesystem instead of
    rejecting every `/Volumes` path. It still rejects the worktree and network filesystem types.
- Design deviations:
  - The owner added a local APFS build disk during implementation. User Cargo configuration now
    places ordinary targets under `/Volumes/Offload/Builds/cargo-target`, and the mutation scratch
    setting points to `/Volumes/Offload/Builds/scorchkit-mutations`. These machine-local settings
    are outside the repository; only the portable local-filesystem validation belongs to this
    ticket.
  - No public scanner contract can enforce the focused rule/template/request/test selectors yet.
    The planner therefore reports every focused selection as unsupported and never substitutes a
    broad scan. Executable focused adapters remain later roadmap work.
  - Removed an unused serialization error case because canonical hashing is infallible at this
    boundary. Added lexical canonical-root rejection in core while the MCP adapter continues to
    perform filesystem canonicalization and policy authorization.
- Focused implementation checks:
  - `cargo test -p scorchkit-core appsec_workflow --no-default-features`: 5 passed.
  - `cargo test -p scorchkit-mcp`: 6 passed.
  - `cargo test --features mcp --test mcp_tools application_context`: 3 passed.
  - `cargo test --features mcp mcp::contract`: 6 passed.
  - `cargo clippy -p scorchkit-core --all-targets -- -D warnings`: passed.
  - `cargo clippy --features mcp --all-targets -- -D warnings`: passed after correcting one test
    fixture initializer.
  - `cargo fmt --all -- --check`, ShellCheck, plugin self-test, and mutation configuration
    self-test: passed.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Codex Security diff scan `08193288-1517-4466-bf71-3a3a80999678` | The new macOS filesystem probe used the file-type formatter, which returned `/` for both APFS and SMB. The nonempty value bypassed the GNU fallback and could let an out-of-worktree network share pass the local-scratch guard. | Security policy: ignored; implementation quality: must fix | Replaced the probe with exact Darwin mount-table filesystem extraction plus a closed local-filesystem allowlist. Added positive and negative self-test rows. |

- Exact reviewed snapshot:
  `codex-security-snapshot/v1:sha256:56c65b7b7d3dbdf8db4c16ce8f78e61bb69eb073cd192b8ecd4d9a75560edb45`.
- Coverage: 14/14 authoritative changed-source rows, plus manual review of the executable plugin
  skill and security-relevant operator documentation; no deferred surfaces.
- Final security result: no reportable findings. The one real classifier defect required
  developer/operator environment control, so attack-path policy suppressed it as a vulnerability
  while the ticket retained it as a required correctness repair.
- TAC advisory: account status could not be verified because the Security Access connector was not
  signed in. This did not affect local diff coverage or ScorchKit authority.
- Review artifacts: generated report, SARIF, findings, and coverage under the scan directory
  recorded by scan ID above. Codex Security measured 6,148,113 total tokens across the one-thread
  review.
- Post-review focused repair proof (no broad rescan): ShellCheck passed; mutation self-test passed;
  inventory-only mutation inspection selected `/Volumes/Offload`; and the same inspection with
  `SCORCHKIT_MUTATION_SCRATCH=/Volumes/srv` failed before creating a run directory or starting
  Cargo. The repair also recognizes GNU's `ext2/ext3` label while unknown types fail closed.
- Fast-gate repair: the all-feature suite exposed a supported-macOS alias mismatch in the existing
  trusted Nuclei collection helper (`/var/...` versus canonical `/private/var/...`). The helper now
  canonicalizes the comparison root before its component-aware containment check; the existing
  symlink and traversal defenses remain in place. A missing required justification was also added
  beside the new step-identity lint suppression.
- The next all-feature pass exposed the same alias only in the CodeQL adapter contract's expected
  working directory. Production already used the canonical code root; the test now compares
  against that canonical root instead of the temporary directory's `/var` spelling.

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `cargo test --all-features --test external_tool_contract codeql_executes_no_build_create_then_offline_analyze_and_cleans_artifacts -- --exact`: 1 passed.
  - `cargo fmt --all` and `git diff --check`: passed.
- Gate run and receipt:
  - `bash bin/gate.sh --fast`: green; 14 passed, 0 failed, and the 8 documented
    fast-mode/not-applicable lanes skipped. Build and documentation artifacts were written under
    `/Volumes/Offload/Builds/cargo-target`.
  - Exact-tree DIFF validation: pending.
  - First `bash bin/gate.sh --diff` attempt: 18 lanes passed, including coverage, nextest,
    PostgreSQL, and CLI/MCP contracts. The mutation lane stopped before compiling a mutant because
    its unmutated isolated-worktree baseline exposed two workflow tests whose requested path came
    from the original compile-time manifest directory while their engagement scope came from the
    runtime working directory. No mutant was executed; focused fixture repair is in progress.
  - Second `bash bin/gate.sh --diff` attempt: the same 18 non-mutation lanes passed and the
    isolated baseline advanced through context construction. It then exposed a second fixture
    assumption: the context assertion required the checkout directory to be named `scorchkit`.
    Cargo-mutants correctly gives its isolated copy a generated name. No mutant was executed;
    the assertion now compares the exact canonical runtime root. The exact test passed both in the
    repository and when its current binary ran from a disposable generated-name Offload copy.
  - Third `bash bin/gate.sh --diff` attempt: the isolated baseline passed and selected 177
    changed-tree mutants. The run was intentionally stopped after process inspection showed that
    the host-global absolute Cargo target setting made both workers share one build directory.
    Those partial outcomes were not accepted as evidence. The runner now exports the relative
    target `target`, which overrides ambient Cargo configuration and resolves separately inside
    each worker copy under Offload. ShellCheck, the mutation self-test, and Cargo metadata proofs
    for both the ordinary absolute target and relative worker target passed.
  - Fourth `bash bin/gate.sh --diff` attempt: intentionally stopped in the all-feature lane after
    the quality-contract tests exposed a binary left in the formerly shared target with an embedded
    path to a deleted mutation copy. The source tree was intact. `cargo clean -p scorchkit` removed
    the contaminated generated package artifacts from Offload while retaining dependency caches;
    the exact quality-contract test then passed 2/2 from the canonical repository.
  - Fifth `bash bin/gate.sh --diff` attempt: intentionally stopped when the all-feature suite found
    a second contaminated artifact in `scorchkit-core`, proving the earlier shared target affected
    workspace packages beyond the root crate. The generated artifacts for all 14 ScorchKit
    workspace packages were removed explicitly while third-party dependencies stayed cached. The
    exact core change-set test passed 1/1 and the quality-contract test passed 2/2 after canonical
    rebuilds.
  - Sixth `bash bin/gate.sh --diff` attempt: all 18 applicable non-mutation lanes passed, with only
    the three web-only lanes skipped. The completed mutation lane selected 177 changed-tree
    mutations and recorded 84 caught, 40 timed out, 28 missed, and 25 unviable: 124/152 viable
    outcomes caught, or 81.57% MSI. The raw inventory is preserved as the broad baseline under
    `.git/scorchkit-mutants-focused-ticket-017`; the owner-approved repair scope is exactly its 28
    survivors in 12 functions across two source files. Only those survivors will be rechecked.
  - Focused repair tests: all 9 `scorchkit-core` application-workflow unit tests passed, including
    direct profile, gap, requirement, identity, revision, path, route, and collection boundaries;
    the exact database-backed registered-target label test passed 1/1.
  - Focused mutation selection: inventory-only matching selected exactly the original 28 survivor
    names in 12 functions/two files. The isolated Offload recheck caught all 28 in 18 minutes with
    zero misses, timeouts, or unviable outcomes. The sealed evidence reconstructs 152/152 viable
    outcomes caught at 100% MSI, binds mutation input
    `d1b5a06c0d652638c368f653bb6e9c81848d10347e08115b075492198eff6b8f`, and has evidence digest
    `dcd9ffa1a7a6732c1499309d95802ce0d93eede444566c537f331ac7be6c3945`.
  - Pre-completion exact-tree focused-repair gate: green with 19 applicable lanes passed, no
    failures, and 3 named web-only skips. It verified the sealed mutation evidence without launching
    cargo-mutants. Canonical line coverage was 81.75%; Nextest passed 1,873 cases with 10 reasoned
    skips; PostgreSQL passed 77 MCP, 12 storage, and 10 storage-integration cases; CLI/MCP contracts
    passed 22 CLI, 2 code-scan, 77 MCP, and 12 scan-plan cases.
- Documented skips with reasons:
  - The fast gate intentionally skips coverage, mutation, nextest strictness, PostgreSQL, and
    CLI/MCP contract lanes; the DIFF delivery gate runs the applicable changed-tree lanes next.
  - Browser, website-render, and built-CSS lanes do not apply because ScorchKit has no web UI or
    web asset pipeline.

## Phase 5 — Complete

- Docs updated: application workflow architecture, MCP and Codex plugin guides, README, changelog,
  roadmap, intake, ticket, executable plugin contracts, and the knowledge register now describe the
  shipped SK-042 boundary and exact delivery evidence.
- AAR submitted: `AAR-017-codex-appsec-workflows` on 2026-08-21 with effectiveness 5/5 and seven new
  reusable failure/prevention entries registered in the knowledge index.
- Archive: the pipeline-owned transition closed TICKET-017 and archived its spec and notes. A
  post-archive focused-repair gate will bind the final exact tree before commit.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | The first macOS local-filesystem guard could not distinguish APFS from SMB. | BSD `stat -f '%T'` reports a file-type suffix, not the mounted filesystem type. A blacklist then accepted the unexpected nonempty value. | Read the exact Darwin mount-table type and use a closed local-filesystem allowlist; retain GNU `statfs` on Linux. | Exercise positive APFS/Linux labels, negative network/unknown labels, the actual configured Offload path, and the actual SMB mount. |
| 2 | Three existing trusted Nuclei path tests failed on macOS temporary directories. | The opened path was canonicalized but its supplied root retained the `/var` alias, making a valid child appear outside `/private/var`. | Canonicalize the root before `Path::starts_with` containment. | Keep direct, nested, symlink, parent-component, and validated-handle tests in the all-feature suite. |
| 3 | The justified-suppression gate rejected the new step identity helper. | The narrow `too_many_arguments` exception lacked the repository-required adjacent rationale. | Documented why every identity-bound field remains explicit. | The gate enforces justification locality for every suppression. |
| 4 | The CodeQL external-tool contract expected the noncanonical macOS temporary path. | `tempfile` exposed `/var/...` while the policy-sealed code context correctly retained `/private/var/...`. | Canonicalized the expected test root. | Compare security-boundary paths after canonicalization in platform-portable tests. |
| 5 | The mutation baseline rejected two new MCP workflow tests before executing a mutant. | The request used the compile-time manifest directory while the engagement fixture scoped the runtime working directory; cargo-mutants deliberately runs the baseline in an isolated copy. | Derive both the requested root and engagement scope from the runtime working directory. | Test fixtures that bind security scope must use one runtime root identity and remain valid in isolated delivery worktrees. |
| 6 | The repaired mutation baseline then rejected the workflow context's checkout-name assertion. | The test required the canonical code root to end in `/scorchkit`, but isolated delivery worktrees use generated directory names. | Compare the returned root with the exact canonical runtime root. | Assert path identity and security properties, not incidental checkout names. |
| 7 | Mutation workers shared the host-global Cargo target directory. | Clearing the environment variable exposed the absolute `target-dir` in the user's Cargo configuration, overriding cargo-mutants' source-copy isolation. | Export the relative target name `target` inside the mutation runner; Cargo resolves it independently in each Offload worker copy while ordinary builds retain the global Offload target. | Mutation launch must override ambient target configuration with a relative worker-local target and retain process-level inspection in delivery proof. |
| 8 | An ordinary quality-contract test read a deleted mutation-copy path. | The earlier shared target retained a test binary compiled in a mutation copy, including its compile-time manifest path. | Remove only ScorchKit package artifacts from the shared Offload cache and rebuild the exact test from the canonical tree. | Never share mutation worker targets with ordinary builds; after detecting target contamination, rebuild affected package artifacts before accepting any gate result. |
| 9 | A core change-set test retained mutated behavior after the root-package cleanup. | The shared target had contaminated workspace-package artifacts beyond the root package. | Remove generated artifacts for every explicit ScorchKit workspace package, preserve third-party dependency caches, and rebuild the exact root and core tests. | Treat a formerly shared mutation target as workspace-wide contamination, not a single-package cache defect. |
| 10 | The completed DIFF mutation baseline missed 28 workflow-boundary mutations. | Existing tests proved representative behavior but did not pin every public profile alias, gap-presence branch, authorization requirement, identity value, or exact length/count boundary. | Preserve the broad result, add direct boundary assertions, and recheck only the exact 28 survivors through approved focused-repair evidence. | Build closed truth tables and exact-limit tests before mutation validation; never repeat the broad inventory after a bounded repair. |
| 11 | The first focused core-test compile used a nonexistent `Repository` scope variant. | The test described the semantic scope rather than using the closed enum's actual `CodeRoot` spelling. | Corrected the test-only variant before any mutation run; the 9-test focused group then passed. | Compile focused tests before inventory or mutation execution and use the public closed vocabulary verbatim. |
