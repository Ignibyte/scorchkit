---
aar: AAR-001-rustal-quality-workflow
ticket: TICKET-001
pipeline: rustal-quality-workflow
status: submitted
opened: 2026-08-15
submitted: 2026-08-16
effectiveness: 5 - exposed and closed baseline defects while preserving executable evidence
---

# AAR-001 — Adopt Rustal-quality delivery workflow

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| Rustal Constitution §§0/3/15 | Direct comparison of binding quality, phase, and receipt rules. | yes — established stable gate IDs, ordered phases, and content receipts. |
| Rustal TICKET-145/146/154/157/158 lessons | Gate and helper inspection. | yes — caused derived feature states, warning-aware Rustdoc, receipt scope, failure clarity, and local mutation scratch. |
| ScorchKit legacy pipeline archive | Read current templates and a completed WORK record. | yes — proved the migration must replace Forge/Claude coupling without deleting history. |
| Official OpenAI skill documentation | Current documentation lookup. | yes — selected `.agents/skills` for repository discovery. |

## What happened

- The first canonical delivery run passed the fast policy checks but exposed a shared-state race in
  MCP schedule tests, five network-dependent tests that consumed the 300-second scan timeout, and an
  N×N production defect in `do_run_due_scans`.
- The CLI and MCP now use one structured due-schedule executor. A short `FOR UPDATE SKIP LOCKED`
  transaction claims and advances rows before releasing its connection and starting scan effects.
  Two simultaneous MCP callers are tested against two due schedules and produce exactly two
  persisted scan records.
- Executing MCP tests now use loopback mock servers and assert success and persistence. The MCP
  binary fell from roughly 450 seconds with intermittent failures to 1.31 seconds; Nextest ran all
  1,191 cases in 6.93 seconds.
- The first real diff mutation run completed at 43.47% MSI: 80 caught, 104 missed, and 100 unviable.
  Its survivors became the ordered baseline-hardening program in the roadmap rather than being
  hidden by exclusions or a lowered floor.
- The first boundary burn-down added exact contract assertions and extracted one pure profile-policy
  decision. On the final current tree, its focused mutation set caught 19 viable mutants, missed
  none, and classified two impossible tuple replacements as unviable.
- DAST and SAST wrappers now execute through a context-owned `ToolExecutor`. One registry contract
  covers 45 bounded DAST wrappers and all 21 SAST wrappers. A focused current-tree run caught all 66
  erased-wrapper mutants. Interactsh uses the same process-group owner through a separate
  long-lived session contract.
- Native DNS, TLS, TCP, infrastructure, and WebSocket connections now use `PolicyNetwork`. It
  authorizes derived hostnames before resolution, every returned address before use, and the
  concrete socket passed to the protocol client.
- The supported cloud registry contains five bounded external-tool adapters. Twelve native AWS,
  GCP, and Azure SDK modules are private and test-only until their authentication and service
  transports can enforce the same address policy.
- The public extension contract now exposes policy-owned HTTP access and family `add_module` seams.
  The DAST and SAST example crates compile and test as standalone consumers.
- CLI profile validation now fails before effectful contexts are built, every assessment family
  observes the selected profile, and one report-emission function owns artifact selection.
- A post-upgrade DIFF run passed gates 1–15 and reached 72.66% line coverage, then cargo-mutants
  failed its copied-tree baseline because a newly written Interactsh fixture could not execute
  directly. Invoking fixture scripts through `/bin/sh` removed that filesystem assumption. A real
  one-mutant shard then completed the copied baseline and caught the mutant.
- The mutation wrapper previously calculated zero completed mutants as 100% before checking the
  cargo-mutants exit status. It now records incomplete evidence as `completed: false` with a null
  score and exits before displaying score or blind-file claims.
- A later mutation pass found 13 surviving effect and presentation cases. Tests now call the CLI
  project and schedule bodies, force database and PDF destination errors, and assert the shared
  quiet/count predicates. The focused 36-mutant run caught those 13 and exposed nine report-diff
  arithmetic survivors.
- The report test used equal old and new totals, so several wrong formulas still rendered expected
  counts. A built-CLI test now compares asymmetric reports and asserts new, resolved, unchanged,
  identity, heading, and trend output. The exact nine-mutant rerun caught all nine.
- The canonical DIFF gate passed all 19 applicable gates. Coverage reached 77.94%. Mutation
  processed 876 cases and caught all 639 viable variants, including 41 timeouts, with 237 unviable
  and zero missed. The completed blind-file report listed 85 changed Rust files, all assigned a
  direct evidence disposition in the completed pipeline notes.
- A later full-repository run was stopped at the owner's direction after it had already exposed 115
  survivors. Its preserved summary is explicitly incomplete and has no score. The survivors were
  concentrated in 14 files and became a bounded 42-function repair list.
- The focused repair campaign selected 171 mutations. It caught 159 on the first pass, exposed three
  missing project-section assertions, and produced nine unviable variants. After the assertions were
  added, an exact three-item recheck caught all three. The final focused result is 162/162 viable
  mutations caught, zero missed, nine unviable, and 100% MSI.
- The owner-approved focused-repair receipt reconstructs that result from the raw outcomes and binds
  it to the current mutation inputs. It reruns every non-mutation delivery lane and records both the
  receipt mode and evidence digest. A source, test, manifest, migration, evidence, or worktree change
  invalidates delivery without launching another broad mutation inventory.
- The pre-completion focused-repair gate passed 19 applicable gates, kept the three web-only skips
  visible, measured 78.68% line coverage, verified 162/162 viable focused mutations, and passed
  Nextest, PostgreSQL, CLI, and MCP lanes. The pipeline consumed its versioned receipt and passed
  Validate before completion edits made that receipt stale.
- Completion archived TICKET-001 and its spec/notes pair, then exposed stale cross-links in the
  moved frontmatter and body. The archive transition now rewrites both documents before moving
  them, and its selftest rejects the old active/open paths. The first post-archive focused-repair
  gate then passed 19 applicable gates with zero failures and three named web skips without
  launching cargo-mutants; the completion-record edit deliberately leaves the later exact-tree
  receipt as the authoritative delivery proof.
- The next coverage pass exposed an OOB teardown race: the fixture could exit after `try_wait` but
  before process-group signaling, and macOS returned `EPERM` while the child was being reaped.
  Shutdown now classifies that transition, gives it a one-second observation bound, and returns
  other live-child termination errors immediately. Mutation was limited to the two repaired
  functions and caught all five viable mutants; one variant was unviable. Cumulative focused
  evidence is 167/167 viable caught, zero missed, and 10 unviable.

## Novel findings

- A public MCP endpoint queried the due set, then called a CLI function that queried and executed the
  entire due set again for every row. With N schedules it performed N² scans and falsely attributed
  batch success to each schedule.
- Database integration tests that make assertions about a global set cannot rely on unique row names;
  they need a database-visible serialization primitive around arrange, act, assert, and cleanup.
- A test that accepts either success or a network timeout tests no postcondition and can make strict
  timeout enforcement take minutes while still reporting green.
- The mutation gap is architectural: 63 of 104 missed mutants are copied external-tool `run`
  implementations. A shared adapter contract and fixtures are higher leverage than 63 isolated
  patches.
- A private function that only delegates to another tested function is not a useful seam. Mutation
  proved both constant outcomes were invisible, so the wrapper was removed instead of receiving a
  wrapper-only test.
- Parser tests cannot prove that a wrapper starts its declared tool. Injecting one owned invocation
  boundary into both contexts made executable identity, arguments, timeout, exit policy, and output
  limit observable without installing or running 66 security tools.
- A protocol library can perform a second hostname resolution after an earlier policy-aware
  discovery request. The WebSocket client did this until ScorchKit supplied its already-authorized
  concrete connection.
- Provider SDK feature flags are not a security boundary when their transport cannot accept the
  engine's resolver and connector. Keeping those modules private, test-only, and unregistered makes
  the unsupported surface explicit while preserving pure parser and posture tests.
- Documentation examples are part of the public API contract. Closing unsafe constructors without
  compiling standalone examples left users with instructions that could not work.
- An accepted CLI option needs a behavior-level assertion. Parsing `--profile` or an output format
  does not prove the value reaches each scanner family or controls artifact creation.
- A repository gate must inspect the same content domain as its receipt. Taplo's implicit recursive
  discovery entered `.git` and treated a sealed security-validation harness as worktree source even
  though `.git` is intentionally outside the receipt.
- Focused mutation evidence stored outside the worktree needs two bindings. One hash seals the Rust,
  test, manifest, configuration, example, migration, and rule inputs. A second digest binds the raw
  evidence to the exact-worktree receipt.
- A selected mutation function can produce no mutant. Evidence must distinguish the requested
  function scope from the functions present in the generated inventory.
- An exceptional receipt mode needs executable ticket scope as well as policy text. TICKET-001 is
  checked by both the gate and pipeline, and the sealed input includes HEAD so the evidence expires
  after delivery is committed.
- Archive moves must rewrite cross-document links as part of the same transition. Moving a valid
  ticket/spec pair without changing its `open/` and `active/` frontmatter leaves a structurally
  closed pipeline with broken historical navigation.
- Module-local locks do not serialize process-global environment variables across modules. NVD and
  OSV cache tests each held a different mutex and could overwrite the other's `XDG_CACHE_HOME`.
- A fixture deadline should measure the behavior under test. Reusing a two-second process timeout in
  an output-boundary contract made clean-build load look like an output-limit regression even though
  the dedicated timeout contracts remained green.
- A test fixture's contents can be portable while its launch mechanism is not. Passing a temporary
  script to a trusted system shell avoids depending on executable permissions for newly written
  files while preserving the exact program and argument contract under test.
- Mutation score has meaning only after the runner recognizes a completed cargo-mutants status.
  Baseline failures may still create an outcomes file, so zero outcomes alone cannot mean 100%.
- Testing a lower-level storage helper does not prove that an async CLI command awaits it. Erasing
  the command body can survive unless a test calls the command and observes its error or artifact.
- Symmetric fixtures hide arithmetic defects. Equal old and new report totals allowed addition and
  division mutants to produce the same visible counts as subtraction.
- A completed mutation run can still name changed Rust files with no selected mutant. The final
  blind-file list needs its own exact diff review and direct evidence ledger.
- One broad mutation inventory is enough to produce a repair queue. Repeating the inventory after
  every mutation wastes hours and obscures whether the rerun verifies the changed seam. Preserve the
  inventory, repair the named functions, and rerun only those functions until a separately scheduled
  full campaign is warranted.
- A child can exit between a nonblocking state check and process-group signaling. An exited-child
  permission error needs a bounded confirmation path; treating every permission error as either
  fatal or harmless can respectively create teardown flakes or hide a live cleanup failure.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-scheduler-n-squared-001` | MCP due-scan execution invoked the all-due CLI loop once per due row, producing duplicate scans and misleading outcomes. | Gate 3 database-backed MCP tests and source inspection. |
| `BF-scorchkit-websocket-second-resolution-001` | WebSocket discovery used policy HTTP, but the handshake client resolved the hostname again outside the policy-owned connector. | Final network-sink inventory and the denied-hostname regression. |
| `BF-scorchkit-test-environment-race-001` | NVD and OSV tests used different locks while mutating the same process-wide cache-root variable. | Canonical DIFF gate 3 and a two-test parallel stress probe. |
| `BF-scorchkit-orthogonal-test-timeout-001` | The exact-output-limit fixture used a two-second process deadline unrelated to its byte-boundary assertion and failed under clean-build load. | Post-upgrade canonical DIFF gate 3. |
| `BF-scorchkit-mutants-temp-script-spawn-001` | The mutation copied-tree baseline tried to execute a newly written Interactsh fixture directly and received `Operation not permitted`. | Canonical DIFF gate 16 before any mutant ran. |
| `BF-scorchkit-mutants-incomplete-score-001` | Cargo-mutants status 4 with zero outcomes was rendered as 100% MSI before the wrapper exited red. | Canonical DIFF gate 16 compact evidence and terminal output. |
| `BF-scorchkit-mutation-effect-erasure-001` | CLI query commands and PDF saving could be replaced with immediate success because tests did not call the effect-owning body and observe its result. | Pre-canonical mutation survivor set and the 36-mutant focused rerun. |
| `BF-scorchkit-report-output-symmetry-001` | Equal report totals hid incorrect subtraction and comparison mutations in human diff output. | First 36-mutant focused run left nine report survivors. |
| `BF-scorchkit-mutation-rescan-cost-001` | A repository-wide mutation campaign continued after its survivor inventory was sufficient to direct a focused repair batch. | The stopped full run and the owner's 2026-08-16 scope correction. |
| `BF-scorchkit-exited-child-killpg-race-001` | A naturally exiting OOB child crossed from running to exited between `try_wait` and `killpg`, producing a macOS `EPERM` teardown failure. | Final post-archive coverage gate and the OOB session regression. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-loopback-integration-001` | Use loopback mocks for automated scan execution and assert the intended success or persisted effect. | Reserved remote addresses consumed the full scan timeout and the tests accepted failure as valid. |
| `PR-scorchkit-global-set-lock-001` | Serialize database-wide due-set operations in production and their arrange/act/assert/cleanup tests. | Unique fixtures do not isolate a query that intentionally selects every due row. |
| `PR-scorchkit-gate-prerequisites-001` | Skip expensive dependent tiers after static failure and skip mutation when coverage fails. | The first red run spent roughly two hours on mutation after gate 3 had already disproved delivery readiness. |
| `PR-scorchkit-observable-seams-001` | Extract decisions into pure, asserted seams, but remove behavior-free delegates and keep one tested owner. | Thin forwarding wrappers can survive constant mutations because they add no independently observable behavior. |
| `PR-scorchkit-executor-contract-001` | Route bounded external tools through an injectable context-owned executor and test every registry entry against its declared invocation. | Parser-only tests did not detect erased wrapper execution. |
| `PR-scorchkit-derived-network-policy-001` | Authorize a derived hostname before DNS, every answer before use, and pass an authorized concrete connection to protocol libraries that would otherwise resolve again. | Native protocol paths and WebSocket handshakes can escape a URL-only policy layer. |
| `PR-scorchkit-doc-examples-contract-001` | Compile standalone examples against the public API whenever extension constructors, contexts, or registration seams change. | Narrative documentation continued to teach closed internal constructors. |
| `PR-scorchkit-provider-transport-quarantine-001` | Keep provider modules private, test-only, and unregistered until authentication and service transports are owned by ScorchKit policy. | Cloud SDK clients did not expose the resolver and connector controls required by the engagement boundary. |
| `PR-scorchkit-cli-options-observable-001` | Prove every accepted profile and output option through scanner selection or artifact behavior, not parser-only assertions. | Assessment families and report paths silently diverged despite accepting the same options. |
| `PR-scorchkit-gate-worktree-scope-001` | Enumerate tracked and unignored worktree files before invoking recursive formatters or linters that may otherwise descend into `.git`. | Taplo inspected sealed security evidence outside the receipt's content domain. |
| `PR-scorchkit-process-env-test-lock-001` | Serialize every library test that mutates process-wide environment variables through one crate-wide mutex. | Locks scoped to individual modules did not protect NVD from OSV's concurrent cache-root mutation. |
| `PR-scorchkit-orthogonal-test-budget-001` | Give a fixture enough bounded time for setup and execution unless deadline behavior is the contract being asserted. | A byte-boundary test's unrelated two-second deadline produced a false signal under loaded clean-build execution. |
| `PR-scorchkit-test-shell-fixtures-001` | Run newly written shell fixtures through an explicit trusted shell and pass the fixture path as an argument. | Direct execution depends on mount and temporary-filesystem permissions unrelated to the process behavior under test. |
| `PR-scorchkit-mutation-completion-evidence-001` | Publish mutation score and blind-file claims only after cargo-mutants returns a recognized completed status; represent incomplete scores as null. | A baseline failure can produce a valid but empty outcomes file that is not a completed 100% result. |
| `PR-scorchkit-mutation-effect-observation-001` | Call each effect-owning async command in a test and observe its error, state change, or artifact instead of relying only on lower-level helper tests. | An erased command body can return success without reaching the already-tested helper. |
| `PR-scorchkit-process-output-contract-001` | Test human CLI and report output through the built process with asymmetric fixtures and exact semantic assertions. | In-process helper tests did not capture terminal output, and symmetric counts hid arithmetic defects. |
| `PR-scorchkit-presentation-predicate-001` | Give repeated quiet and cardinality decisions one shared predicate owner with a complete truth table. | Copied presentation branches were inconsistently observable across command paths. |
| `PR-scorchkit-canonical-blind-ledger-001` | Review the completed mutation run's exact blind-file list and assign every path a direct evidence disposition. | A pre-run inventory cannot predict unviable-only files or the final selected mutant set. |
| `PR-scorchkit-focused-mutation-repair-001` | Preserve one broad survivor inventory, repair its named seams, and rerun only the exact repaired functions; run a new full inventory as scheduled evidence rather than after each edit. | The 171-item focused campaign closed 162 viable mutations while avoiding another 5,730-item repository sweep. |
| `PR-scorchkit-focused-evidence-binding-001` | Bind focused mutation evidence to both its mutation-relevant inputs and the exact delivery receipt, then reconstruct counts and survivor identity from raw outcomes. | Evidence lives under `.git`, outside the worktree fingerprint, and must become stale when either source inputs or evidence changes. |
| `PR-scorchkit-archive-link-integrity-001` | Rewrite ticket and spec cross-links to their closed and completed destinations before the pipeline moves either artifact. | The first archive moved both files but left their frontmatter pointing to paths that no longer existed. |
| `PR-scorchkit-bounded-process-exit-race-001` | Classify process-group termination failures against observed child state, bound only the exited-child permission transition, and return live-child errors without waiting indefinitely. | A child can exit between state observation and signaling; unbounded reconciliation turns a cleanup error into a hang. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

5 - The workflow found and fixed authorization, network-policy, process-lifecycle, scheduler,
terminal, secret-handling, documentation, test-race, and mutation-observability defects while
keeping one ticket, one inspect ledger, and executable delivery evidence. The owner-directed stop to
broad rescans became a narrow, testable receipt rule rather than an unrecorded bypass. The remaining
full inventory and architectural refactors are ordered in the roadmap with concrete exit evidence.
