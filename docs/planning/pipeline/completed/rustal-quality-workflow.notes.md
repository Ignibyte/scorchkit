---
title: Adopt Rustal-quality delivery workflow — notes
pipeline_id: b1b510c8-0096-4083-af37-2ffaea595b10
---

# Adopt Rustal-quality delivery workflow — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: Rustal `CONSTITUTION.md` §§0/3/15/18/19, its ticket/spec/notes/AAR templates,
  gate receipt and pre-commit enforcement, feature-state derivation, nextest empty-suite check, and
  recent mutation scratch fixes. ScorchKit's legacy completed pipeline records confirmed that Forge
  and Claude command fields were obsolete.
- OpenAI Docs confirmed repository skills are discovered under `.agents/skills`; the skill remains an
  adapter while `bin/pipeline.sh` and versioned artifacts own state.
- Operator confirmation: the 2026-08-15 instruction explicitly requested the complete Rustal-style
  workflow and exact quality gates, excluding web checks.

## Phase 2 — Design

- Architecture: `CONSTITUTION.md` declares policy; `bin/pipeline.sh` is the artifact/state machine;
  `bin/gate.sh` is the delivery verdict; `bin/gate-state.sh` is the shared fingerprint; Git's
  `.githooks/pre-commit` is the agent-neutral enforcement point; `.agents/skills/scorchkit-pipeline`
  is a progressive-disclosure Codex adapter. Planning state remains Markdown with parseable YAML
  frontmatter and one active spec/notes pair.
- File manifest: add constitution, ticket/intake/spec/notes/AAR templates, knowledge and bulletin
  registers, pipeline/feature-state/gate-state scripts, pre-commit hook, Codex skill; update gate,
  mutation configuration/runner, CI, AGENTS, roadmap, and ignore rules.
- Compatibility: keep the existing completed WORK archive untouched. New ticket numbering begins at
  TICKET-001 in a separate authoritative store. The workflow uses Bash 3-compatible constructs where
  practical and invokes scripts through `bash` for the noexec SMB mount.
- Security: the hook is a discipline and integrity control, not a sandbox. Its receipt covers tracked
  and untracked non-ignored files, includes HEAD, and lives under `.git` so it cannot alter its own
  fingerprint. Missing hash tools, empty inputs, active pipelines, and stale receipts fail closed.
- Regression test plan: derive feature names from a fixture; create one synthetic pipeline and reject
  a second; accept a fresh receipt and reject it after content mutation; assert gate IDs 1–22 and the
  receipt writer; validate the Codex skill; run ShellCheck; inspect Nextest JSON; run the canonical
  fast gate; use one real cargo-mutants shard to prove local scratch and compact evidence.
- Operator confirmation: the requested Rustal parity fixes the design direction; web-only gates are
  explicit skips and project-specific database/contracts append as 21/22.

## Phase 3 — Implement

- Files and behavior changed: added the binding Constitution; canonical ticket state machine;
  content-addressed gate receipts; Git enforcement hook; derived feature-state helper; Codex repo
  skill; stable 1–22 gate runner; CI alignment; mutation scratch runner; ticket, intake, spec, notes,
  AAR, knowledge, and bulletin stores; roadmap and agent guidance; executable gate-contract tests.
- Regression enforcement: pipeline selftest rejects an early design transition, incomplete plan,
  and second active ticket; hook selftest accepts an exact receipt and rejects content mutation;
  feature selftest derives manifest states; Rust tests bind policy, gate IDs, web-only skips, CI,
  Nextest, coverage, mutation, and receipt wiring.
- Mutation behavior: inventory contains 5,504 mutants across 234 source files, excludes only the
  composition root and database-only functions, includes the policy kernel, and a one-mutant real
  shard was caught at 100% MSI using ephemeral local scratch with compact evidence.
- Design deviations: none. Gate IDs 17–19 remain named non-applicable skips as designed; ScorchKit
  database and CLI/MCP contract checks append as gates 21–22.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness / CI | CI applied migration SQL directly, so SQLx had no ledger and would reapply the same schema during tests. | high | Fixed: removed raw SQL application; the tested Rust migrator exclusively owns migration state. |
| 2 | Security / integrity | Receipt hashing dereferenced symlinks, so retargeting a link to equal-content files could preserve the fingerprint. | high | Fixed: the manifest hashes path, entry kind, file digest, and literal symlink target; regression test added. |
| 3 | Portability | Bash 3 strict mode treated the default Clippy state's empty array as unbound and aborted the canonical gate. | high | Fixed: the default branch invokes Clippy without an argument array; full fast gate proved all nine states. |
| 4 | Correctness | Blanket-lint detection matched the specific lint `unused_async` as though it were the `unused` group. | medium | Fixed: require a lint-token boundary; canonical gate:10 passed. |
| 5 | Data integrity | Completion did not preflight archive collisions and accepted an AAR without submission date/effectiveness. | medium | Fixed: collision, queue-row, date, and score checks now fail before archival mutation. |
| 6 | Test quality | Initial workflow selftest proved only creation and one-active behavior, not ordered or evidence-bearing transitions. | medium | Fixed: negative checks reject early design and placeholder plan evidence; gate-contract Rust tests added. |
| 7 | Simplification | Policy, state machine, receipt, hook, and Codex guidance have single owners with no duplicate agent-specific implementation. | none | Accepted: no further simplification change. |
| 8 | Security | Facade, CLI, MCP, project, and agent entry points could reach effectful contexts without an engagement. | high | Fixed: absence denies, production context constructors are crate-private, and every host routes through the policy-gated engine. Family and transport regressions prove denial before effects. |
| 9 | Security | Automatic redirects and DNS answers inherited the original hostname grant. | high | Fixed: one policy-bound HTTP layer reauthorizes the direct URL, each redirect, hostname, and every IPv4/IPv6 answer. DAST and CVE clients share it. |
| 10 | Data integrity | Stored schedules could become executable after policy expansion and did not bind the grant used at creation. | high | Fixed: migration 005 stores the exact engagement snapshot; execution requires an identical current grant, registered canonical target, and current profile authorization. Legacy rows fail closed. |
| 11 | Correctness / availability | The first scheduler correction still made advisory-lock waiters consume the same pool needed by the lock owner. | high | Fixed: removed the advisory lock. A short `FOR UPDATE SKIP LOCKED` transaction claims and advances rows before scan work; a one-slot, two-caller test proves bounded N-not-N² execution. |
| 12 | Security | Timeout and output errors killed only a scanner's direct child; background descendants survived. | high | Fixed: one RAII process-group owner reaps the tree on timeout, limit, error, success, stop, and drop. Interactsh uses the same lifecycle primitive. Non-Unix builds fail until job-object parity exists. |
| 13 | Security / observability | Tool and target-controlled bytes reached terminals and human logs without neutralizing controls. | medium | Fixed: one sink encoder escapes C0/C1, ESC, BEL, and bidi controls while structured evidence remains unchanged. Terminal, CLI, agent, AI, project, schedule, and diff sinks were audited. |
| 14 | Security | `init <target>` probed the target before an engagement existed, and an unused public webhook sender could post to arbitrary URLs. | high | Fixed: init now performs only bounded DNS bootstrap and emits a pinned quick grant; the dead webhook sender was removed while its redacted config shape remains compatible. |
| 15 | Security / confidentiality | Derived configuration `Debug` output exposed database URLs, proxy credentials, auth values, NVD keys, and webhook URLs. | high | Fixed: manual redacted renderers plus secret-literal regression fixtures; webhook errors no longer log destination URLs. |
| 16 | Architecture | AI execution was coupled to Claude command syntax and duplicated host assumptions. | medium | Fixed: provider-neutral interface with Codex-first non-interactive, read-only, ephemeral execution and a retained Claude compatibility adapter. Repository policy stays host-neutral. |
| 17 | Compatibility | Public context/client constructors and native provider helpers bypassed the new type boundary; current documentation taught those obsolete calls. | high | Code fixed: production constructors and provider helpers are closed or require an engagement. Documentation migration is required before completion; historical completed records remain unchanged. |
| 18 | Testing | Parser tests did not observe whether 66 external adapters executed their declared program or respected bounds. | high | Fixed: injectable context executor and registry-wide contracts assert program, arguments, timeout, exit policy, output cap, and parser results. Focused mutation caught all 66 erased runs. |
| 19 | Maintenance / simplification | DAST redirect and CVE providers built separate raw clients with divergent scope behavior. | medium | Fixed: `engine::policy_http` owns redirect/DNS authorization; specialized callers retain only headers, credentials, timeout, and endpoint details. |
| 20 | Security | NVD/OSV public constructors accepted arbitrary endpoints and created cache directories without endpoint or path authorization. | high | Fixed: constructors require an engagement, authorize both canonical endpoint and existing cache path before resources, recheck per query, and use the shared policy-bound resolver. |
| 21 | Documentation / compatibility | Current tutorials still taught obsolete public context constructors, raw clients, old module counts, and Claude-owned workflow state. | high | Fixed: public SDK, CVE-backend, development, architecture, getting-started, and agent-workflow docs now match the engagement-owned APIs and agent-neutral pipeline. Both standalone SDK example crates compile and test. Historical completed records remain unchanged. |
| 22 | Security | Native DNS, TLS, and TCP probes derived or resolved destinations outside the HTTP policy layer. | high | Fixed: `PolicyNetwork` authorizes a derived hostname before DNS, authorizes every returned address before use, and connects through an already-authorized concrete `SocketAddr`. Denied-name, mixed-answer, metadata-address, and allowed-loopback tests pass. |
| 23 | SDK usability | External modules could implement scanner traits but had no supported way to use policy-owned HTTP or register themselves with an orchestrator. | medium | Fixed: contexts expose a read-only policy HTTP accessor and all family orchestrators expose `add_module`; two standalone example crates exercise the supported API. |
| 24 | Security / support boundary | Native AWS, GCP, and Azure modules created provider SDK transports that could not enforce ScorchKit's per-address policy. | high | Fixed for the current support boundary: the 12 modules are private, test-only, and absent from the production registry. Five bounded external-tool cloud adapters remain supported. Restoration is explicit debt SK-042. |
| 25 | Correctness / CLI | `assess --profile` did not reach all scanner families, infrastructure scans omitted configured CVE correlation, and report output behavior was duplicated across commands. | high | Fixed: family-specific facade profile methods, CVE injection, and one report-emission owner now serve assess, DAST, SAST, infrastructure, cloud, and resume paths. Profile and output-selection regressions cover the observable behavior. |
| 26 | Security | WebSocket discovery used policy HTTP, then `connect_async` performed a second uncontrolled hostname resolution for the handshake. | high | Fixed: the WebSocket module obtains an authorized concrete connection through `PolicyNetwork` and hands that stream to the TLS/WebSocket client. A denied hostname fails before connect and an authorized loopback handshake still produces findings. |
| 27 | Correctness / authorization | Unknown non-DAST profile names silently selected every code, infrastructure, or cloud module. | high | Fixed: the facade rejects unknown profiles before context creation and low-level orchestrators fail closed by clearing their registry. Negative tests cover all three families. |
| 28 | Simplification | Five CLI paths owned nearly identical JSON, HTML, SARIF, PDF, terminal, and default report branching. | medium | Fixed: `emit_scan_report` is the single owner, and one artifact-selection test covers the default, terminal-only, and SARIF cases. |
| 29 | Documentation / API | Warning-denied Rustdoc found nine links from public module docs to private AI and TLS helpers. | medium | Fixed: the prose names internal implementation helpers without publishing or linking them. `RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features` passes with no suppression or visibility expansion. |
| 30 | Documentation / gate compatibility | The development guide spelled the three actionable-marker tokens in prose, so gate 12 classified its own instruction as debt. | low | Fixed: rephrased the instruction without duplicating the banned tokens. The targeted scan and full fast-gate rerun pass. |
| 31 | Pipeline integrity | Taplo's unconstrained recursive discovery descended into `.git/scorchkit-security-validation` and judged a sealed scan harness as worktree source. | high | Fixed: gate 13 enumerates only tracked and unignored TOML files through Git. A gate-contract test pins that boundary; internal `.git` evidence remains untouched. |
| 32 | Test correctness | NVD and OSV cache-directory tests changed `XDG_CACHE_HOME` concurrently behind separate module-local mutexes. | high | Fixed: every library test that mutates process-wide cache or credential environment variables now shares one crate-wide mutex. The failing pair passed 25 parallel stress runs and the complete all-feature suite passed five consecutive runs. |
| 33 | Correctness | The focused summary counted 42 selected repair functions while the generated mutant inventory contained 41 functions because one selected seam produced no mutant. | medium | Fixed: evidence now records both 42 selected functions and 41 mutated functions; the verifier derives and checks the latter instead of conflating the two counts. |
| 34 | Security | An unrestricted focused mode could be reused by a different active ticket or accept crafted numeric fields through shell arithmetic. | high | Fixed: the gate and pipeline restrict this evidence to TICKET-001, the input hash includes HEAD, and the verifier requires typed nonnegative integer counts, bounded scores, one baseline, no timeouts, and matching cargo-mutants versions before arithmetic. |
| 35 | Data integrity | Focused outcomes live under `.git`, outside the exact-worktree fingerprint, so a worktree receipt alone did not bind the evidence it claimed. | high | Fixed: one hash seals mutation-relevant inputs, a second digest covers every raw and summary evidence file, and the versioned receipt rechecks both bindings. Negative tests alter source, evidence, survivor identity, receipt mode, symlink target, and ordinary content. |
| 36 | Simplification | The verifier declared its required evidence file list twice, which could let validation and digest coverage drift apart. | low | Fixed: one readonly file inventory now drives presence checks and digest construction. DIFF and FULL retain their original mutation commands; the focused path is one explicit third branch. |
| 37 | Data integrity | The archive transition moved the ticket and spec but left their frontmatter links pointing to the former `open/` and `active/` paths. | medium | Fixed: the pipeline rewrites both links to `closed/` and `completed/` before moving artifacts, its selftest exercises the rewrite helper, and TICKET-001's archived pair now resolves in both directions. |
| 38 | Reliability | A naturally exiting OOB fixture could finish between the first child-state check and process-group termination, causing macOS to report `EPERM` during coverage teardown. | high | Fixed: shutdown classifies the process-group result, gives only the exited-child permission race a one-second observation window, and returns every other live-child termination error without an unbounded wait. The OOB regression and all 20 subprocess lifecycle tests pass. |
| 39 | Evidence integrity | The post-archive source repair changed the mutation-input hash after the original 162/162 focused campaign. | high | Fixed: the evidence seals the exact old `subprocess.rs`, proves replacing only that current file reconstructs the original input hash, and verifies raw outcomes for six mutants in the two repaired functions. Five viable mutants were caught, none missed, and one was unviable. |

## Phase 4 — Validate

- Scope expansion: the repository owner directed this active ticket to continue through the product
  refactor, complete baseline burn-down, full mutation sweep, thorough code review, and sealed
  technical-debt roadmap before feature work begins. The earlier product-refactor and full-sweep
  exclusions no longer apply. REQ-008 through REQ-014 record the observable expanded contract.
- Codex Security diff scan `efe30eaf-9b1b-4572-949a-0e8391d48247` sealed the exact snapshot
  `codex-security-snapshot/v1:sha256:aacce46c8735819a2356f1e2333d90036ce3871a399bce71d35505e02a32a375`.
  It closed 192/192 semantic review rows across 603 changed paths with complete coverage, no
  exclusions, and no deferred rows. The report contains eight high-confidence findings: five medium
  and three low.
- Runtime security validation stayed local. Facade tests passed 5/5, MCP integration tests passed
  49/49 against the migrated disposable database, and an isolated harness reproduced redirect scope
  escape, surviving process descendants, preserved terminal control bytes, and a one-slot scheduler
  deadlock. No remote target was scanned.
- Accepted security work: make effect authorization mandatory across facade/MCP/project/schedule
  entry points; reauthorize redirects and resolved addresses; remove the scheduler pool ownership
  cycle; own full process trees; and neutralize terminal controls at presentation sinks while
  preserving structured evidence.
- Follow-up inspection corrected the first scheduler remediation: a transaction-scoped advisory
  lock still allowed waiters to occupy the scan pool. The final design uses a short row-claim
  transaction with `FOR UPDATE SKIP LOCKED`, advances the occurrence before commit, and performs no
  network work while a transaction or claim connection is held.
- The sealed scan's supplemental `artifacts/fix_report.md` maps all eight findings to current code
  and regression evidence without altering the original report or canonical findings.

- First canonical DIFF run: red. Gate 3 exposed concurrent global-due-set tests and five execution
  tests that waited on a reserved remote address. Coverage repeated the failures. Mutation completed
  rather than failing fast: 80 caught, 104 missed, 100 unviable, 43.47% MSI versus 95% required.
- Root-cause correction: extracted one structured CLI/MCP due-schedule executor; serialized batches
  with a transaction-scoped PostgreSQL advisory lock; added a two-caller/two-schedule N-versus-N²
  regression; moved scan execution tests to `httpmock` loopback targets; asserted scan success and
  persistence; bounded integration scan timeout at five seconds.
- Gate correction: delivery tiers now skip after static prerequisite failure, and mutation skips
  when coverage is red. Gate IDs and visible reasons remain stable.
- `cargo test --all-features --test quality_gate_contract`: 2 passed.
- `cargo test --all-features --test mcp_tools`: 49 passed in 1.31 seconds.
- `cargo clippy --all-targets --all-features -- -D warnings`: pass.
- `cargo test --all-features`: 1,203 passed, 6 ignored; MCP binary completed in 0.12 seconds.
- `cargo nextest run --all-features`: 1,191 passed, 6 skipped in 6.93 seconds; slowest 6.37 seconds.
- `bash bin/gate.sh --fast`: 14 passed, 0 failed, 8 expected delivery-tier skips across the exact
  updated worktree.
- `cargo llvm-cov --all-features --ignore-filename-regex '(^|/)main\\.rs$'
  --fail-under-lines 62`: 69.08% line coverage; gate floor passed with 7.08 points of headroom.
- Boundary mutation burn-down: added exact URL/display, IPv4/IPv6 prefix, profile requirement,
  engagement exposure, PATH state, quiet rendering, MCP tool inventory, cookie expiry, and CORS
  preflight threshold assertions. A first 23-mutant focused run caught 19, left two redundant
  `cli::runner::is_tool_available` delegates alive, and found two unviable tuple replacements.
- Simplification correction: removed the redundant CLI availability delegate and called the tested
  doctor function directly. The exact-tree rerun selected 21 boundary mutants and finished with
  19 caught, 0 missed, and 2 unviable: 100% MSI among viable cases. No mutation exclusion changed.
- External-process correction: added an owned `ToolInvocation`, explicit strict/lenient exit policy,
  injectable `ToolExecutor`, canonical executable path, per-stream 8 MiB capture limit, timeout
  cleanup, and shared execution methods on `ScanContext` and `CodeContext`. Migrated 45 bounded DAST
  wrappers and all 21 SAST wrappers to the context-owned executor. Interactsh remains separate because
  it owns a long-lived callback session rather than one bounded invocation.
- `cargo test --all-features --test external_tool_contract`: 2 passed. The registry contract requires
  every bounded wrapper to execute its declared tool with a nonzero timeout, explicit exit policy,
  and the shared output limit. Its DAST fixture includes a harmless query parameter so SQLMap reaches
  its execution seam without changing SQLMap's no-parameter early return.
- `cargo test --all-features`: 1,203 non-documentation tests passed, 6 reasoned tests ignored, and 14
  doctests passed after the process-contract refactor.
- Adapter mutation burn-down: an exact-tree focused run selected 66 erase-the-`run` mutants and caught
  all 66 in 24 minutes. It had 0 missed and 0 unviable. The command omitted only Interactsh from this
  focused set; Interactsh remains in the canonical inventory pending its lifecycle contract.
- Interactsh lifecycle correction: its persistent process now shares the process-group owner and
  bounded reader. Stop, drop, startup timeout, output overflow, and early failure terminate the
  process tree; local descendant fixtures pass.
- Schedule authorization correction: migration 005 persists an engagement snapshot. Creation and
  execution require registered canonical targets and profile grants; legacy/no-snapshot and changed
  policy rows fail closed. The database-backed MCP suite now has 55 tests for the transport layer,
  including no-engagement, changed-snapshot, one-slot concurrency, and at-most-once failure cases.
- Provider-boundary correction: NVD and OSV constructors now require explicit endpoint and cache-path
  grants, reuse the policy-aware resolver/redirect layer, and reauthorize resources per query. GCP
  and Azure client helpers are crate-private behind authorized cloud contexts.
- Post-reboot exact-tree compiler evidence: `cargo check --all-targets --all-features` and strict
  Clippy passed with zero diagnostics. The database-backed all-feature run passed 1,283 tests, kept
  six reasoned live-network ignores, and had zero failures.
- Documentation and SDK review replaced obsolete constructor, raw-client, module-census, and
  Claude-owned workflow instructions. `examples/custom_scanner` passed two unit tests and one
  doctest; `examples/custom_code_scanner` passed two unit tests.
- The final network-sink review found a WebSocket second-resolution path after policy HTTP
  discovery. The module now connects through `PolicyNetwork` to an authorized concrete address;
  the denied-hostname and authorized-loopback WebSocket tests both pass.
- Profile and output review found that unknown non-DAST profiles expanded to all modules and report
  selection had five duplicate owners. Unknown profiles now fail before effects, and one report
  emitter serves every CLI scan path. Strict all-target/all-feature Clippy passed after the cleanup.
- `bash bin/mutants.sh --inspect` after the reboot inventoried 5,730 mutants across 240 source files.
  The runner kept ephemeral builds on local scratch, included the policy kernel, and excluded only
  the declared composition root plus exact database-only functions.
- Post-review executable checks: `cargo fmt --all -- --check` passed; database-backed
  `cargo test --all-features` passed 1,284 non-documentation tests with six reasoned live-network
  ignores and 14 doctests; strict all-target/all-feature Clippy passed; warning-denied all-feature
  Rustdoc passed after correcting nine private-item links.
- Standalone extension checks: the DAST example passed two unit tests and one doctest; the SAST
  example passed two unit tests.
- Workflow enforcement checks passed: pipeline selftest, derived feature-state selftest, stable
  gate-number/receipt-writer selftest, pre-commit receipt selftest, and the Codex skill quick
  validator.
- The first post-review fast gate passed gates 1–11 and 14, then found two source defects: gate 12
  matched the development guide's literal marker examples, and gate 13 let Taplo inspect a sealed
  security harness under `.git`. The guide was rephrased and the TOML lane now enumerates only
  tracked and unignored files through Git. The quality-gate contract pins that scope.
- The full fast-gate rerun passed gates 1–14 with zero failures. Delivery gates 15–16 and 20–22 were
  skipped by fast mode, and web gates 17–19 emitted their required named not-applicable skips.
- Exact DIFF mutation inventory before execution: 858 generated mutants across 133 changed source
  files. No floor, exclusion, retry, test ignore, or diagnostic suppression changed.
- The first canonical DIFF attempt stopped at gate 3 before coverage or mutation. A quiet rerun passed,
  and a two-test stress probe reproduced the nondeterminism immediately: NVD read OSV's concurrent
  `XDG_CACHE_HOME` value because their locks were not shared. All environment-mutating library tests
  now use one crate-wide mutex. The pair passed 25 consecutive parallel runs and the full
  database-backed all-feature suite passed five consecutive runs with the gate's five test threads.
- The first post-upgrade DIFF attempt passed 13 static gates but gate 3 exposed another overloaded-runner
  flake: the exact-output-limit test used a two-second process deadline even though it verifies byte
  preservation rather than timeout behavior. The test-only invocation budget is now ten seconds;
  dedicated timeout tests still use millisecond bounds, and no production timeout or output limit
  changed. The gate correctly skipped coverage, mutation, and the remaining delivery tiers. The
  repaired contract passed 25 consecutive focused runs, then the complete database-backed
  all-feature suite passed five consecutive runs with five test threads.
- The next canonical DIFF attempt passed gates 1–15, including 72.66% line coverage, before
  cargo-mutants failed its copied-tree baseline. A newly written Interactsh fixture returned
  `Operation not permitted (os error 1)` when executed directly, so no mutant ran. Gates 20–22
  passed independently and web gates 17–19 remained named skips.
- The fixture no longer depends on direct execution of a newly written file. Tests invoke fixture
  scripts through the trusted `/bin/sh` executable, while `InteractshSession` accepts an explicit
  program and argument vector and production retains `interactsh-client -json -v`. The implicated
  tests passed 200 process executions under Nextest, the focused lifecycle/tool contracts passed,
  and canonical shard `0/5730` completed its copied-tree baseline in 153 seconds and caught its one
  selected mutant.
- The failed baseline also exposed an evidence defect in `bin/mutants.sh`: cargo-mutants status 4
  with zero outcomes was temporarily rendered as 100% MSI before the wrapper exited red. Incomplete
  runs now retain compact evidence with `completed: false` and a null score, then exit before any
  score or mutation-blind claim. The quality-gate contract pins that ordering and schema.
- A later DIFF mutation pass left 13 survivors in CLI query commands, PDF saving, and repeated
  quiet/count presentation branches. Tests now call each command body, force a closed-pool error,
  reject a regular-file PDF destination, and assert shared presentation predicates over their full
  truth tables. A focused 36-mutant run caught those 13 cases and exposed nine additional report
  arithmetic survivors.
- The report fixture originally had equal old and new totals, which made incorrect addition and
  division produce the expected counts. A built-CLI process test now uses an asymmetric pair with
  two new, two resolved, and three unchanged findings. The exact nine-mutant rerun caught all nine.
- The canonical DIFF gate completed on 2026-08-16 with 19 passes, no failures, and the three named
  web-only skips. Coverage was 77.94%. Mutation processed all 876 selected cases in four hours:
  598 failed tests and 41 timed out, for 639 caught viable mutations, zero missed, 237 unviable, and
  100% MSI. Gates 20 through 22 then passed Nextest, migrated PostgreSQL, and CLI/MCP contracts.
  The receipt matched the exact worktree before these evidence documents were updated.
- The repository owner stopped the subsequent full-repository mutation run and directed all further
  mutation work to the repaired seams only. The stopped run remains preserved as incomplete:
  cargo-mutants status 1, 239 caught or timed out, 115 missed, 354 viable outcomes, and no score.
  These partial counts are discovery evidence, not a delivery result.
- The 115 observed survivors were concentrated in 14 files. Behavior-preserving extraction and
  direct tests covered 42 repaired functions in facade configuration, agent configuration and
  rendering, AI formatting/parsing/planning, database migration errors, doctor summaries, finding
  filters, initialization recommendations, and project presentation predicates.
- Current non-mutation evidence after those repairs: strict all-target/all-feature Clippy passed;
  the database-backed all-feature suite passed 1,203 library tests, 153 integration tests, and 14
  doctests with four reasoned live-network ignores and no failures; focused doctor, finding, init,
  project, agent, AI, facade, and database tests all passed.
- The focused inventory selected 171 mutations in exactly the 42 repaired functions across the 14
  reviewed files. Its first pass caught 159, missed three new project-section assertions, and found
  nine unviable variants. Direct metric-to-section and membership assertions closed those gaps. An
  exact three-item recheck caught all three. The final focused result is 162/162 viable mutations
  caught, zero missed, nine unviable, and 100% MSI. Both passes and the merged summary are retained
  under `.git/scorchkit-mutants-focused-ticket-001`.
- Per the 2026-08-16 scope amendment, TICKET-001 does not require another full mutation run. A fresh
  full inventory remains scheduled evidence. The incomplete run is not described as green, and no
  mutation floor, exclusion, retry, ignore, test, or diagnostic rule changed.
- Final non-mutation delivery evidence after the scope amendment: `bash bin/gate.sh --fast` passed
  gates 1 through 14 with zero failures; coverage passed at 78.68% lines against the 62% floor;
  Nextest passed with 19 nonempty suites and 1,394 listed cases; the PostgreSQL lane passed 58 MCP,
  11 storage, and 7 storage-integration tests; the CLI/MCP contract lane passed 18 CLI, 2 code-scan,
  58 MCP, and 13 scan-plan tests. No mutation run was started by these checks.
- The receipt gap is resolved by the explicit `CONSTITUTION.md` §19 amendment and REQ-014. The new
  verifier reconstructs counts and mutant identities from both raw runs, requires the initial
  three-survivor set to equal the three-item caught recheck, enforces the 95% floor, and binds the
  evidence to mutation-relevant inputs. Its original base input hash is
  `7a51e44cd83034f673d1407c3b7bf013f74847560d2a098348771fafafe6c5a0`.
- The focused-repair gate keeps gate 16 visible, verifies the sealed evidence without launching
  cargo-mutants, reruns gates 1–15 and 17–22, and writes a versioned receipt that names the mode and
  evidence digest. Receipt verification rejects a changed worktree, changed focused evidence,
  changed mutation input, malformed receipt, or path traversal. Script, gate, pipeline, and hook
  selftests pass before the final delivery run.
- The pre-completion `bash bin/gate.sh --focused-repair` passed 19 applicable gates with zero
  failures and the three named web skips. Coverage was 78.68% against the 62% floor. Gate 16
  reconstructed 162/162 viable mutations caught at 100% MSI from the sealed evidence without
  launching cargo-mutants. Nextest ran 1,388 tests with six reasoned skips. PostgreSQL passed 58 MCP,
  11 storage, and 7 storage-integration tests. The CLI/MCP lane passed 18 CLI, 2 code-scan, 58 MCP,
  and 13 scan-plan tests. Receipt v2 recorded mode `focused-repair`, input hash
  `7a51e44cd83034f673d1407c3b7bf013f74847560d2a098348771fafafe6c5a0`, and evidence digest
  `15d1cc4a10b378b38d296f089940565268da4fb503cd8e1e46f767d036b664f3`. The pipeline consumed the
  matching receipt and passed Validate before the completion edits.

### Mutation-blind changed-file review before the canonical run

The current mutation inventory has no generated mutant for the 22 changed Rust files below. Each
file was reviewed directly and has a separate executable check. The canonical DIFF result will
replace this pre-run inventory if it reports any additional file with no viable mutant.

| Class | Exact files | Disposition and evidence |
|---|---|---|
| Standalone SDK example | `examples/custom_scanner/src/lib.rs` | Retained. The change uses the public policy HTTP accessor; the example's unit tests and doctest compile it as an external consumer. |
| Static agent contracts | `src/agent/prompt.rs`, `src/mcp/instructions.rs` | Retained. These are constants rather than functions mutation testing can alter. Unit tests assert the required workflow, safety language, tools, and all four profiles. |
| Error and public wiring | `src/engine/error.rs`, `src/engine/mod.rs`, `src/lib.rs`, `src/prelude.rs` | Retained. These files add enum variants, module declarations, re-exports, feature guards, and doctests. All-feature compilation, warning-denied Rustdoc, policy/executor/hook error tests, and prelude tests consume the changed surface. |
| Binary composition root | `src/main.rs` | Retained under the existing narrow `src/main.rs` exclusion. Its only behavior change delegates error text to the directly tested terminal encoder; gate 22 exercises the built CLI contract. |
| Database-only storage | `src/storage/projects.rs` | Retained under the exact `remove_target` database-function exclusion. Migrated PostgreSQL tests cover target removal, and the MCP suite proves a target ID cannot be removed through a different project. |
| Test and contract sources | `tests/ai_types.rs`, `tests/cve_nvd.rs`, `tests/cve_osv.rs`, `tests/external_tool_contract.rs`, `tests/hooks.rs`, `tests/mcp_tools.rs`, `tests/module_census.rs`, `tests/posture_metrics.rs`, `tests/quality_gate_contract.rs`, `tests/scan_plan.rs`, `tests/scan_schedules.rs`, `tests/storage.rs`, `tests/storage_integration.rs` | Retained as executable evidence rather than production mutation targets. The all-feature and gate-specific lanes run them, including PostgreSQL where required. |

### Canonical mutation-blind changed-file review

The completed canonical run reported 85 changed Rust files with no selected mutant. Every file is
accounted for below. This replaces the pre-run inventory above.

| Class | Exact files | Disposition and evidence |
|---|---|---|
| Executable test and contract sources | `tests/ai_types.rs`, `tests/cli_init_contract.rs`, `tests/cve_nvd.rs`, `tests/cve_osv.rs`, `tests/external_tool_contract.rs`, `tests/hooks.rs`, `tests/mcp_tools.rs`, `tests/module_census.rs`, `tests/posture_metrics.rs`, `tests/quality_gate_contract.rs`, `tests/scan_plan.rs`, `tests/scan_schedules.rs`, `tests/storage.rs`, `tests/storage_integration.rs` | Retained. Cargo-mutants does not mutate test targets. Gate 3 ran the complete all-feature suite, gate 21 ran 58 MCP, 11 storage, and 7 storage-integration PostgreSQL tests, and gate 22 ran the built CLI and MCP contract suites. |
| Scanner and recon files with comment, lint-justification, or test-only diffs | `src/recon/cloud.rs`, `src/recon/cname_takeover.rs`, `src/recon/dns.rs`, `src/recon/js_analysis.rs`, `src/recon/vhost.rs`, `src/scanner/acl.rs`, `src/scanner/api.rs`, `src/scanner/api_schema.rs`, `src/scanner/clickjacking.rs`, `src/scanner/cmdi.rs`, `src/scanner/crlf.rs`, `src/scanner/csp.rs`, `src/scanner/csrf.rs`, `src/scanner/dom_xss.rs`, `src/scanner/graphql.rs`, `src/scanner/host_header.rs`, `src/scanner/idor.rs`, `src/scanner/injection.rs`, `src/scanner/jwt.rs`, `src/scanner/ldap.rs`, `src/scanner/mass_assignment.rs`, `src/scanner/misconfig.rs`, `src/scanner/nosql.rs`, `src/scanner/path_traversal.rs`, `src/scanner/prototype_pollution.rs`, `src/scanner/ratelimit.rs`, `src/scanner/sensitive.rs`, `src/scanner/smuggling.rs`, `src/scanner/ssrf.rs`, `src/scanner/ssti.rs`, `src/scanner/subtakeover.rs`, `src/scanner/upload.rs`, `src/scanner/waf.rs`, `src/scanner/xss.rs` | Retained. Direct diff review found no production branch change. The edits repair Rustdoc, source-policy, or secret-fixture annotations and simplify test syntax. Gate 3 and the scanner unit tests exercise the surrounding code. |
| Other comment, fixture, or test-only diffs | `src/engine/cloud_credentials.rs`, `src/engine/cloud_evidence.rs`, `src/engine/cloud_module.rs`, `src/engine/correlation.rs`, `src/engine/cve.rs`, `src/engine/events.rs`, `src/engine/evidence.rs`, `src/engine/network_credentials.rs`, `src/engine/risk_score.rs`, `src/engine/shared_data.rs`, `src/infra/cve_cache.rs`, `src/infra/cve_match.rs`, `src/infra/cve_multi.rs`, `src/runner/rule_engine.rs`, `src/storage/intelligence.rs` | Retained. Direct diff review found only shared test-lock adoption, test fixture cleanup, comment fixes, or equivalent test syntax. The all-feature suite passed five loaded repetitions before the canonical run and passed again in gate 3. |
| Static host, schema, and help contracts | `src/agent/config.rs`, `src/agent/prompt.rs`, `src/ai/correlator.rs`, `src/ai/prompts.rs`, `src/ai/remediation.rs`, `src/ai/types.rs`, `src/cli/args.rs`, `src/mcp/instructions.rs`, `src/mcp/resources.rs`, `src/mcp/types.rs` | Retained. Most edits are documentation. The changed agent and MCP instruction constants have direct content tests for policy ownership and all four profiles. Built CLI help and MCP initialization cover the derived help and schema surfaces. |
| Public wiring, error, visibility, and storage types | `examples/custom_scanner/src/lib.rs`, `src/cloud/azure/mod.rs`, `src/cloud/gcp/mod.rs`, `src/engine/error.rs`, `src/engine/mod.rs`, `src/lib.rs`, `src/main.rs`, `src/mcp/server.rs`, `src/prelude.rs`, `src/storage/models.rs` | Retained. Feature-matrix compilation, warning-denied Rustdoc, standalone example tests, direct error-variant tests, 58 MCP tests, built-CLI contracts, and schedule snapshot round trips consume these changes. The private cloud SDK registrations are absent from the production census by design. |
| Behavior seams without a generated DIFF mutant | `src/ai/response.rs`, `src/engine/tls_probe.rs` | Retained. AI response tests assert structured parsing, fallback, cost, model, and focus through the shared parser. Policy-network denial and authorized-loopback tests, plus infrastructure closed-port tests, cover the TLS probe's policy-owned connection path. |

- Documented skips: four reasoned external-network tests remain ignored. Delivery web gates 17–19
  remain named not-applicable skips by product boundary.

## Phase 5 — Complete

- Docs updated: Constitution §§0/3/15/19, agent guidance, pipeline skill, development and module
  guides, roadmap, changelog, ticket/spec/notes, knowledge register, security review, and AAR.
- AAR submitted: `AAR-001-rustal-quality-workflow`, 2026-08-16, effectiveness 5.
- Archive: `bash bin/pipeline.sh pass complete` closed TICKET-001 on 2026-08-16, removed it from the
  open queue, and moved the spec/notes pair to `pipeline/completed`. The archive transition now
  rewrites the ticket/spec frontmatter and body cross-links before moving either file.
- Post-archive proof: the first `bash bin/gate.sh --focused-repair` pass completed 19 applicable
  gates with zero failures and three named web-only skips. It verified 162/162 viable focused
  mutations at 100% from sealed evidence without launching cargo-mutants and issued interim
  worktree receipt `889f474e89022ca20e879308f4c5fc38ce8b48ec2aa16f6fa3f7ff1cf5a48fbc`.
  This completion record changes the worktree, so only the later exact-tree rerun and receipt
  readback are authoritative for delivery.
- Final-tree repair: the next coverage pass exposed an exited-child `killpg` race in OOB fixture
  cleanup. `stop_owned_process` now distinguishes an exited-child `EPERM` transition from a live
  termination failure and bounds the former to one second. The affected OOB test and all 20
  subprocess lifecycle tests pass. Mutation was limited to the two repaired functions: six
  selected, five caught, zero missed, and one unviable. The cumulative sealed result is 167/167
  viable caught with 10 unviable. The current input hash is
  `b215d1490232178dd35d2a51c04f511bd0c358ae3fdf9407af8149f946bd30fe`, and the cumulative
  evidence digest is `76203138a87f815b2e66c2d1626c67edf3fd343a5301e21e62486512d4775aec`.
  No broad mutation run was launched.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Fast gate aborted before Clippy. | Empty Bash array under `set -u` on the system Bash 3 runtime. | Split default and flagged Clippy invocations. | Hook/fast gate selftest on the actual macOS shell. |
| 2 | Gate:10 rejected valid `unused_async` suppressions. | Regex lacked a lint-token boundary. | Added boundary-aware matching anchored to attributes. | Keep source-policy scans syntax-shaped and exercise them in the canonical gate. |
| 3 | Gate 3 MCP tests failed intermittently and took about 450 seconds. | Tests queried a database-wide due set concurrently and executed scans against a reserved remote address with a 300-second timeout. | Serialize global-set tests, use loopback mocks, assert effects, and use a five-second test scan budget. | `PR-scorchkit-loopback-integration-001`, `PR-scorchkit-global-set-lock-001`. |
| 4 | N due schedules could execute N² scans through MCP. | `do_run_due_scans` looped rows while calling a CLI function that independently executed every due row. | One shared structured batch executor plus a PostgreSQL advisory lock; concurrent two-schedule regression. | `BF-scorchkit-scheduler-n-squared-001`. |
| 5 | A known-red delivery run spent roughly two hours in mutation. | Delivery gates were independent even when their prerequisites had already failed. | Static failures skip delivery tiers; coverage failure skips mutation while independent contract lanes may still run. | `PR-scorchkit-gate-prerequisites-001`. |
| 6 | A private CLI availability delegate survived both constant-return mutations. | It duplicated a tested function without adding behavior or an independently observable contract. | Removed the delegate and called the tested owner directly. | `PR-scorchkit-observable-seams-001`. |
| 7 | Sixty-three external wrapper bodies could be erased without failing a test. | Parser tests did not observe process invocation, and contexts had no injectable process boundary. | Added a typed context-owned executor and registry-wide DAST/SAST invocation contracts; focused mutation caught all 66 current wrapper erasures. | `PR-scorchkit-executor-contract-001`. |
| 8 | Native protocol modules could authorize one destination and let a library resolve another. | HTTP policy checks did not own later DNS, TLS, TCP, or WebSocket sockets. | Added `PolicyNetwork`; derived names and every answer are checked before an authorized concrete connection is handed to the protocol client. | `PR-scorchkit-derived-network-policy-001`, `BF-scorchkit-websocket-second-resolution-001`. |
| 9 | Published extension docs compiled only against obsolete internal APIs. | The SDK examples and narrative docs were not treated as compatibility contracts after policy constructors closed. | Added public policy-owned accessors and registration seams, rewrote the docs, and test both standalone crates. | `PR-scorchkit-doc-examples-contract-001`. |
| 10 | Native cloud SDK modules remained buildable as production registry candidates without a policy-owned transport. | Provider authentication and request stacks resolved and connected below ScorchKit's address policy. | Made all 12 provider modules private and test-only; production keeps five bounded external-tool adapters. | `PR-scorchkit-provider-transport-quarantine-001`. |
| 11 | Accepted CLI profile and output arguments did not consistently change execution. | Family commands and report branches duplicated option plumbing. | Validate profiles before effects, route each family through profile-aware facade methods, and use one report emitter with artifact tests. | `PR-scorchkit-cli-options-observable-001`. |
| 12 | Gate 13 inspected a sealed security-validation harness under `.git`. | Taplo's implicit recursive discovery was broader than the repository content represented by the delivery receipt. | Enumerate tracked and unignored TOML paths through Git before invoking Taplo. | `PR-scorchkit-gate-worktree-scope-001`. |
| 13 | The all-feature suite failed intermittently when NVD read OSV's test cache root. | Process-global environment mutations were protected by separate module-local mutexes. | Use one crate-wide test environment lock for every cache and credential environment mutation. | `BF-scorchkit-test-environment-race-001`, `PR-scorchkit-process-env-test-lock-001`. |
| 14 | The exact-output-limit process test timed out during a loaded clean-build gate. | A byte-boundary contract reused a two-second execution deadline that was unrelated to the behavior it asserted. | Give the byte-boundary fixture a ten-second test-only budget while keeping dedicated timeout tests narrow. | `BF-scorchkit-orthogonal-test-timeout-001`, `PR-scorchkit-orthogonal-test-budget-001`. |
| 15 | The cargo-mutants copied-tree baseline could not execute a newly written Interactsh fixture. | The test assumed a temporary script could be made directly executable on every supported macOS runner and scratch layout. | Invoke the data fixture through the trusted `/bin/sh` executable and pass script paths as arguments. | `BF-scorchkit-mutants-temp-script-spawn-001`, `PR-scorchkit-test-shell-fixtures-001`. |
| 16 | An incomplete mutation baseline displayed 100% MSI before exiting red. | Zero outcomes were scored before cargo-mutants completion status was classified. | Record completion explicitly, use a null score for incomplete runs, and reject them before score or blind-file output. | `BF-scorchkit-mutants-incomplete-score-001`, `PR-scorchkit-mutation-completion-evidence-001`. |
| 17 | Four CLI query commands and the PDF saver could be erased without a failing test. | Tests covered storage helpers and report formatting but did not call each effect-owning command body and observe its error or artifact. | Invoke the command bodies on missing records, a closed pool, and an invalid output destination. | `BF-scorchkit-mutation-effect-erasure-001`, `PR-scorchkit-mutation-effect-observation-001`. |
| 18 | Nine report-diff arithmetic and branch mutants survived the first focused run. | The fixture used equal old and new totals, so several incorrect formulas produced the same visible counts. | Add a built-CLI asymmetric report pair and assert headings, identities, new, resolved, unchanged, and trend output. | `BF-scorchkit-report-output-symmetry-001`, `PR-scorchkit-process-output-contract-001`. |
| 19 | Repeated quiet/count branches were difficult to cover consistently. | Presentation conditions were copied across orchestration and CLI paths. | Give visibility and empty/nonempty cardinality one shared predicate owner with a complete truth-table test. | `PR-scorchkit-presentation-predicate-001`. |
| 20 | A broad full mutation run continued after its first survivor inventory was already sufficient to direct repair. | The validation plan treated mutation discovery and mutation verification as the same repeated repository-wide action. | Stop after one inventory, repair the observed seams, rerun only exact repaired functions, and schedule a later full campaign as separate evidence. | `BF-scorchkit-mutation-rescan-cost-001`, `PR-scorchkit-focused-mutation-repair-001`. |
| 21 | OOB fixture shutdown intermittently returned `EPERM` after the fixture had emitted its final interaction. | The direct child exited between `try_wait` and process-group signaling, but the error was considered ignorable only when exit was observed before the signal attempt. | Classify group-stop outcomes and give only the macOS exited-child permission transition a bounded wait; return other live termination errors immediately. | `BF-scorchkit-exited-child-killpg-race-001`, `PR-scorchkit-bounded-process-exit-race-001`. |
