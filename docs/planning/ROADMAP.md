# ScorchKit roadmap

**Status:** feature-readiness baseline, SK-028 executor, and SK-029 durable jobs complete
**Started:** 2026-08-14  
**Last reviewed:** 2026-08-16  
**Direction:** agent-neutral security execution engine with Codex as the preferred host

## Product boundary

ScorchKit owns deterministic effects and evidence:

- engagement authorization, target scope, capabilities, and effect classes;
- DAST, SAST, infrastructure, cloud, and external-tool execution;
- network, process, time, concurrency, output, credential, and filesystem controls;
- raw observations, findings, evidence, artifacts, correlation, and reports;
- jobs, schedules, persistence, audit events, CLI operations, and MCP tools.

Agent hosts own reasoning around those controls:

- natural-language interaction and threat modeling;
- scan-plan proposals within an existing engagement;
- source-level semantic review;
- prioritization, explanation, and remediation planning;
- interpretation that remains labeled separately from scanner evidence.

Codex is the preferred host. Claude remains an optional compatibility adapter. No vendor owns
workflow state, target authorization, scanner evidence, or delivery truth.

## Current source census

The 3.0.0 repository contains about 73,000 lines of Rust. Registry code and contract tests establish
this module census:

| Family | Count | Source of truth |
|---|---:|---|
| DAST and recon | 91 | 10 recon + 35 scanner + 46 tool adapters |
| SAST | 22 | 1 native module + 21 tool adapters |
| Infrastructure | 4 or 5 | 4 registered modules plus configured CVE correlation |
| Cloud | 5 | Bounded external-tool adapters; 12 native provider modules are private and test-only |
| Maximum | 123 | All production registries, including optional CVE correlation |

Of the 46 DAST tool adapters, 45 are bounded one-shot processes and Interactsh owns a long-lived
callback session. All 21 SAST adapters are bounded one-shot processes.

Supported production hosts are Linux and macOS. A non-Unix build fails until a Windows Job Object
backend can match the descendant-process cleanup contract.

## Feature-readiness contract

Feature work may begin only when all of the following are true under the repository owner's
2026-08-16 mutation-scope amendment:

1. The closed TICKET-001 requirements and archived inspection ledger have dispositions and direct
   evidence.
2. `bash bin/pipeline.sh selftest`, the feature-state selftest, gate selftest, skill validator, and
   pre-commit receipt selftest pass.
3. The completed canonical DIFF result remains the broad changed-line baseline, and every later
   production repair has an exact focused mutation inventory at the unchanged 95% floor.
4. The final worktree passes all non-mutation delivery lanes with a live migrated PostgreSQL
   database. A new full mutation inventory is scheduled evidence rather than a TICKET-001 blocker.
5. Every mutation-blind changed Rust file is reviewed, covered, removed, or listed with a narrow
   source-backed disposition. A broad exclusion is not a disposition.
6. The current AAR is submitted, the ticket/spec/notes pair is archived by the pipeline script, and
   the final worktree has a matching delivery receipt under the repository's enforced gate policy.
7. `SECURITY.md` describes the implemented boundary and identifies any unsupported surface without
   presenting it as enforced.

Staging files does not change the receipt. Any worktree content edit does.

## Starting baseline

The first inventory on 2026-08-14 established:

- 1,189 all-feature tests passed and 6 reasoned live-network tests were ignored;
- strict linting found 94 production diagnostics and 267 additional test-target diagnostics;
- line coverage was 64.40% without the database lane;
- the lockfile contained 12 RustSec vulnerabilities, including fixable advisories;
- one unused root dependency and unused example dependencies remained;
- seven secret-scanner matches required narrow review;
- 35 obsolete `.claude` files and 567 SMB-generated mode observations made the worktree ambiguous.

The repository owner directed ScorchKit to retain the 35 deletions. Git now ignores synthetic local
file-mode observations while the index retains authoritative modes.

## Closed baseline work

| Batch | Closed work | Evidence |
|---|---|---|
| SK-001 | Reconciled the worktree and removed Claude-only command/hook state. | Owner decision recorded in `AGENTS.md`; effective diff retains exactly the intended deletions. |
| SK-002 | Added the 22-gate quality system, CI parity, coverage and mutation configuration, local scratch runner, and exact-worktree receipt. | Gate/selftest contracts and `CONSTITUTION.md` §0. |
| SK-003 | Upgraded fixable vulnerable dependencies and removed unused direct dependencies. | `cargo audit`, `cargo deny`, and `cargo machete` gates. |
| SK-004 | Removed the strict Clippy and Rustdoc warning backlog across all feature states. | Strict all-target/all-feature checks and derived feature-state gate. |
| SK-005 | Added serializable engagement, scope, capability, effect, denial, expiry, and audit types. | Policy unit and facade contract tests. |
| SK-006 | Made the engine, CLI, MCP, project, and agent entry points fail closed without an engagement. | Absence and out-of-scope tests across each public host surface. |
| SK-007 | Bound project scans and schedules to registered canonical targets and exact engagement snapshots. | Migration 005 and database-backed MCP/scheduler tests. |
| SK-008 | Defined quick, standard, thorough, and pentest capability/effect requirements. | Profile-policy table tests and restricted-module tests. |
| SK-011 | Added bounded one-shot execution and Unix process-tree ownership, including Interactsh lifecycle cleanup. | Timeout, output, stop, drop, and descendant fixtures. |
| SK-014A | Replaced Claude-only AI configuration with a provider-neutral interface and Codex-first CLI adapter. | Adapter invocation and legacy-config compatibility tests. |
| SK-021 | Implemented the repository ticket/spec/notes/AAR state machine, Codex skill, Git hook, and gate receipt. | Pipeline, skill, gate, and hook selftests plus the archived TICKET-001 pair. |
| SK-022 | Replaced N-squared due-schedule execution with short `FOR UPDATE SKIP LOCKED` claims and at-most-once advancement. | One-slot, N-caller, failure, and exact persisted-count tests. |
| SK-023 | Burned down the policy/facade boundary mutation cluster. | Focused exact-tree run: 19 caught, 0 missed, 2 unviable. |
| SK-024 | Routed 45 DAST and 21 SAST one-shot adapters through one typed, bounded executor seam. | Registry contracts and focused exact-tree run: 66 caught, 0 missed. |
| SK-025H | Centralized HTTP authorization for direct URLs, redirects, hostnames, and every IPv4/IPv6 answer. | Loopback redirect, hostname, address, private, metadata, and changed-DNS tests. |
| SK-025C | Required NVD/OSV endpoint and cache-path grants, closed raw native cloud client helpers, and quarantined 12 provider SDK modules outside the public production registry. | Provider constructor/query tests, five-module cloud census, and visibility review. |
| SK-025T | Neutralized terminal controls at presentation sinks and redacted secret-bearing config diagnostics. | Terminal fixtures/property tests and secret-literal tests. |
| SK-025I | Changed target initialization to DNS-only bootstrap with an exact quick-profile engagement. | Init/config-discovery tests and source inspection. |
| SK-025N | Put native DNS, TLS, TCP, and infrastructure resolution behind `PolicyNetwork`; derived names and every address are denied before query or connection unless granted. | Loopback allow, derived-host denial, mixed-answer denial, concrete-address connect, and metadata-address tests. |
| SK-025W | Removed the WebSocket handshake's second uncontrolled hostname resolution by handing the protocol client a `PolicyNetwork`-authorized concrete connection. | Denied-hostname-before-connect and authorized-loopback WebSocket tests. |
| SK-025P | Made profile selection fail closed and observable across DAST, SAST, infrastructure, cloud, and unified assessment. | Unknown-profile negatives for every non-DAST family plus facade profile-requirement contracts. |
| SK-025S | Re-established the public extension contract around policy-owned HTTP and explicit family module registration, then migrated the stale SDK and architecture docs. | Standalone DAST/SAST example tests and warning-denied Rustdoc. |
| SK-025R | Centralized scan report artifact selection across normal, resume, code, infrastructure, cloud, and assessment commands. | Default, terminal-only, and SARIF artifact-selection regression. |
| SK-026 | Closed the mutation-blind changed-file ledger by separating executable tests, non-behavioral edits, static contracts, public wiring, and behavior seams with direct tests. | Canonical DIFF `blind-files.txt` lists 85 files; every file has an exact class and evidence disposition in the completed pipeline notes. |
| SK-027D | Passed the canonical DIFF gate without changing floors, exclusions, retries, ignores, or suppressions. | 19 gates passed, 0 failed, 3 named web-only skips; 77.94% line coverage and 639/639 viable mutations caught. |
| SK-027R | Repaired the 14-file survivor cluster and validated only the 42 changed behavior seams. | 171 selected mutations; final 162/162 viable caught, 0 missed, 9 unviable, with an exact three-item survivor recheck. |
| SK-027V | Passed every current non-mutation delivery lane and resolved validation without launching mutation outside the repaired scope. | Pre-completion focused-repair gate: 19 pass, 0 fail, 3 named web skips; 78.68% coverage and sealed 162/162 focused evidence. |
| SK-027A | Submitted the AAR, archived TICKET-001, repaired the archived ticket/spec cross-links and process-exit teardown race, and proved the archived content through the approved focused-repair delivery path. | No active pipeline; pipeline integrity check green; final focused evidence catches 167/167 viable mutations with 10 unviable; exact-tree receipt records `focused-repair` and the sealed evidence digest. |
| SK-028 | Replaced four serial-looking orchestration loops with one agent-neutral bounded executor, caller cancellation, whole-batch deadlines, stable outcomes, and explicit producer/consumer phases. | Four-family contract suite; bounded HTTP/process cancellation; 79.26% line coverage; 1,406/1,406 Nextest cases; sealed 35/35 viable focused mutations with zero missed. |
| SK-029 | Added a provider-neutral durable DAST job lifecycle with progress, cancellation, recovery, resume, audit events, in-memory and PostgreSQL stores, foreground CLI control, and stateless MCP startup. | Eight inspection findings fixed; 79.55% line coverage; 1,433/1,433 Nextest cases; PostgreSQL and CLI/MCP contracts green; sealed evidence reconstructs 233/233 viable mutations caught plus a 41/41 final-tree validator follow-up. |

The sealed Codex Security scan `efe30eaf-9b1b-4572-949a-0e8391d48247` reviewed 603 changed paths and
closed 192/192 semantic rows. Its eight high-confidence findings have code fixes and regression
mapping in the completed pipeline notes. The original report remains immutable; the durable
[security review](../security/TICKET-001-security-review.md) is part of TICKET-001 completion
evidence.

## Current validation evidence

Evidence produced through the TICKET-003 pre-completion worktree:

| Signal | Last result | Final requirement |
|---|---:|---:|
| Compiler | all targets and all features passed | pass after final edits |
| Strict Clippy | zero diagnostics across every derived feature state | pass after final edits and every feature state |
| All-feature tests | 1,241 library cases with 4 reasoned live-network cases ignored; all integration and doctests green | pass after final edits with PostgreSQL |
| Canonical line coverage | 79.55% | at least 62%; next ratchet target 80% |
| SK-029 DIFF mutation baseline | 279 selected: 150 test-failure catches, 22 timeout catches, 61 missed, and 46 unviable; 73.81% pre-repair MSI | retain as the broad survivor inventory; do not repeat during focused repair |
| Focused SK-029 survivor repair | Exact recheck of all 61 survivors caught 61/61 with zero misses, timeouts, or unviable cases | reconstructed 233/233 viable caught at the unchanged 95% floor |
| Focused SK-029 validator follow-up | All 41 mutants generated for the two mechanically edited validator functions were caught | preserve the final-tree transition without double-counting the broad score |
| Interrupted full inventory | incomplete: status 1, 239 caught or timed out, 115 missed, no score | discovery evidence only; never report as green |
| Nextest strictness | 19 nonempty suites; 1,433/1,433 executed cases passed and 6 live-network cases skipped by reason | pass |
| PostgreSQL integration | 62 MCP, 11 storage, and 8 storage-integration tests passed | pass |
| CLI/MCP contracts | 21 CLI, 2 code-scan, 62 MCP, and 13 scan-plan tests passed | pass |
| Delivery receipt | TICKET-003 pre-completion focused gate passed 19 applicable lanes with no failures and 3 named web-only skips | post-archive matching focused-repair receipt and evidence digest |

The test count is historical evidence, not a promised final count. The gate output after all source and
documentation edits is authoritative.

## Baseline blockers

None. The feature-readiness baseline, SK-028, and SK-029 are closed above.

## Accepted technical debt after baseline

Accepted debt is ordered work, not a waiver of a safety invariant. Each row names its dependency and
the evidence required to close it.

| Order | Batch | Debt and planned correction | Depends on | Exit evidence |
|---:|---|---|---|---|
| 1 | SK-030 | Replace `AiProvider::generate(system, user)` with typed plan, analysis, correlation, and remediation contracts. Version prompt and response schemas. | SK-027 | Codex and Claude adapters pass the same fixtures; disabled/unavailable AI never changes scan success. |
| 2 | SK-031 | Package the Codex-first plugin and focused skills for engagement setup, planning, execution, reporting, and remediation verification. | SK-029, SK-030 | Codex runs an authorized local engagement through typed MCP content without shell instructions. |
| 3 | SK-032 | Return typed MCP structured content, separate read/state/effect tools, and attach correct annotations and principal context. | SK-029 | Schema snapshots, authorization negatives, and transport-independent server tests. |
| 4 | SK-033 | Extract stable core, policy, executor, family, storage, MCP, CLI, and agent crates after contracts are fixed. | SK-028, SK-029, SK-030 | Workspace dependency graph enforces the intended direction and all contract suites remain green. |
| 5 | SK-034 | Reduce scanner duplication into request, response-diff, confidence, evidence, parser, and finding-mapping components. Version plugin definitions and bound temporary files. | SK-028, SK-033 | Each adapter has metadata, fixtures, policy class, bounded output, and parser property tests. |
| 6 | SK-035 | Version observation, finding, evidence, correlation, SARIF, and report identity. Apply one redaction policy to every sink. | SK-029, SK-034 | Cross-format golden tests agree on identity, severity, confidence, provenance, and redaction. |
| 7 | SK-036 | Reintroduce webhooks only through a policy-owned event-delivery service with retries bounded outside scan execution. | SK-028, SK-035 | Authorized loopback delivery tests, denial tests, redaction tests, and queue bounds. |
| 8 | SK-037 | Add authenticated remote MCP transport with principal-to-engagement binding, host validation, and a TLS termination policy. | SK-032 | Remote startup fails without authentication and passes adversarial host/principal tests. |
| 9 | SK-038 | Add a Windows Job Object process owner before enabling Windows builds. | SK-028 | Windows CI proves child and descendant cleanup for success, timeout, cancellation, output limit, and drop. |
| 10 | SK-039 | Replace reachable unmaintained `fxhash` and `number_prefix` transitives and remove the time-bounded disabled-MySQL advisory exception. | upstream availability or dependency replacement | `cargo audit`/`cargo deny` without the reviewed exceptions. |
| 11 | SK-040 | Ratchet line coverage from the 62% floor toward 80%, then raise mutation and coverage floors from measured green results. | SK-027 | Full database-backed `cargo llvm-cov` at the new proposed floor and a reviewed blind-file report. |
| 12 | SK-041 | Add reproducible builds, SBOM, provenance, signing, upgrade tests, and performance/chaos budgets. | SK-033, SK-035 | Clean-checkout release gate, signed artifacts, SBOM/provenance verification, and tested rollback. |
| 13 | SK-042 | Restore the 12 native AWS, GCP, and Azure modules through provider authentication and service transports owned by ScorchKit policy. | SK-028, SK-033 | Public registry census plus authorized-loopback and denial tests for auth endpoints, service endpoints, redirects, every DNS answer, metadata addresses, and credentials for all three providers. |

## Target architecture

```text
Codex plugin / Claude adapter / other hosts
                    |
         typed MCP and host contracts
                    |
      policy-gated job control plane
                    |
       shared executor and adapters
       /          |          |       \
     DAST        SAST      Infra     Cloud
       \          |          |       /
       observations, evidence, findings
                    |
       storage, correlation, reports
```

The intended workspace split is a destination, not the next edit:

```text
crates/
  scorchkit-core/       targets, observations, findings, evidence, descriptors
  scorchkit-policy/     engagements, scope, capabilities, decisions, audit types
  scorchkit-executor/   jobs, events, cancellation, process and resource limits
  scorchkit-web/        DAST and recon adapters
  scorchkit-code/       deterministic SAST and code-tool adapters
  scorchkit-infra/      network, TLS, DNS, and CVE adapters
  scorchkit-cloud/      cloud posture adapters
  scorchkit-tools/      process contracts and parsers
  scorchkit-storage/    storage trait and PostgreSQL implementation
  scorchkit-mcp/        typed, policy-aware MCP server
  scorchkit-cli/        human and CI interface
  scorchkit-agent/      provider-neutral reasoning contracts and host adapters
```

Crate extraction begins only after policy, executor, job, and provider contracts prevent moves from
changing behavior silently.

## Quality system

`bin/gate.sh` is the only delivery verdict. DIFF and FULL execute mutation testing. The narrowly
approved focused-repair mode verifies sealed raw mutation outcomes at the same 95% floor and reruns
every other delivery lane without compiling or testing mutants. TICKET-001 established the repair
campaign contract. TICKET-002 has a separate owner-approved SK-028 scope because the accumulated
worktree makes Git DIFF select 1,038 mutants across 135 files instead of the five changed executor
files. Its verifier binds the initial 68-mutant inventory, exact two-survivor recheck, current
inventory equivalence, two inline-test source snapshots, raw logs, and both mutation-input hashes.
The receipt records the mode and binds the cumulative evidence digest under `CONSTITUTION.md` §19.

### Static gates, IDs 1–14

Rustfmt, derived-feature Clippy with warnings denied, all-feature tests, warning-denied Rustdoc,
Cargo Audit, Cargo Deny, Cargo Machete, Gitleaks, ShellCheck and script selftests, suppression policy,
source bans, actionable-marker policy, Cargo Sort/Taplo/typos, and Semgrep.

### Delivery gates, IDs 15–22

Coverage, mutation, named web skips 17–19, Nextest strictness, migrated PostgreSQL integration, and
CLI/MCP contracts. The web IDs remain visible not-applicable skips because ScorchKit has no web UI.

Missing tools and missing database configuration fail closed. Cargo commands run sequentially.
Mutation workers may run in bounded parallel on local scratch. Floors may rise through reviewed
changes; they may not be lowered to obtain green.

### Scheduled evidence after feature readiness

- `SK-027F`: run the complete full mutation inventory in planned local-scratch shards, preserve one
  merged compact result, require at least 95% viable MSI, and use survivors to open focused repair
  tickets rather than rerunning the full inventory after each edit;
- advisory, license, and unused-dependency refresh;
- authorized lab-only smoke scans for every effect class;
- performance, resource-limit, cancellation, and failure-injection benchmarks.

## Feature sequence

With SK-027A complete, new product work should follow this order:

1. Build job control and storage abstraction before adding long-running scan features.
2. Add typed agent contracts and the Codex plugin before expanding conversational automation.
3. Consolidate scanner adapters before adding many new modules.
4. Version evidence and reports before exposing stable remote APIs.
5. Add authenticated remote operation only after principal and engagement binding are explicit.
6. Begin quasi-pentest capabilities only after job cancellation, cleanup, evidence, and per-effect
   authorization are proven.

Quasi-pentest plans must name preconditions, blast radius, cleanup, evidence, and a separate grant for
each credential, exploit, persistence, privilege, lateral-movement, or destructive effect. An agent
may propose the plan. ScorchKit remains the authority that permits or denies execution.

## Definition of done for future work

A batch is complete only when:

- its ticket contains one observable EARS requirement and verification method per behavior;
- plan and design were confirmed through the pipeline state machine;
- implementation matches the confirmed file and boundary design;
- correctness, security, data-integrity, and simplification findings have dispositions;
- every new effect path has authorization, audit, redaction, timeout, cleanup, and negative tests;
- the exact changed worktree passes the required DIFF or FULL gate;
- public CLI, MCP, config, report, storage, and plugin compatibility is documented;
- durable lessons are recorded in the AAR and knowledge register;
- no floor, exclusion, retry, skip, suppression, or advisory exception was broadened to obtain green.
