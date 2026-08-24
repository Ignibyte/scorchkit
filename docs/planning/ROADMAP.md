# ScorchKit roadmap

**Status:** SK-049 is complete; SK-050 is next; SK-051 through SK-057 are documented platform candidates
**Started:** 2026-08-14  
**Last reviewed:** 2026-08-23
**Direction:** agent-neutral application-security evidence and execution engine with Codex as the
preferred host

## Product boundary

ScorchKit owns deterministic application-security effects and evidence:

- engagement authorization, target scope, capabilities, and effect classes;
- source analysis, secrets, dependencies, application IaC, artifact analysis, web/API DAST, and
  code-informed application testing;
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

Codex model selection remains outside the engine contract. Separately approved defenders can use
Daybreak Blue for host reasoning when it is provisioned on their applicable identity and product
surface. ScorchKit does not grant model access, select or substitute a model, or convert model
conclusions into scanner evidence.

The core product does not implicitly select general port and network enumeration, Active Directory,
SMB, Kerberos, password spraying, cloud-account posture, persistence, lateral movement, or
general-purpose exploit frameworks. Existing adapters remain available through an explicit
compatibility or future extension surface until a reviewed deprecation decides their disposition.
Application deployment definitions, containers, Kubernetes manifests, and cloud configuration that
directly describe the assessed application remain in scope.

## Current source census

The 3.0.0 repository contains about 73,000 lines of Rust. Registry code and contract tests establish
this module census:

| Family | Count | Source of truth |
|---|---:|---|
| DAST and recon | 89 | 10 recon + 35 scanner + 44 tool adapters |
| SAST | 22 | 1 native module + 21 tool adapters |
| Infrastructure | 4 or 5 | 4 registered modules plus configured CVE correlation |
| Cloud | 5 | Bounded external-tool adapters; 12 native provider modules are private and test-only |
| Maximum | 122 | All production registries, including optional CVE correlation |

Of the 44 DAST tool adapters, 43 are bounded one-shot processes and Interactsh owns a long-lived
callback session. All 21 SAST adapters are bounded one-shot processes.

This census is an inventory, not the intended default product surface. SK-034 introduced an
application-security classification and prevents non-application families from implicit Codex, CLI,
MCP, or profile selection while preserving an explicit compatibility catalog.

Supported production hosts are Linux, macOS, and Windows. Unix process groups and Windows
kill-on-close Job Objects enforce the same bounded descendant-process cleanup contract.

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
| SK-030 | Replaced the raw AI prompt boundary with typed, versioned planning, analysis, correlation, and remediation contracts shared by Codex and Claude adapters. | External-provider bypass fixed; 79.63% line coverage; 1,432 Nextest cases; PostgreSQL and CLI/MCP contracts green; scoped DIFF caught 26/26 viable mutations with zero survivors. |
| SK-031 | Packaged the Codex-first host adapter with local stdio MCP startup and focused preparation, planning, execution, reporting, and remediation-verification skills while keeping the engine agent-neutral. | Official package/skill validators and repository negative contracts green; registered-target denial and profile-narrowing tests green; 79.54% line coverage; 1,433 Nextest cases; scoped DIFF caught 2/2 viable mutations with zero survivors. |
| SK-032 | Added versioned native MCP success/error results, an exhaustive 30-tool read/local-state/external-effect inventory, complete conservative annotations, and local-process principal context with explicitly untrusted client attribution. | Exact schema/inventory fixtures and router/duplex/spoofing tests green; 79.68% line coverage; 1,439 strict cases; one 54-mutant DIFF baseline plus an exact two-survivor `tool_title` recheck yields sealed 13/13 viable mutations caught with zero misses. |
| SK-033 | Extracted stable policy, domain, configuration, executor, process, family, storage-model, MCP, CLI, and agent contracts into 13 internal packages while retaining `scorchkit` as the composition and compatibility facade. | Exact manifest-edge, type-identity, version, and visibility tests; 79.99% line coverage; 1,443 strict cases; PostgreSQL and CLI/MCP contracts green; 83/83 viable mutations caught across the 11 inspection-repaired functions. |
| SK-034 | Narrowed every implicit host catalog to application security, retained non-core adapters behind explicit compatibility selection, and added a versioned cross-family descriptor, bounded invocation fields, typed parser outcomes, and scoped artifact ownership. | Exact 69/22 web and 21/1 code catalog partitions; Nuclei/Semgrep integrity fixtures; credential/effect denial-before-execution tests; 79.11% line coverage; 1,469 strict cases; sealed evidence catches 48/48 viable mutations across 23 inspection-repaired functions. |
| SK-035 | Added a provider-neutral v2 finding/observation contract with typed locations, scanner provenance, redacted evidence, stable identities, correlation keys, separately labeled agent analysis, enriched Semgrep/Nuclei producers, canonical report projections, and append-preserving PostgreSQL persistence. | Legacy/v2 migration, redaction, identity, SARIF, report, and fresh-schema PostgreSQL tests; 79.44% line coverage; 1,494 strict cases; the completed 157-mutant DIFF baseline plus exact 25-survivor repair closes 109/109 viable mutations with 48 unviable and zero misses. |
| SK-036 | Added reproducible fast/deep SAST with an embedded or exact-digest Semgrep pack, offline no-build CodeQL, isolated Psalm taint analysis, corrected PHPStan evidence, typed coverage outcomes, and complete code-flow provenance. | Nine inspection findings repaired; 81.90% line coverage; 1,574 strict cases; PostgreSQL and CLI/MCP contracts green; the preserved 521-mutant DIFF plus exact 111-survivor repair closes 421/421 viable mutations with 100 unviable and zero misses. |
| SK-037 | Added application-only supply-chain analysis for source trees and local artifacts with one verified CycloneDX SBOM, offline OSV/Grype/Trivy consumers, typed provider snapshots, and policy-owned refresh. | Twelve inspection findings repaired; 82.40% line coverage; 1,664 strict cases; PostgreSQL and CLI/MCP contracts green; sealed focused evidence catches 211/211 viable mutations with zero misses. |
| SK-038 | Replaced the ambient ZAP quick-scan wrapper with authorized OWASP ZAP Automation Framework plans for anonymous, header-token, and browser personas plus digest-pinned OpenAPI and GraphQL inputs. | Nine inspection findings repaired; three pinned-runtime loopback integrations; 81.26% line coverage; 1,744 strict cases; PostgreSQL and CLI/MCP contracts green; sealed evidence catches 79/79 viable delivery mutations plus the 5/5 final-tree follow-up with zero misses after one preserved broad inventory. |
| SK-039 | Replaced ambient Nuclei template discovery with an explicit signed local collection, application-HTTP classifier, exact policy grants, concrete-address execution, and typed adapter evidence across every public and durable projection. | Thirteen inspection findings repaired; signed pinned-runtime loopback integration; 83.15% line coverage; 1,780 strict cases; PostgreSQL and CLI/MCP contracts green; sealed current-tree evidence catches the exact remaining viable mutation with zero misses while preserving the prior 84- and 39-case focused inventories. |
| SK-040 | Correlated source flows, runtime proof, deployment provenance, and comparable verification into versioned attack paths with inert focused selectors and append-only transitions. | Fifteen inspection findings repaired; 216/216 viable focused mutations caught at 100% MSI; PostgreSQL, MCP, and canonical report projections green. |
| SK-041 | Added stable application-only pentest plans, closed trusted execution, isolated persona invariants, typed coverage, and atomic redacted HAR/manual evidence import. | Ten reportable inspection findings and three hardenings repaired; 84.03% line coverage; 1,861 strict cases; PostgreSQL and CLI/MCP contracts green; sealed evidence catches 194/194 viable focused mutations at 100% MSI. |
| SK-042 | Added inert provider-neutral application context, immutable change sets, tiered workflow plans, two read-only MCP tools, and a Codex-first application-security coordinator. | Exact-tree security review found no reportable finding; 81.75% line coverage; 1,873 strict cases; PostgreSQL and CLI/MCP contracts green; sealed evidence catches 152/152 viable mutations at 100% MSI. |
| SK-043 | Restored webhook delivery through a redacted durable queue, policy-owned network attempts, credential-indirect configuration, revision ownership, recovery, immutable audits, and foreground-independent workers. | Thirteen inspection findings repaired; 84.39% line coverage; 1,904 strict cases; PostgreSQL and CLI/MCP contracts green; canonical DIFF caught 276/283 viable mutations at 97.52% MSI, above the unchanged 95% floor. |
| SK-044 | Added authenticated remote MCP through a trusted same-host TLS proxy with principal-to-engagement binding, isolated stateful sessions, bounded request guards, and credential scrubbing. | Ten inspection findings repaired; 84.55% line coverage; 1,928 strict cases; PostgreSQL and CLI/MCP contracts green; canonical DIFF caught 117/117 viable mutations at 100% MSI. |
| SK-045 | Added Windows suspended-spawn Job Object ownership and native CI while preserving Unix process groups and one bounded provider-neutral child lifecycle for one-shot and Interactsh execution. | Seven inspection findings repaired; Windows-target workspace Clippy green; 84.58% line coverage; 1,931 strict cases; 100 PostgreSQL tests and CLI/MCP contracts green; canonical DIFF caught 16/16 viable mutations at 100% MSI. |
| SK-046 | Replaced reachable unmaintained parser and progress dependencies, upgraded SQLx with an exact PostgreSQL-only graph, and removed the disabled-MySQL RSA audit exception. | Unignored Audit/Deny/Machete green; HTML, progress, peer-auth, PostgreSQL, CLI, and MCP contracts green; 84.59% line coverage; 1,937 strict cases; canonical DIFF caught 7/7 viable mutations at 100% MSI. |
| SK-047 | Preserved the owner-stopped broad mutation work as incomplete discovery evidence and repaired only its exact reproduced survivor set without another broad campaign or unsupported floor change. | Completed 13-candidate baseline caught 1 and reproduced 12 misses; direct TLS, rate-limit, and SSRF tests made the exact recheck catch all 12; sealed evidence accounts for 13/13 viable at 100% focused MSI; 84.71% line coverage and 1,945 strict cases passed. |
| SK-048 | Added reproducible raw binaries for four native targets, exact Rust/features, target-header validation, canonical manifest/checksums, per-binary CycloneDX SBOMs, signed SLSA provenance, draft-first publication, hard operational budgets, and v2.1.0 upgrade/restore proof. | Five inspection findings repaired; local Linux double-build bytes matched; exact tool downloads and live upgrade/failure/restore passed; 82.13% line coverage and 1,954 strict cases passed; canonical DIFF completed an explicit empty mutation selection at 100% MSI without a broad campaign. |

The sealed Codex Security scan `efe30eaf-9b1b-4572-949a-0e8391d48247` reviewed 603 changed paths and
closed 192/192 semantic rows. Its eight high-confidence findings have code fixes and regression
mapping in the completed pipeline notes. The original report remains immutable; the durable
[security review](../security/TICKET-001-security-review.md) is part of TICKET-001 completion
evidence.

## Current validation evidence

Evidence produced through the TICKET-026 pre-completion worktree:

| Signal | Last result | Final requirement |
|---|---:|---:|
| Compiler | all targets, workspace packages, and features passed | pass after final edits |
| Strict Clippy | zero diagnostics across every derived feature state and workspace package | pass after final edits and every feature state |
| All-feature tests | Workspace library, package, integration, and doctest suites passed; strict feature-matrix Clippy had zero diagnostics | pass after final edits with PostgreSQL |
| Canonical line coverage | 82.13% | at least the unchanged 62% floor |
| SK-048 DIFF mutation selection | Completed with explicit empty evidence: 0 viable, missed, timed out, or unviable mutations and 100% MSI; no broad campaign ran | remain at or above the unchanged 95% floor |
| Nextest strictness | 1,954 executed cases passed and 10 live-tool/network cases were skipped by reason; exact contract-only library harnesses remain explicitly allowlisted | pass |
| PostgreSQL integration | 77 MCP, 12 storage, and 11 storage-integration tests passed | pass |
| CLI/MCP contracts | 24 CLI, 2 code-scan, 77 MCP, and 12 scan-plan tests passed | pass |
| Delivery receipt | TICKET-026 pre-completion DIFF gate passed 19 applicable lanes with no failures and 3 named web-only skips | post-archive DIFF receipt for the exact completed tree |

The test count is historical evidence, not a promised final count. The gate output after all source and
documentation edits is authoritative.

## Baseline blockers

None. The feature-readiness baseline and SK-028 through SK-049 are closed above.

## Ordered product and platform backlog

The pipeline permits one active ticket. TICKET-027 closed the provider-neutral control boundary;
SK-050 is the next platform candidate.
Each later row has a specified candidate intake under `docs/planning/intake/` and becomes a numbered
ticket only when promoted. Backlog status is not a waiver of a safety invariant.

| Order | Batch | Planned outcome | Depends on | Planning artifact |
|---:|---|---|---|---|
| 1 | SK-040 (completed) | Correlate source flows, routes, parameters, components, and runtime proof into versioned attack paths and focused verification selections. | SK-035 through SK-039 | [TICKET-015](tickets/closed/TICKET-015-source-runtime-correlation.md) |
| 2 | SK-041 (completed) | Add code-informed, application-only pentest scenarios plus HAR/manual proxy evidence interoperability. | SK-038 through SK-040 | [TICKET-016](tickets/closed/TICKET-016-application-pentest.md) |
| 3 | SK-042 (completed) | Present change-aware commit, PR, staging, release, and deep AppSec workflows through Codex-first, agent-neutral contracts. | SK-036 through SK-041 | [TICKET-017](tickets/closed/TICKET-017-codex-appsec-workflows.md) |
| 4 | SK-043 (completed) | Restore webhook delivery through a redacted, policy-owned, durable bounded queue outside scan execution. | SK-028, SK-035 | [TICKET-021](tickets/closed/TICKET-021-policy-webhooks.md) |
| 5 | SK-044 (completed) | Add authenticated remote MCP with principal-to-engagement binding, host validation, and an explicit TLS policy. | SK-032, SK-035 | [TICKET-022](tickets/closed/TICKET-022-authenticated-remote-mcp.md) |
| 6 | SK-045 (completed) | Add Windows Job Object process ownership before enabling Windows builds. | SK-028, SK-034 | [TICKET-023](tickets/closed/TICKET-023-windows-process-owner.md) |
| 7 | SK-046 (completed) | Replace reachable unmaintained dependencies and remove the reviewed disabled-MySQL advisory exception. | upstream availability or replacement | [TICKET-024](tickets/closed/TICKET-024-dependency-debt.md) |
| 8 | SK-047 (completed) | Preserve the stopped broad campaign as incomplete discovery evidence and close the exact reproduced survivor set without another broad run or an unsupported floor change. | SK-027 | [TICKET-025](tickets/closed/TICKET-025-quality-ratchet.md) |
| 9 | SK-048 (completed) | Add reproducible ScorchKit releases, signed artifacts, SBOM/provenance, upgrade and rollback tests, and performance/chaos budgets. | SK-033, SK-035, SK-046 | [TICKET-026](tickets/closed/TICKET-026-reproducible-releases.md) |
| 10 | SK-049 (completed) | Add a versioned provider-neutral control API and self-description contract for configuration, engagements, jobs, findings, evidence, modules, reports, and event streams. | SK-029, SK-032, SK-033, SK-044, SK-048 | [TICKET-027](tickets/closed/TICKET-027-control-api.md) |
| 11 | SK-050 | Add a capability-declared extension manifest, SDK, and isolated runtime for first-party and third-party application-security modules. | SK-034, SK-048, SK-049 | [intake](intake/INTAKE-extension-runtime.md) |
| 12 | SK-051 | Promote the existing event bus and lifecycle hooks into a typed run pipeline for preprocessing, planning proposals, normalization, enrichment, correlation, reporting, and notification. | SK-028, SK-043, SK-049, SK-050 | [intake](intake/INTAKE-typed-run-pipeline.md) |
| 13 | SK-052 | Add provider-neutral model roles, host and service adapters, provenance, readiness reporting, and evaluations without granting a model execution authority or scanner-evidence status. | SK-030, SK-031, SK-042, SK-049, SK-050 | [intake](intake/INTAKE-model-analysis.md) |
| 14 | SK-053 | Add an append-only finding validation and triage lifecycle with correlation, scoped suppression, accepted risk, fix state, and regression verification. | SK-035, SK-040, SK-041, SK-052 | [intake](intake/INTAKE-finding-triage.md) |
| 15 | SK-054 | Add optional conversation-native result views for scan summaries, evidence, triage, and attack paths while keeping every MCP and API workflow complete without UI. | SK-031, SK-032, SK-042, SK-049, SK-053 | [intake](intake/INTAKE-conversation-workbench.md) |
| 16 | SK-055 | Add an optional Rustal-based local operator console that consumes the control API for jobs, evidence, triage, engagement editing, and live progress. | SK-049, SK-053, SK-054 | [intake](intake/INTAKE-rustal-console.md) |
| 17 | SK-056 | Add an authenticated multi-user deployment profile with tenant and project isolation, RBAC, shared queues, object storage, audit, backup, and recovery. | SK-043, SK-044, SK-048, SK-049, SK-055 | [intake](intake/INTAKE-team-suite.md) |
| 18 | SK-057 | Add a signed extension catalog with compatibility, provenance, permission review, upgrade, rollback, revocation, and conformance checks. | SK-048, SK-050, SK-051, SK-052 | [intake](intake/INTAKE-extension-catalog.md) |

The former native cloud-provider restoration item is removed from the core sequence. General cloud
posture may return only as an explicit optional extension; application IaC and deployment artifacts
remain part of SK-036 and SK-037. Existing quarantined provider modules remain private and
test-only.

## Post-release platform contracts

SK-049 through SK-057 extend the application-security engine without replacing its current local,
headless operation. They follow these contracts:

1. **One application service.** Engagements, policy decisions, configuration resolution, jobs,
   findings, evidence, triage, modules, and events have one provider-neutral command/query boundary.
   CLI, MCP, conversation components, Rustal, CI, and later remote clients adapt that boundary. A
   client never writes ScorchKit storage directly.
2. **Configuration narrows toward policy.** Built-in defaults, organization profiles, project
   profiles, and run overrides produce one effective configuration and decision log. A later layer
   may narrow a grant but cannot expand the engagement's target, capability, or effect class.
3. **Extensions declare effects.** First-party modules may remain compiled Rust. Third-party
   modules run outside the ScorchKit process through a versioned protocol and declare their input
   and output schemas, network, filesystem, credential, and subprocess effects, plus time, memory,
   and output-size budgets.
   Manifests and host approval remain context; the engine authorizes every effect. Extensions
   return typed outputs to the engine and never receive a direct ScorchKit storage handle.
4. **Hooks propose typed changes.** The current event bus and pre-scan, post-module, and post-scan
   hooks are the starting seam. Future preprocessors and hooks return versioned proposals. ScorchKit
   validates and reauthorizes a proposal before it can change planning or execution. Scanner
   evidence stays immutable; enrichment and filtering decisions are separate records.
5. **Models interpret rather than authorize.** Host-managed Codex or another agent, optional
   service adapters, and local models share typed analysis roles and provenance. ScorchKit reports
   an unavailable requested role instead of silently substituting a model. Model output remains
   labeled analysis and cannot become scanner evidence or grant an effect.
6. **Triage preserves disagreement.** Detector output, correlation, model assessment, user
   disposition, accepted risk, suppression, fix, and regression verification are append-only
   transitions. Suppressions are scoped, reasoned, expiring, and auditable. The original finding
   and evidence remain readable.
7. **Frontends are optional clients.** Conversation views and a Rustal console can inspect,
   compare, confirm, and navigate structured results. Every tool and command remains useful without
   a component. Local operation remains complete before the authenticated multi-user profile is
   added.
8. **Rustal does not enter the core dependency graph.** A future `scorchkit-console` may use
   Rustal's compiled pages, modules, RBAC, audit, PostgreSQL support, and server-sent updates, but it
   consumes the ScorchKit API and does not own ScorchKit authorization, evidence, or storage.

The platform candidates remain application-security work. General network, enterprise, cloud
posture, persistence, privilege, and lateral-movement features do not return to the default product
through an extension, API, model, or frontend.

## Target architecture

```text
Codex / Claude compatibility / other hosts   CLI / CI   conversation views   Rustal   teams
                    \                           |                |              |       /
                     \------ MCP and versioned control API / event stream -----/
                                              |
                     provider-neutral application commands and queries
                                              |
                  configuration, engagements, policy, jobs, and audit
                                              |
               capability-declared extension and lifecycle-hook runtime
                                              |
             source / dependencies / artifacts / runtime / manual inputs
                                              |
                 immutable observations, findings, evidence, attack paths
                                              |
                    labeled model analysis, triage, storage, reports

Explicit optional extensions: network / enterprise / cloud posture
```

SK-033 implemented this workspace split:

```text
crates/
  scorchkit-core/       targets, observations, findings, evidence, descriptors
  scorchkit-policy/     engagements, scope, capabilities, decisions, audit types
  scorchkit-config/     configuration, credentials, provider and webhook shapes
  scorchkit-executor/   scheduling, durable jobs, cancellation, resource limits
  scorchkit-web/        DAST and recon adapters
  scorchkit-code/       deterministic SAST and code-tool adapters
  scorchkit-infra/      network, TLS, DNS, and CVE adapters
  scorchkit-cloud/      cloud posture adapters
  scorchkit-tools/      process contracts, ownership, and bounded output
  scorchkit-storage/    persistence record models
  scorchkit-mcp/        typed MCP schemas, inventory, annotations, and results
  scorchkit-cli/        human and CI argument contract
  scorchkit-agent/      provider-neutral reasoning, manifest, and prompt contracts
```

The root `scorchkit` package remains the composition and compatibility facade. Family packages own
stable categories and descriptors while policy-sealed contexts and concrete adapters remain in the
root package. Exact allowed dependency edges are executable in `tests/workspace_architecture.rs`.

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
Documenting SK-054 and SK-055 does not change that status. A future UI ticket must replace each skip
with an executable browser, rendering, or asset-drift contract before claiming the surface ships.

Missing tools and missing database configuration fail closed. Cargo commands run sequentially.
Mutation workers may run in bounded parallel on local scratch. Floors may rise through reviewed
changes; they may not be lowered to obtain green.

### Scheduled evidence after feature readiness

- `SK-047` disposition: the owner stopped the broad campaign after two complete shards and 138
  outcomes from a third. Those artifacts remain incomplete discovery evidence, not a FULL result;
  the completed exact candidate baseline and survivor-only repair closed 13/13 viable candidates at
  the unchanged 95% floor without running another broad campaign;
- advisory, license, and unused-dependency refresh;
- authorized lab-only smoke scans for every effect class;
- performance, resource-limit, cancellation, and failure-injection benchmarks.

## Feature sequence

With job control, typed agent contracts, the Codex plugin, MCP hardening, and workspace extraction
complete, product work follows this order:

1. Narrow and consolidate scanner adapters before adding new tools.
2. Version evidence, provenance, identity, reports, and storage before deep integrations.
3. Add source and artifact depth before relying on runtime correlation.
4. Add authenticated schema-driven DAST and trusted runtime templates against registered staging or
   disposable applications.
5. Correlate static hypotheses with runtime proof and use those links for focused repair
   verification.
6. Add application-only pentest scenarios after persona, evidence, cancellation, cleanup, and
   per-effect authorization are proven.
7. Expose the complete lifecycle through Codex-first, agent-neutral profiles.
8. Deliver remote and platform expansion without allowing it to reorder the AppSec core.
9. Stabilize the provider-neutral application service and control API before building a frontend.
10. Add extension manifests and typed lifecycle proposals before loading third-party modules.
11. Add model roles and durable triage before presenting model-assisted false-positive decisions.
12. Add conversation-native views before a full console, while keeping headless operation complete.
13. Build the Rustal console as an optional API client with no direct ScorchKit database writes.
14. Add multi-user deployment only after remote identity, release, API, triage, and console
    boundaries are proven locally.
15. Publish a signed extension catalog only after runtime isolation, conformance, rollback, and
    revocation contracts exist.

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
