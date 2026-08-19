---
title: Application-security registry and scanner adapter foundation — notes
pipeline_id: d53149f6-15a8-4448-a980-72609e59df62
---

# Application-security registry and scanner adapter foundation — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: `PR-scorchkit-policy-before-effects-001` requires authorization before a
  process or client; `PR-scorchkit-executor-contract-001` requires one injectable bounded process
  seam; `PR-scorchkit-effect-contract-single-source-001` requires one exhaustive behavior
  inventory; `PR-scorchkit-workspace-gate-scope-001` requires workspace-wide verification;
  `PR-scorchkit-facade-visibility-preservation-001` prevents refactors from widening constructors;
  `PR-scorchkit-focused-mutation-repair-001` records the owner's preference to repair named
  survivors without repeating a broad inventory.
- Comparable work: WORK-085 introduced the parallel SAST family but assumed the shared `Finding`
  was sufficient; WORK-093 correlated findings by coarse module identity; WORK-096 introduced
  custom runtime rules; WORK-116 connected API specs to six consumers; TICKET-007 extracted stable
  vocabulary while deliberately retaining policy-sealed composition in the root package.
- Recon result: the next change should narrow and describe adapters without yet changing scanner
  depth or evidence wire formats. The latter have independent compatibility and security risks.
- Operator confirmation: on 2026-08-17 the owner directed creation and specification of the
  remaining roadmap. That confirms backlog preparation only; passing Plan and beginning Design or
  implementation still requires the next explicit phase instruction.
- Operator confirmation: on 2026-08-17 the owner explicitly directed Codex to wrap up the active
  ticket. This authorizes the remaining pipeline phases within the locked TICKET-008 scope.

## Phase 2 — Design

- Architecture: add `AdapterContractV1` and parser outcomes to `scorchkit-core`; embed the common
  contract in web/code/infra/cloud package descriptors; keep the exhaustive ID classification in
  root composition; derive application and compatibility registries, named-profile filtering,
  CLI/MCP catalogs, AI planning, and external-tool effect authorization from those descriptors.
- Compatibility: retain `all_modules`, `all_code_modules`, module IDs, finding serialization, and
  explicit compatibility selection. Default named profiles and agent catalogs become
  application-only. `full` is corrected to match `thorough`; `network` remains explicit and a new
  `compatibility` template exposes the complete non-core web catalog.
- Security boundary: classification happens before implicit selection, but never grants authority.
  Every selected adapter still needs the exact context-owned target, capability, strongest effect,
  executable, timeout, output, and credential grants. Metasploit and Kerbrute move to exploit and
  credential-test authorization through the canonical tool-effect function.
- File manifest: `crates/scorchkit-core/{Cargo.toml,src/adapter.rs,src/lib.rs}`; the four family
  package manifests and descriptor libraries; `Cargo.toml`/`Cargo.lock`; root catalog, module
  traits, contexts, orchestrators, AI planner, CLI contract/runner, MCP listing; Nuclei and Semgrep
  adapters; registry, architecture, CLI, MCP, parser, profile, and workspace tests; AppSec catalog,
  SAST, roadmap, security, README, changelog, ticket, notes, AAR, and knowledge documentation.
- Regression test plan: core enum/serde/parser outcomes; exact package dependency graph and type
  identity; exhaustive application/compatibility partition with stable total census; representative
  domain/effect/output/provenance assertions; default profile and AI catalog exclusion; explicit
  module and compatibility-template selection; CLI default/all listing; MCP DAST/SAST catalog JSON;
  Nuclei/Semgrep empty/malformed/findings outcomes; ToolInvocation environment and working-directory
  execution; existing policy, process, public example, CLI/MCP, and workspace suites.
- Operator confirmation: the owner's 2026-08-17 direction to wrap up TICKET-008 authorizes this
  design within the locked scope.

## Phase 3 — Implement

- Files and behavior changed:
  - Added `scorchkit.adapter/v1` domains, lifecycle stages, target kinds, effect, output,
    provenance, temporary-artifact, and parser-outcome contracts to `scorchkit-core`; embedded the
    contract in all four scanner-family descriptors.
  - Added one exhaustive root adapter classification with 69 default web application modules, 22
    web compatibility modules, 21 default code modules, and one code compatibility module. Exact
    census tests prove that all 113 web/code IDs have one versioned descriptor.
  - Routed named profiles, CLI listing and execution, MCP listing and execution, durable jobs, AI
    planning, and autonomous-agent planning through application-only defaults. Explicit IDs and the
    web `compatibility` template retain compatibility access. Corrected stale template aliases to
    their preserved module IDs and pinned every advertised template count.
  - Made the DAST authorization effect and profile restriction read the same canonical mapping.
    Hydra, Kerbrute, NetExec, and SMBMap require credential-test authority; Commix and Metasploit
    require exploit authority.
  - Extended bounded tool invocations with environment inheritance/clearing, explicit values, and
    working directories. An execution fixture proves the fields reach the child process.
  - Migrated Nuclei JSONL and Semgrep JSON production parsing to a typed no-findings/findings/
    malformed outcome while retaining their legacy parser return shapes.
  - Found that the legacy code-family ScoutSuite adapter inherited provider credentials with only a
    passive external-tool grant. It now requires a separate exact `CredentialUse/Passive` grant
    before process creation; a recording-executor negative proves denial occurs first.
  - Reconciled declared output shapes with the actual parser inputs, including JSONL, text, and XML;
    replaced SQLMap's shared fixed output directory with a scoped temporary directory; and pinned
    representative web, infrastructure, and cloud artifact contracts.
  - Classified onesixtyone's default-community attempts as credential testing and required a
    separate passive credential-use grant before the legacy web-family Prowler adapter can inherit
    cloud credentials.
  - Added the application-security catalog architecture guide and aligned README, SAST, workspace,
    security, roadmap-facing, changelog, CLI, MCP, and AI contract documentation.
- Design deviations: none. The ScoutSuite credential check is the enforcement needed to satisfy the
  locked rule that explicit compatibility selection does not grant credential authority.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | Several v1 descriptors labeled JSONL, XML, and console parsers as JSON or text, so the canonical metadata did not match execution. | high | Fixed the concrete shape inventory, added XML to v1, and pinned representative cross-family contracts. |
| 2 | Authorization | `apply_selection` validated profiles only for implicit selection, allowing a low-level explicit-ID call to retain modules under an unknown profile. | high | Both web and code selectors now clear on an unknown profile before considering IDs; negative tests cover the bypass. |
| 3 | Authorization | onesixtyone tried default SNMP communities without credential-test classification, while legacy web Prowler could inherit cloud credentials without a passive credential-use grant. | high | Added canonical effect/credential classification and denial-before-executor coverage. |
| 4 | Data integrity | Nuclei accepted schema-invalid JSON values as findings, and Semgrep could drop invalid records or treat a failed/incomplete scan as no findings. | high | Required core record fields, rejected partial records and reported Semgrep errors, and restored strict Semgrep exit handling. |
| 5 | Artifact ownership | SQLMap wrote every run to the shared `/tmp/scorchkit-sqlmap` directory while its descriptor claimed no temporary artifacts. | high | Each run now owns a scoped temporary directory and advertises `scoped_owned`. |
| 6 | Compatibility | The module and CLI guides still claimed a 77-module all-inclusive `thorough` profile. | medium | Updated the 91-module census, 69/22 boundary, explicit listing command, and profile semantics. |
| 7 | Simplification | The exhaustive known-ID census duplicates registry IDs, but it is the root classification guard and plugin-provenance discriminator rather than a host-facing inventory. | none | Retained intentionally; exact set-equality tests make additions fail visibly until classified. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused adapter, catalog, parser, external-tool, module-census,
  formatting, and exact lint checks passed. The final focused-repair gate passed all 19 applicable
  lanes with no failures and three named web-only skips. It included 1,041 root all-feature tests
  with four reasoned live-network ignores, 1,469 Nextest cases with six reasoned skips, 79.11% line
  coverage, PostgreSQL integration, and CLI/MCP contracts.
- Gate run and receipt: DIFF mutation preflight required 48 GiB for two workers while 32 GiB was
  available, so cargo-mutants did not start and no TICKET-008 broad outcomes were produced. The
  owner-approved focused path selected 76 mutations in 23 inspection-repaired functions across 11
  files. The initial run caught 35, missed 13, and found 28 unviable; the exact repaired-function
  recheck caught all 13 former survivors. Sealed evidence reconstructs 48/48 viable caught, zero
  missed or timed out, 28 unviable, and 100% MSI at
  `.git/scorchkit-mutants-focused-ticket-008`.
- Documented skips with reasons: gates 17–19 are the repository's named web-only skips because the
  terminal engine has no web UI, website renderer, or CSS asset pipeline. Live-network tests remain
  reasoned skips and are not delivery proof.

## Phase 5 — Complete

- Docs updated: product and architecture guides now describe the application-only default catalog,
  explicit compatibility access, adapter-contract v1, parser integrity, effect and credential
  grants, scoped tool artifacts, exact validation evidence, and SK-035 as the next product batch.
- AAR submitted: `AAR-008-appsec-registry-adapters` records the inspection failures, prevention
  rules, focused validation decision, and 5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-008 are ready for the pipeline-controlled archive. The
  archive invalidates the pre-completion receipt, so delivery must rerun the same focused-repair
  gate without launching a broad mutation campaign.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Initial fast gate failed Clippy and compilation. | New invocation fields were missing from two AI-provider struct literals; old tests called the effect helper by module ID; several new branches were not in strict lint form. | Completed the literals, changed tests to inspect descriptors, and simplified the branches. | Keep the feature-matrix Clippy lane early in implementation. |
| 2 | The first all-feature run expected compatibility tools in the implicit pentest profile. | Legacy tests encoded the old all-module profile rather than the new locked catalog boundary. | Replaced them with exact application/compatibility selection assertions. | Pin both default exclusion and explicit compatibility reachability. |
| 3 | The external-tool contract stopped before ScoutSuite execution. | The new credential gate correctly rejected a fixture that granted only code scan and external tool. | Added the credential grant to the positive fixture and a separate no-credential non-invocation test. | Every credential-consuming adapter needs a positive exact grant and a denial-before-executor test. |
| 4 | The invocation working-directory fixture failed on macOS. | The shell reports `/private/var/...` while `tempfile` exposed the equivalent `/var/...` symlink path. | Compare against the canonical temporary-directory path. | Canonicalize filesystem identity in cross-platform execution assertions. |
| 5 | All-feature compilation rejected the infrastructure adapter helper after XML classification. | The helper remained `const fn`, but string equality is not a stable const operation on the supported Rust toolchain. | Made the descriptor helper a normal function. | Do not retain `const` on metadata builders once runtime ID classification is required. |
| 6 | The final fast gate's Clippy lane rejected the hardened Nuclei parser at 106 lines. | Record-schema validation was added inline to an already substantial JSONL loop. | Extracted a focused single-record decoder; the exact failed default-feature Clippy command and Nuclei parser tests are green. | Keep transport iteration and record decoding as separate functions in later parser migrations. |
| 7 | The DIFF gate could not start mutation execution. | Its two-worker scratch guard required 48 GiB, but the machine had 32 GiB available. | Kept the broad run deferred and selected the 23 inspection-repaired functions under the owner's fixed-functions-only direction. | Record focused scope before execution and use one worker when local scratch cannot support two isolated build trees. |
