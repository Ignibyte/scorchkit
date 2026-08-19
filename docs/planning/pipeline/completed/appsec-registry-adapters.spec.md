---
title: Application-security registry and scanner adapter foundation
pipeline_id: d53149f6-15a8-4448-a980-72609e59df62
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-008
ticket_doc: docs/planning/tickets/closed/TICKET-008-appsec-registry-adapters.md
aar: docs/planning/knowledge/aar/AAR-008-appsec-registry-adapters.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-008
created: 2026-08-17
---

# Application-security registry and scanner adapter foundation — spec

## Intent

Ship a behavior-preserving application-security registry and scanner-adapter foundation before
adding deeper static, artifact, and dynamic analysis. The result gives Codex a small, relevant
default tool surface while retaining an explicit compatibility path and one policy-aware metadata
source for every host surface.

## Scope

- In: application-security taxonomy and lifecycle stages; canonical versioned adapter descriptors;
  default application and explicit compatibility catalogs; shared bounded invocation and parser
  outcomes; temporary-artifact ownership; representative adapter migrations; exact registry,
  policy, compatibility, CLI, MCP, agent, and public-example tests.
- Out: new scanners; evidence schema migration; source-to-runtime correlation; authenticated DAST;
  arbitrary template execution; remote transport; webhooks; Windows support; cloud-module revival;
  deletion of existing adapters.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a caller requests the default security catalog, ScorchKit shall return only modules classified as application source, application dependency, application artifact, application runtime, or application attack-path capabilities. | Exact registry and public CLI/MCP catalog tests. |
| REQ-002 | When a caller explicitly requests the compatibility catalog, ScorchKit shall preserve access to existing non-application adapters without allowing them into an implicit application profile. | Compatibility registry census and profile-selection tests. |
| REQ-003 | When an external scanner is registered, ScorchKit shall expose one versioned descriptor containing its target kinds, lifecycle stage, strongest effect class, output contract, provenance strategy, and application-security classification. | Descriptor schema tests and exhaustive registry validation. |
| REQ-004 | When an adapter constructs a tool invocation, ScorchKit shall use the shared bounded invocation contract for executable identity, arguments, timeout, output limits, environment, and temporary artifacts. | Executor fixture tests across representative DAST and SAST adapters. |
| REQ-005 | When a migrated adapter uses the v1 parser contract, ScorchKit shall distinguish no findings, parse failure, execution failure, and successful findings; Nuclei and Semgrep shall prove the contract in this ticket. | Parser contract and asymmetric Nuclei/Semgrep fixture tests. |
| REQ-006 | When CLI, MCP, agent, or report code consumes scanner metadata, ScorchKit shall derive it from the canonical adapter descriptor rather than a second scanner inventory. | Exact cross-surface inventory tests. |
| REQ-007 | When an unknown or incompatible profile requests a module, ScorchKit shall fail closed before creating a process or network effect. | Negative profile and executor non-invocation tests. |
| REQ-008 | When the refactor is delivered, ScorchKit shall preserve existing explicit module identifiers and serialized findings unless a separately versioned contract states otherwise. | Compatibility fixtures, public example builds, and DIFF gate. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Keep ScorchKit agent-neutral with Codex as the preferred host. | Policy and evidence authority must remain inside the engine. |
| 2 | Define the default product around application source, dependencies, artifacts, runtime behavior, and application attack paths. | General network and enterprise tooling dilutes code-informed AppSec selection. |
| 3 | Retain out-of-bound adapters behind an explicit compatibility catalog in this ticket. | Avoid an unnecessary breaking deletion while preventing implicit use. |
| 4 | Extract common behavior before changing scanner behavior. | This keeps the refactor reviewable and preserves evidence semantics. |
| 5 | Defer richer evidence and scanner-specific capabilities to their queued tickets. | Adapter structure and domain schema need separate validation boundaries. |
| 6 | Keep the exhaustive legacy registries and add application/compatibility views over them. | Existing explicit module IDs remain available while named profiles and agent catalogs become application-only. |
| 7 | Make explicit module IDs and the compatibility template the only web paths that can select compatibility adapters. | Operator intent remains visible and policy still independently denies missing effect grants. |
| 8 | Migrate Nuclei and Semgrep to the shared parser outcome in this ticket. | They represent runtime JSONL and source JSON without turning the catalog refactor into a 67-adapter rewrite. |
| 9 | Execute mutation testing only for the functions repaired during inspection and defer the broad inventory. | The owner explicitly stopped broad mutation reruns and directed validation to fixed functions. |

## Owner-approved focused delivery scope

The repository owner directed that mutation testing run only against repaired functions and that a
full campaign happen later. The DIFF delivery gate passed every non-mutation lane but could not
start cargo-mutants because its two-worker scratch preflight required 48 GiB and 32 GiB was
available; it produced no TICKET-008 mutation outcomes. TICKET-008 therefore executes the 23
functions repaired during inspection across adapter classification, profile selection, credential
authorization, parser integrity, temporary-artifact ownership, and the package-owned MCP title
contract. The selected inventory contains 76 mutations across 11 files. Its raw inventory and
outcomes are sealed under `.git/scorchkit-mutants-focused-ticket-008` and may be reused after
archive only while the mutation-input hash and exact function list remain unchanged. The broad
inventory remains deferred.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-008-appsec-registry-adapters.md`
- AAR: `docs/planning/knowledge/aar/AAR-008-appsec-registry-adapters.md`
- Architecture: `docs/architecture/workspace.md`, `docs/architecture/sast.md`,
  `docs/architecture/executor.md`, `docs/architecture/api-spec-shared-data.md`

## Confirmed design

### Contract ownership

- `scorchkit-core` owns adapter-contract v1: security domain, lifecycle stage, target kinds,
  strongest effect, output shape, provenance strategy, temporary-artifact policy, and typed parser
  outcome.
- The four family descriptor packages depend only on `scorchkit-core` and embed the common contract
  while preserving their existing category-specific fields.
- Root composition owns the exhaustive concrete-module classification because only the root knows
  every built-in adapter ID and policy-sealed implementation.

### Catalog behavior

- The existing `all_modules` and `all_code_modules` remain exhaustive compatibility inventories.
- New application and compatibility views filter only through descriptor metadata.
- Named web and code profiles retain application-security modules before applying their existing
  depth rules. Unknown profiles continue to clear the registry.
- Explicit module IDs bypass the implicit application profile but remain subject to engagement,
  capability, effect, executable, timeout, and output enforcement.
- `network` remains an explicit compatibility template; `compatibility` selects every non-core web
  adapter. The `full` template becomes application-only, matching its documented `thorough` alias.
- CLI and MCP module listing plus AI planning use the application catalog by default. CLI listing
  accepts an explicit compatibility flag.

### Execution and parsing

- `ToolInvocation` gains explicit environment inheritance/clearing, environment overrides, and
  working-directory fields with behavior-preserving defaults.
- The adapter contract declares temporary-artifact ownership; adapters continue using RAII-owned
  temporary files and no executor accepts deletion paths.
- The process authorization mapping and descriptor strongest effect share one root classification
  function, closing the existing Metasploit/Kerbrute under-classification.
- Adapter parser outcome v1 distinguishes no findings, findings, and malformed output. Nuclei and
  Semgrep use it in production while their existing public parser compatibility is retained.

### Compatibility and security

- Existing module IDs and finding serialization remain unchanged.
- Descriptor serialization is additive and versioned.
- No new network, filesystem, credential, cloud, or subprocess effect is introduced.
- Unknown/custom configured adapters receive an application-runtime contract only after explicit
  registration; their actual effects still require the existing policy-sealed context.

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
