---
title: Codex-first application-security workflows and tiered scan profiles
pipeline_id: 59f9a729-0811-49ee-9bdd-ab9f0a41e280
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-017
ticket_doc: docs/planning/tickets/closed/TICKET-017-codex-appsec-workflows.md
aar: docs/planning/knowledge/aar/AAR-017-codex-appsec-workflows.md
created: 2026-08-21
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-017
---

# Codex-first application-security workflows and tiered scan profiles — spec

## Intent

Present ScorchKit's completed application-security lifecycle through stable, agent-neutral context
and workflow-plan contracts, then package a Codex-first coordinator that combines labeled Codex
Security semantic review with existing ScorchKit policy-gated tools. The plan is deliberately
inert: it tells a host exactly what is bounded, broad, unsupported, and separately authorized
without becoming an alternate executor or evidence source.

## Scope

- In: canonical context/change-set/profile/focused-plan types, two read-only MCP tools, an exact
  profile and effect matrix, a sixth composite Codex skill, server/plugin instructions, contract
  fixtures, architecture and operator documentation.
- Out: new scanners, arbitrary workflow steps, direct Git mutation, implicit effects, a generic
  run-all tool, agent-owned authorization/evidence, remote MCP, compatibility security families,
  automatic provider refresh, broad rescans after repairs, and full/repository-wide mutation.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When an application context is requested for an authorized local code root, ScorchKit shall return one versioned, stably identified contract containing the canonical root, detected languages and manifests, declared change set, declared routes and artifacts, configured persona labels, registered project targets, configured capability/effect labels, provenance, and explicit gaps without credential values. | Core canonicalization, filesystem boundary, MCP, redaction, and identity tests. |
| REQ-002 | When commit, pull-request, staging, release, or deep is selected, ScorchKit shall compile one closed, ordered workflow plan whose exact steps, scope, host/engine ownership, required inputs, tool contracts, capability/effect requirements, and broad-scan status are stably identified. | Complete profile truth table, ordering, identity, and schema tests. |
| REQ-003 | When commit or pull-request scope is declared, ScorchKit shall bind semantic change review to exactly one Git change-set identity and shall not represent repository-wide source, dependency, artifact, or runtime coverage as completed by that review. | Change-set boundary, incomplete-coverage, and hostile-input tests. |
| REQ-004 | When staging, release, or deep expands a workflow, ScorchKit shall preserve the documented monotonic coverage order while retaining each target, capability, and exact effect as an independent execution-time requirement. | Profile/effect matrix and no-grant-by-profile tests. |
| REQ-005 | When a host supplies routes, artifacts, targets, changed paths, or analysis, ScorchKit shall retain the source as declared context and shall not promote it to scanner evidence, target registration, policy authorization, or verified coverage. | Attribution, policy-bypass, evidence-separation, and projection tests. |
| REQ-006 | When a focused verification selection is supplied, ScorchKit shall compile only its supported static, runtime, request, and test selectors, preserve unsupported selectors as gaps, and require a separate explicit choice before any broader fallback. | Focused-selection mapping and broad-fallback negative tests. |
| REQ-007 | When the workflow contracts are requested through MCP, ScorchKit shall expose read-only `application_context` and `plan_appsec_workflow` tools with complete schemas, conservative annotations, exact inventory parity, and native structured results. | MCP contract fixture, router, schema, and transport tests. |
| REQ-008 | When Codex runs the application-security workflow, the plugin shall use Codex Security only for labeled host semantic review and ScorchKit MCP for deterministic effects/evidence, shall use the correct diff or repository scan class, and shall stop rather than inventing an unsupported changed-scope or effectful fallback. | Plugin positive/negative contract and documentation tests. |
| REQ-009 | When another agent host consumes the same MCP results, no core, policy, evidence, storage, or workflow-plan field shall require Codex, ChatGPT, Claude, or another vendor. | Source scan, serialization, and provider-neutrality contract tests. |
| REQ-010 | When a repair is ready for verification, the documented default shall prefer the correlated focused selection and shall leave broad scans and mutation inventories explicit or scheduled rather than automatic after a mutation. | Focused-remediation plugin contract and no-broad-rescan tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Compile inert plans; do not add a composite execution tool. | Existing MCP effect boundaries already enforce policy and preserve evidence. |
| 2 | Keep Codex integration in a plugin skill over provider-neutral core/MCP contracts. | Codex is preferred without becoming an engine dependency. |
| 3 | Model commit, pull request, staging, release, and deep separately from legacy scan depth profiles. | Workflow coverage and operational scan strength are different dimensions. |
| 4 | Treat one declared Git change set as the only commit/PR semantic-review scope. | A change scan is not repository assurance and cannot silently widen. |
| 5 | Return explicit unsupported/gap rows when an existing tool cannot enforce requested changed scope. | Honest partial coverage is safer than running a broad substitute. |
| 6 | Retain target/capability/effect requirements on every step and recheck them at execution. | Profile selection and host reasoning do not mint grants. |
| 7 | Prefer an exact focused selection after repairs; broad fallback is a new explicit plan. | This honors the no-repeat-broad-scan operating rule and reduces unrelated effects. |
| 8 | Use DIFF validation only; no full or repository-wide mutation scan. | The owner has prohibited broad mutation reruns. |

## Owner-approved focused repair scope

The repository owner has repeatedly directed that mutation validation must not repeat a full or
broad changed-tree scan after repairs and that only repaired functions should be rerun. The
completed 177-mutant DIFF baseline is preserved unchanged. Its exact repair scope is the complete
28-survivor set in 12 functions across two files:

- `crates/scorchkit-core/src/appsec_workflow.rs`:
  `ApplicationSecurityWorkflowProfile::parse`, `compile_application_security_context`,
  `normalize_context_paths`, `normalize_context_routes`, `normalize_relative_paths`,
  `normalized_relative_path`, `normalized_revision`, `normalized_root`, `normalized_route`,
  `push_engine_step`, and `step_identity`
- `src/mcp/tools.rs`: `ScorchKitServer::application_security_context`

The raw broad inventory and outcomes, exact survivor inventory and recheck, two pre-repair input
snapshots, mutation-input hashes, and reconstructed final score are sealed under
`.git/scorchkit-mutants-focused-ticket-017`. No repeat 177-mutant or repository-wide run is in
scope; the next broad inventory remains scheduled work.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-017-codex-appsec-workflows.md`
- AAR: `docs/planning/knowledge/aar/AAR-017-codex-appsec-workflows.md`
- Architecture:
  `docs/architecture/appsec-workflows.md`

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
