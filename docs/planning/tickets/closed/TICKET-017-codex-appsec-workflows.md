---
title: TICKET-017-codex-appsec-workflows
status: done
ticket_number: 017
type: feature
created: 2026-08-21
closed: 2026-08-21
intake: docs/planning/intake/INTAKE-codex-appsec-workflows.md
pipeline_spec: docs/planning/pipeline/completed/codex-appsec-workflows.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-017
---

# Codex-first application-security workflows and tiered scan profiles

## Summary

Ship versioned, provider-neutral application-security context and workflow-plan contracts for
commit, pull-request, staging, release, deep, and focused-remediation work. Expose those contracts
through read-only MCP tools and a Codex-first plugin workflow that deliberately combines Codex
Security semantic review with ScorchKit's deterministic, policy-gated source, dependency, artifact,
runtime, correlation, and verification tools.

## Why

SK-036 through SK-041 provide the underlying application SAST, supply-chain, DAST, correlation, and
pentest capabilities, but hosts still have to assemble them from generic tools. A stable workflow
contract is now needed to keep change review bounded, make profile expansion visible, prefer focused
verification after repairs, and prevent a host profile or AI proposal from becoming authorization.

## EARS Requirements

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

## Scope

- In: provider-neutral context/profile/focused-plan contracts; read-only MCP tools; Codex-first
  composite workflow; exact profile and effect truth tables; plugin/server/docs parity.
- Out: new scanner implementations; an opaque run-everything executor; agent authority; implicit
  target registration; implicit provider refresh; remote MCP; general network/enterprise/cloud
  posture; automatic release/deep scans or broad mutation after source changes.

## Locked decisions

- Planning is effect-free after the separately authorized bounded code-context read; execution
  remains a sequence of existing MCP tools with their existing policy checks.
- The profiles are application workflow profiles, not aliases for legacy quick/standard/thorough/
  pentest scan profiles.
- Codex Security results remain labeled host analysis. They never become ScorchKit scanner evidence
  or authorization by serialization or prompt assertion.
- Commit and PR use one declared Git change-set. Only explicit staging/release/deep plans may include
  repository-wide or runtime steps, and no profile supplies a missing grant.
- Focused verification wins over broad fallback after repairs. Broader work requires a separate
  explicit operator selection.
- No full or repository-wide mutation scan is authorized for this ticket.

## Owner-approved focused repair scope

- Broad baseline: completed DIFF inventory of 177 mutations; 84 caught, 40 timed out, 28 missed,
  and 25 unviable, for 124/152 viable outcomes caught before repair.
- Exact repair scope: all 28 survivors in
  `ApplicationSecurityWorkflowProfile::parse`, `compile_application_security_context`,
  `normalize_context_paths`, `normalize_context_routes`, `normalize_relative_paths`,
  `normalized_relative_path`, `normalized_revision`, `normalized_root`, `normalized_route`,
  `push_engine_step`, `step_identity`, and
  `ScorchKitServer::application_security_context`.
- Authorized evidence: `.git/scorchkit-mutants-focused-ticket-017`, with the next broad inventory
  explicitly deferred. Only this exact survivor set may be rerun after repair.

## Recon

- The five existing plugin skills are phase-oriented and have no application-profile coordinator.
- ScorchKit already exposes the underlying SAST, SCA, DAST, attack-path, pentest, and focused
  selection contracts through MCP; TICKET-017 composes them without adding a generic effect path.
- Official Codex plugin guidance permits a skill to coordinate tools already available to the host,
  while MCP remains the controlled tool boundary. Official Codex Security guidance defines change
  review as exactly one Git change set and distinguishes it from a repository scan.
- Existing code discovery is bounded to 200,000 entries, does not follow symbolic links, skips
  generated/vendor roots, and already runs behind `CodeScan`/`Passive` policy authorization.
- Existing scan tools do not implement an exact changed-file execution boundary. The workflow must
  expose that gap rather than relabel a full-root deterministic scan as change-bounded.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/codex-appsec-workflows.spec.md`
- Architecture: `docs/architecture/appsec-workflows.md`

## Log

- 2026-08-21: opened.
- 2026-08-21: plan locked from SK-042 intake and the owner direction to continue autonomously.
- 2026-08-21: implementation, exact-tree security review, and all non-mutation delivery lanes
  completed with no reportable security finding.
- 2026-08-21: exact repair caught all 28 preserved mutation survivors and sealed 152/152 viable
  outcomes at 100% MSI without repeating the broad inventory.
- 2026-08-21: pre-completion focused-repair gate passed 19 applicable lanes with no failures and 3
  named web-only skips.
- 2026-08-21: pipeline completion archived the ticket, spec, and notes; post-archive delivery proof
  is required before commit.
